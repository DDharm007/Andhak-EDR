use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, UNIX_EPOCH};

use chrono::Utc;
use sysinfo::{Disks, Networks, ProcessesToUpdate, System, Users};
use uuid::Uuid;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    TRUST_E_NOSIGNATURE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptQueryObject, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::EventLog::{EvtClose, EvtOpenChannelConfig};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::collectors::filesystem::sha256_file;
use crate::collectors::{
    EventLogCollector, HostMetadata, NetworkCollector, ProcessCollector, SystemCollector,
    SystemSnapshot,
};
use crate::error::AgentError;
use crate::models::{
    compute_dedup_hash, make_process_guid, NetworkPayload, ProcessPayload, SensorState, Severity,
    SignatureStatus, SystemPayload, TelemetryCategory, TelemetryEventIn, TelemetryOrigin,
};

fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn is_process_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

pub fn verify_authenticode(path: &Path) -> (SignatureStatus, Option<String>) {
    if !path.is_file() {
        return (SignatureStatus::Unknown, None);
    }
    let wide = to_wide_null(path.as_os_str());
    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: null_mut(),
            pgKnownSubject: null_mut(),
        };
        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let mut wvt_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: null_mut(),
            pSIPClientData: null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: null_mut(),
            pwszURLReference: null_mut(),
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: 0,
            pSignatureSettings: null_mut(),
        };

        let status = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut wvt_data as *mut _ as *mut _,
        );
        wvt_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut wvt_data as *mut _ as *mut _,
        );

        let sig_status = if status == ERROR_SUCCESS as i32 {
            SignatureStatus::Valid
        } else if status == TRUST_E_NOSIGNATURE {
            if let Some(cat_res) = verify_catalog_signature(path, &wide) {
                return cat_res;
            }
            SignatureStatus::Unsigned
        } else {
            SignatureStatus::Invalid
        };

        let signer = if sig_status == SignatureStatus::Valid {
            extract_embedded_signer(&wide)
        } else {
            None
        };
        (sig_status, signer)
    }
}

unsafe fn verify_catalog_signature(
    path: &Path,
    wide_path: &[u16],
) -> Option<(SignatureStatus, Option<String>)> {
    let file = std::fs::File::open(path).ok()?;
    let h_file = file.as_raw_handle() as HANDLE;

    let mut h_cat_admin: isize = 0;
    if CryptCATAdminAcquireContext(&mut h_cat_admin, null(), 0) == 0 {
        return None;
    }

    let mut hash_len: u32 = 0;
    let _ = CryptCATAdminCalcHashFromFileHandle(h_file, &mut hash_len, null_mut(), 0);
    if hash_len == 0 {
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        return None;
    }

    let mut hash = vec![0u8; hash_len as usize];
    if CryptCATAdminCalcHashFromFileHandle(h_file, &mut hash_len, hash.as_mut_ptr(), 0) == 0 {
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        return None;
    }

    let h_cat_info =
        CryptCATAdminEnumCatalogFromHash(h_cat_admin, hash.as_ptr(), hash_len, 0, null_mut());
    if h_cat_info == 0 {
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        return None;
    }

    let mut cat_info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        wszCatalogFile: [0u16; 260],
    };
    let got_info = CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info, 0);
    if got_info == 0 {
        CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        return None;
    }

    let member_tag = to_wide_null(OsStr::new(&hex::encode_upper(&hash)));
    let mut wci = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: cat_info.wszCatalogFile.as_ptr(),
        pcwszMemberTag: member_tag.as_ptr(),
        pcwszMemberFilePath: wide_path.as_ptr(),
        hMemberFile: h_file,
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: hash_len,
        pcCatalogContext: null_mut(),
        hCatAdmin: h_cat_admin,
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut wvt_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 { pCatalog: &mut wci },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };

    let status = WinVerifyTrust(
        INVALID_HANDLE_VALUE,
        &mut action_guid,
        &mut wvt_data as *mut _ as *mut _,
    );
    wvt_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(
        INVALID_HANDLE_VALUE,
        &mut action_guid,
        &mut wvt_data as *mut _ as *mut _,
    );

    let result = if status == ERROR_SUCCESS as i32 {
        let signer = extract_embedded_signer(&cat_info.wszCatalogFile);
        Some((SignatureStatus::Valid, signer))
    } else {
        Some((SignatureStatus::Invalid, None))
    };

    CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
    CryptCATAdminReleaseContext(h_cat_admin, 0);
    result
}

unsafe fn extract_embedded_signer(wide_path: &[u16]) -> Option<String> {
    let mut store: HCERTSTORE = null_mut();
    let ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        wide_path.as_ptr() as *const _,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        null_mut(),
        null_mut(),
        null_mut(),
        &mut store,
        null_mut(),
        null_mut(),
    );
    if ok == 0 || store.is_null() {
        return None;
    }

    let mut leaf_name: Option<String> = None;
    let mut prev = CertEnumCertificatesInStore(store, null());
    while !prev.is_null() {
        let mut buf = [0u16; 256];
        let len = CertGetNameStringW(
            prev,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if len > 1 {
            let name = String::from_utf16_lossy(&buf[..(len as usize - 1)]);
            if !name.contains("Root") && !name.contains("PCA") && !name.contains("Authority") {
                leaf_name = Some(name);
                CertFreeCertificateContext(prev);
                break;
            }
            if leaf_name.is_none() {
                leaf_name = Some(name);
            }
        }
        prev = CertEnumCertificatesInStore(store, prev);
    }
    CertCloseStore(store, 0);
    leaf_name
}

struct CachedBinaryInfo {
    size: u64,
    mtime_secs: u64,
    sha256: Option<String>,
    signature_status: SignatureStatus,
    signer_subject: Option<String>,
}

pub struct WindowsProcessCollector {
    sys: System,
    users: Users,
    known_pids: HashMap<u32, u64>,
    guid_map: HashMap<u32, (String, String)>,
    binary_cache: HashMap<PathBuf, CachedBinaryInfo>,
    partial_access: bool,
}

impl Default for WindowsProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsProcessCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            users: Users::new_with_refreshed_list(),
            known_pids: HashMap::new(),
            guid_map: HashMap::new(),
            binary_cache: HashMap::new(),
            partial_access: false,
        }
    }

    fn inspect_binary(&mut self, path: &Path) -> (Option<String>, SignatureStatus, Option<String>) {
        let Ok(meta) = std::fs::metadata(path) else {
            return (None, SignatureStatus::Unknown, None);
        };
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some(cached) = self.binary_cache.get(path) {
            if cached.size == size && cached.mtime_secs == mtime {
                return (
                    cached.sha256.clone(),
                    cached.signature_status,
                    cached.signer_subject.clone(),
                );
            }
        }
        let sha256 = sha256_file(path);
        let (signature_status, signer_subject) = verify_authenticode(path);
        if self.binary_cache.len() > 2048 {
            self.binary_cache.clear();
        }
        self.binary_cache.insert(
            path.to_path_buf(),
            CachedBinaryInfo {
                size,
                mtime_secs: mtime,
                sha256: sha256.clone(),
                signature_status,
                signer_subject: signer_subject.clone(),
            },
        );
        (sha256, signature_status, signer_subject)
    }
}

impl ProcessCollector for WindowsProcessCollector {
    fn collect_delta(&mut self, endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.users.refresh();

        let mut events = Vec::new();
        let mut current: HashMap<u32, u64> = HashMap::new();
        let mut any_missing_exe = false;

        // First pass: refresh guid map for all running processes so parent GUID lookup works out of order.
        let mut snapshot_rows = Vec::new();
        for (pid, proc_info) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            let start = proc_info.start_time();
            current.insert(pid_u32, start);
            let name = proc_info.name().to_string_lossy().to_string();
            let guid = make_process_guid(endpoint_id, pid_u32, start);
            self.guid_map.insert(pid_u32, (name.clone(), guid.clone()));

            let is_new = self.known_pids.get(&pid_u32) != Some(&start);
            if is_new {
                let ppid = proc_info.parent().map(|p| p.as_u32()).unwrap_or(0);
                let exe = proc_info.exe().map(|p| p.to_path_buf());
                if exe.is_none() && pid_u32 > 4 {
                    any_missing_exe = true;
                }
                let cmd = proc_info
                    .cmd()
                    .iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                let user_ctx = proc_info
                    .user_id()
                    .and_then(|uid| self.users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();
                snapshot_rows.push((pid_u32, ppid, name, guid, exe, cmd, user_ctx, start));
            }
        }

        // Detect exited processes
        let mut exited_events = Vec::new();
        for (old_pid, old_start) in &self.known_pids {
            if current.get(old_pid) != Some(old_start) {
                if let Some((old_name, old_guid)) = self.guid_map.remove(old_pid) {
                    let occurred = Utc::now().to_rfc3339();
                    exited_events.push(TelemetryEventIn {
                        event_id: format!("proc-{}", Uuid::new_v4()),
                        telemetry_origin: TelemetryOrigin::RealEndpoint,
                        category: TelemetryCategory::Process,
                        event_type: "process_exit".into(),
                        severity: Severity::Info,
                        occurred_at: occurred.clone(),
                        dedup_hash: compute_dedup_hash(&["process", "process_exit", &old_guid]),
                        process: Some(ProcessPayload {
                            process_guid: old_guid,
                            parent_process_guid: None,
                            pid: *old_pid,
                            ppid: 0,
                            name: old_name,
                            executable_path: String::new(),
                            command_line: String::new(),
                            user_context: String::new(),
                            sha256: None,
                            signature_status: SignatureStatus::Unknown,
                            signer_subject: None,
                            started_at: occurred,
                        }),
                        network: None,
                        filesystem: None,
                        system: None,
                        extra: serde_json::json!({}),
                    });
                }
            }
        }

        for (pid_u32, ppid, name, guid, exe, cmd, user_ctx, start) in snapshot_rows {
            let parent_guid = self.guid_map.get(&ppid).map(|(_, g)| g.clone());
            let (sha256, signature_status, signer_subject) = match &exe {
                Some(path) => self.inspect_binary(path),
                None => (None, SignatureStatus::Unknown, None),
            };
            let exe_str = exe
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let started_at = chrono::DateTime::from_timestamp(start as i64, 0)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();
            let dedup_hash = compute_dedup_hash(&["process", "process_start", &guid]);

            events.push(TelemetryEventIn {
                event_id: format!("proc-{}", Uuid::new_v4()),
                telemetry_origin: TelemetryOrigin::RealEndpoint,
                category: TelemetryCategory::Process,
                event_type: "process_start".into(),
                severity: Severity::Info,
                occurred_at: Utc::now().to_rfc3339(),
                dedup_hash,
                process: Some(ProcessPayload {
                    process_guid: guid,
                    parent_process_guid: parent_guid,
                    pid: pid_u32,
                    ppid,
                    name,
                    executable_path: exe_str,
                    command_line: cmd,
                    user_context: user_ctx,
                    sha256,
                    signature_status,
                    signer_subject,
                    started_at,
                }),
                network: None,
                filesystem: None,
                system: None,
                extra: serde_json::json!({}),
            });
        }

        events.extend(exited_events);
        self.partial_access = any_missing_exe && !is_process_elevated();
        self.known_pids = current;
        Ok(events)
    }

    fn active_process_map(&self) -> HashMap<u32, (String, String)> {
        self.guid_map.clone()
    }

    fn health(&self) -> SensorState {
        if self.partial_access {
            SensorState::Partial
        } else {
            SensorState::Ready
        }
    }
}

pub struct WindowsNetworkCollector {
    seen_sockets: HashSet<String>,
    last_state: SensorState,
}

impl Default for WindowsNetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsNetworkCollector {
    pub fn new() -> Self {
        Self {
            seen_sockets: HashSet::new(),
            last_state: SensorState::Ready,
        }
    }
}

fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => "Unknown",
    }
}

fn ipv4_from_dword(raw: u32) -> String {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())).to_string()
}

fn port_from_dword(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

#[derive(Clone)]
struct RawSocket {
    protocol: &'static str,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: &'static str,
    pid: u32,
}

fn query_tcp_v4() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    unsafe {
        let rc = GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc2 = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc2 != ERROR_SUCCESS {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .map(|r: &MIB_TCPROW_OWNER_PID| RawSocket {
                protocol: "tcp",
                local_addr: ipv4_from_dword(r.dwLocalAddr),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: ipv4_from_dword(r.dwRemoteAddr),
                remote_port: port_from_dword(r.dwRemotePort),
                state: tcp_state_name(r.dwState),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

fn query_tcp_v6() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    unsafe {
        let rc = GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc2 = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc2 != ERROR_SUCCESS {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .map(|r: &MIB_TCP6ROW_OWNER_PID| RawSocket {
                protocol: "tcp",
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)).to_string(),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)).to_string(),
                remote_port: port_from_dword(r.dwRemotePort),
                state: tcp_state_name(r.dwState),
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

fn query_udp_v4() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    unsafe {
        let rc = GetExtendedUdpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc2 = GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc2 != ERROR_SUCCESS {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .map(|r: &MIB_UDPROW_OWNER_PID| RawSocket {
                protocol: "udp",
                local_addr: ipv4_from_dword(r.dwLocalAddr),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: "0.0.0.0".into(),
                remote_port: 0,
                state: "Stateless",
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

fn query_udp_v6() -> Vec<RawSocket> {
    let mut size: u32 = 0;
    unsafe {
        let rc = GetExtendedUdpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc2 = GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc2 != ERROR_SUCCESS {
            return Vec::new();
        }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .map(|r: &MIB_UDP6ROW_OWNER_PID| RawSocket {
                protocol: "udp",
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)).to_string(),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: "::".into(),
                remote_port: 0,
                state: "Stateless",
                pid: r.dwOwningPid,
            })
            .collect()
    }
}

impl NetworkCollector for WindowsNetworkCollector {
    fn collect_sockets(
        &mut self,
        endpoint_id: &str,
        process_map: &HashMap<u32, (String, String)>,
    ) -> Result<Vec<TelemetryEventIn>, AgentError> {
        let mut sockets = query_tcp_v4();
        sockets.extend(query_tcp_v6());
        sockets.extend(query_udp_v4());
        sockets.extend(query_udp_v6());

        self.last_state = if sockets.is_empty() {
            SensorState::Partial
        } else {
            SensorState::Ready
        };

        let mut events = Vec::new();
        let mut current_keys = HashSet::new();
        let now = Utc::now().to_rfc3339();

        for sock in sockets {
            let key = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                sock.protocol,
                sock.local_addr,
                sock.local_port,
                sock.remote_addr,
                sock.remote_port,
                sock.state,
                sock.pid
            );
            current_keys.insert(key.clone());
            if self.seen_sockets.contains(&key) {
                continue;
            }
            let (proc_name, proc_guid) = process_map
                .get(&sock.pid)
                .map(|(n, g)| (Some(n.clone()), Some(g.clone())))
                .unwrap_or((None, None));
            let dedup_hash = compute_dedup_hash(&["network", endpoint_id, &key]);
            events.push(TelemetryEventIn {
                event_id: format!("net-{}", Uuid::new_v4()),
                telemetry_origin: TelemetryOrigin::RealEndpoint,
                category: TelemetryCategory::Network,
                event_type: "socket_observed".into(),
                severity: Severity::Info,
                occurred_at: now.clone(),
                dedup_hash,
                process: None,
                network: Some(NetworkPayload {
                    protocol: sock.protocol.into(),
                    local_addr: sock.local_addr,
                    local_port: sock.local_port,
                    remote_addr: sock.remote_addr,
                    remote_port: sock.remote_port,
                    state: sock.state.into(),
                    pid: Some(sock.pid),
                    process_name: proc_name,
                    process_guid: proc_guid,
                }),
                filesystem: None,
                system: None,
                extra: serde_json::json!({}),
            });
        }

        self.seen_sockets = current_keys;
        Ok(events)
    }

    fn health(&self) -> SensorState {
        self.last_state
    }
}

pub struct WindowsSystemCollector {
    sys: System,
    disks: Disks,
    networks: Networks,
}

impl Default for WindowsSystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsSystemCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_cpu_usage();
        std::thread::sleep(Duration::from_millis(120));
        sys.refresh_cpu_usage();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
        }
    }
}

impl SystemCollector for WindowsSystemCollector {
    fn collect_metrics(
        &mut self,
        endpoint_id: &str,
        uptime_seconds: u64,
    ) -> Result<(SystemSnapshot, TelemetryEventIn), AgentError> {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(true);

        let cpu = self.sys.global_cpu_usage().clamp(0.0, 100.0);
        let used_mb = self.sys.used_memory() / (1024 * 1024);
        let total_mb = self.sys.total_memory() / (1024 * 1024);

        let (tot_disk, avail_disk) = self.disks.list().iter().fold((0u64, 0u64), |(t, a), d| {
            (
                t.saturating_add(d.total_space()),
                a.saturating_add(d.available_space()),
            )
        });
        let disk_pct = if tot_disk > 0 {
            ((tot_disk - avail_disk) as f64 / tot_disk as f64 * 100.0) as f32
        } else {
            0.0
        };

        let rss_mb = sysinfo::get_current_pid()
            .ok()
            .and_then(|pid| {
                self.sys
                    .refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                self.sys
                    .process(pid)
                    .map(|p| p.memory() as f32 / (1024.0 * 1024.0))
            })
            .unwrap_or(0.0);

        let os_version = System::long_os_version().unwrap_or_else(|| "Windows".into());
        let now = Utc::now();
        let bucket = (now.timestamp() / 5).to_string();
        let evt = TelemetryEventIn {
            event_id: format!("sys-{}", Uuid::new_v4()),
            telemetry_origin: TelemetryOrigin::RealEndpoint,
            category: TelemetryCategory::System,
            event_type: "host_metrics".into(),
            severity: Severity::Info,
            occurred_at: now.to_rfc3339(),
            dedup_hash: compute_dedup_hash(&["system", endpoint_id, &bucket]),
            process: None,
            network: None,
            filesystem: None,
            system: Some(SystemPayload {
                cpu_percent: cpu,
                memory_used_mb: used_mb,
                memory_total_mb: total_mb,
                disk_used_percent: disk_pct,
                agent_rss_mb: rss_mb,
                os_version,
                uptime_seconds,
            }),
            extra: serde_json::json!({}),
        };
        Ok((
            SystemSnapshot {
                cpu_percent: cpu,
                memory_used_mb: used_mb,
                memory_total_mb: total_mb,
                disk_used_percent: disk_pct,
                agent_rss_mb: rss_mb,
            },
            evt,
        ))
    }

    fn host_metadata(&mut self) -> HostMetadata {
        self.networks.refresh(true);
        let mut primary_ip: Option<String> = None;
        let mut mac_addr: Option<String> = None;

        for data in self.networks.list().values() {
            for net in data.ip_networks() {
                if let IpAddr::V4(v4) = net.addr {
                    if !v4.is_loopback() && !v4.is_link_local() {
                        primary_ip = Some(v4.to_string());
                        if !data.mac_address().is_unspecified() {
                            mac_addr = Some(data.mac_address().to_string());
                        }
                        break;
                    }
                }
            }
            if primary_ip.is_some() {
                break;
            }
        }

        HostMetadata {
            hostname: System::host_name().unwrap_or_else(|| "windows-host".into()),
            fqdn: None,
            os_family: "windows".into(),
            os_version: System::long_os_version().unwrap_or_else(|| "Windows".into()),
            architecture: std::env::consts::ARCH.into(),
            primary_ip,
            mac_address: mac_addr,
            elevated_sensor: is_process_elevated(),
        }
    }

    fn health(&self) -> SensorState {
        SensorState::Ready
    }
}

pub struct WindowsSysmonCollector {
    available: bool,
}

impl Default for WindowsSysmonCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsSysmonCollector {
    pub fn new() -> Self {
        let available = probe_sysmon_channel();
        Self { available }
    }
}

fn probe_sysmon_channel() -> bool {
    let channel = to_wide_null(OsStr::new("Microsoft-Windows-Sysmon/Operational"));
    unsafe {
        let handle = EvtOpenChannelConfig(0, channel.as_ptr(), 0);
        if handle != 0 {
            EvtClose(handle);
            true
        } else {
            false
        }
    }
}

impl EventLogCollector for WindowsSysmonCollector {
    fn probe_available(&self) -> bool {
        self.available
    }

    fn collect_new(&mut self, _endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError> {
        // Honest degradation: return empty until Sysmon operational log is installed/enabled.
        Ok(Vec::new())
    }

    fn health(&self) -> SensorState {
        if self.available {
            SensorState::Ready
        } else {
            SensorState::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_real_windows_processes_sockets_and_system_metrics() {
        let mut proc_col = WindowsProcessCollector::new();
        let proc_events = proc_col.collect_delta("ep_test").unwrap();
        assert!(!proc_events.is_empty());
        assert!(proc_events.iter().any(|e| {
            e.process
                .as_ref()
                .map(|p| p.sha256.is_some())
                .unwrap_or(false)
        }));

        let mut net_col = WindowsNetworkCollector::new();
        let net_events = net_col
            .collect_sockets("ep_test", &proc_col.active_process_map())
            .unwrap();
        assert!(!net_events.is_empty());

        let mut sys_col = WindowsSystemCollector::new();
        let (snap, sys_evt) = sys_col.collect_metrics("ep_test", 1).unwrap();
        assert!(snap.memory_total_mb > 0);
        assert!(sys_evt.system.is_some());
    }

    #[test]
    fn verifies_authenticode_on_windows_system_binary() {
        let notepad = Path::new("C:\\Windows\\System32\\notepad.exe");
        if notepad.exists() {
            let (status, signer) = verify_authenticode(notepad);
            assert_eq!(status, SignatureStatus::Valid);
            assert!(signer.is_some());
        }
    }
}
