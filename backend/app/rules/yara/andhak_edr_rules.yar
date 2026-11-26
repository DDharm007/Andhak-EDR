rule ANDHAK_EICAR_Test_String {
  meta:
    description = "Standard harmless EICAR antivirus test string for scanner verification"
    severity = "info"
    confidence = "1.0"
    mitre = ""
    kind = "test_signature"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar
}

rule ANDHAK_PowerShell_Encoded_Execution {
  meta:
    description = "Detects PowerShell encoded command parameters commonly used to obfuscate execution"
    severity = "high"
    confidence = "0.82"
    mitre = "T1059.001"
    kind = "heuristic"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $ps1 = "powershell" ascii wide nocase
    $pwsh = "pwsh" ascii wide nocase
    $enc1 = "-EncodedCommand" ascii wide nocase
    $enc2 = " -enc " ascii wide nocase
    $enc3 = "FromBase64String" ascii wide nocase
  condition:
    ($ps1 or $pwsh) and any of ($enc1, $enc2, $enc3)
}

rule ANDHAK_Suspicious_PE_Injection_APIs {
  meta:
    description = "Windows PE importing process-injection API triplet (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
    severity = "high"
    confidence = "0.78"
    mitre = "T1055"
    kind = "heuristic"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $mz = { 4D 5A }
    $api1 = "VirtualAllocEx" ascii
    $api2 = "WriteProcessMemory" ascii
    $api3 = "CreateRemoteThread" ascii
  condition:
    $mz at 0 and all of ($api*)
}

rule ANDHAK_Suspicious_Ransom_Note_Indicators {
  meta:
    description = "Detects common ransom-note instruction markers or harmless ransomware test fixtures"
    severity = "critical"
    confidence = "0.85"
    mitre = "T1486"
    kind = "heuristic"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $m1 = "ALL YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
    $m2 = "YOUR PERSONAL FILES ARE ENCRYPTED" ascii wide nocase
    $m3 = "HOW_TO_DECRYPT" ascii wide nocase
    $m4 = "ANDHAK_RANSOM_TEST_FIXTURE" ascii wide
  condition:
    any of them
}

rule ANDHAK_Credential_Access_Command_Markers {
  meta:
    description = "Detects credential dumping tool markers targeting LSASS memory"
    severity = "critical"
    confidence = "0.90"
    mitre = "T1003.001"
    kind = "signature"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $s1 = "sekurlsa::logonpasswords" ascii wide nocase
    $s2 = "lsadump::sam" ascii wide nocase
    $s3 = "comsvcs.dll,MiniDump" ascii wide nocase
    $s4 = "ANDHAK_CRED_DUMP_TEST_FIXTURE" ascii wide
  condition:
    any of them
}

rule ANDHAK_Script_Dropper_Stager {
  meta:
    description = "Detects download-and-execute script stager combinations"
    severity = "high"
    confidence = "0.76"
    mitre = "T1105"
    kind = "heuristic"
    author = "ANDHAK EDR Security Engineering"
    license = "MIT"
  strings:
    $dl1 = "DownloadString(" ascii wide nocase
    $dl2 = "DownloadFile(" ascii wide nocase
    $dl3 = "Invoke-WebRequest" ascii wide nocase
    $exec1 = "Invoke-Expression" ascii wide nocase
    $exec2 = "IEX(" ascii wide nocase
    $exec3 = "Start-Process" ascii wide nocase
  condition:
    any of ($dl*) and any of ($exec*)
}
