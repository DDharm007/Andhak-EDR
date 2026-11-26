"""Process tree builder and React Flow attack-graph generator."""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def build_incident_process_tree_and_graph(
    conn: sqlite3.Connection,
    incident_id: str,
) -> dict[str, Any]:
    incident = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    endpoint_id = incident["endpoint_id"]
    endpoint = conn.execute(
        "SELECT endpoint_id, hostname, os_version, status, isolation_state "
        "FROM endpoints WHERE endpoint_id = ?",
        (endpoint_id,),
    ).fetchone()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
        (incident_id,),
    ).fetchall()

    proc_guids: set[str] = set()
    for a in alerts:
        if a["process_guid"]:
            proc_guids.add(str(a["process_guid"]))

    # Expand ancestors & descendants on the same endpoint
    frontier = list(proc_guids)
    while frontier:
        guid = frontier.pop()
        row = conn.execute(
            "SELECT parent_process_guid FROM process_executions WHERE process_guid = ?",
            (guid,),
        ).fetchone()
        if row and row["parent_process_guid"] and row["parent_process_guid"] not in proc_guids:
            parent_guid = str(row["parent_process_guid"])
            proc_guids.add(parent_guid)
            frontier.append(parent_guid)
        children = conn.execute(
            "SELECT process_guid FROM process_executions WHERE parent_process_guid = ?",
            (guid,),
        ).fetchall()
        for ch in children:
            cg = str(ch["process_guid"])
            if cg not in proc_guids:
                proc_guids.add(cg)
                frontier.append(cg)

    processes: dict[str, dict[str, Any]] = {}
    if proc_guids:
        placeholders = ",".join("?" for _ in proc_guids)
        rows = conn.execute(
            f"SELECT * FROM process_executions WHERE process_guid IN ({placeholders}) "
            "ORDER BY started_at ASC",
            tuple(proc_guids),
        ).fetchall()
        for r in rows:
            processes[r["process_guid"]] = {
                "process_guid": r["process_guid"],
                "parent_process_guid": r["parent_process_guid"],
                "pid": r["pid"],
                "ppid": r["ppid"],
                "process_name": r["process_name"],
                "executable_path": r["executable_path"],
                "command_line": r["command_line"],
                "user_context": r["user_context"],
                "sha256": r["sha256"],
                "signature_status": r["signature_status"],
                "signer_subject": r["signer_subject"],
                "started_at": r["started_at"],
                "ended_at": r["ended_at"],
                "alerts": [],
                "network_connections": [],
                "children": [],
            }

    # Attach alerts & network connections to matching process nodes
    for a in alerts:
        g = a["process_guid"]
        if g and g in processes:
            processes[g]["alerts"].append(
                {
                    "alert_id": a["alert_id"],
                    "rule_id": a["rule_id"],
                    "rule_name": a["rule_name"],
                    "severity": a["severity"],
                    "confidence": a["confidence"],
                }
            )

    if proc_guids:
        placeholders = ",".join("?" for _ in proc_guids)
        sock_rows = conn.execute(
            f"SELECT * FROM network_sockets WHERE process_guid IN ({placeholders})",
            tuple(proc_guids),
        ).fetchall()
    else:
        sock_rows = []

    for s in sock_rows:
        g = s["process_guid"]
        if g and g in processes:
            processes[g]["network_connections"].append(
                {
                    "socket_id": s["socket_id"],
                    "protocol": s["protocol"],
                    "remote_addr": s["remote_addr"],
                    "remote_port": s["remote_port"],
                    "state": s["state"],
                }
            )

    # Build hierarchical tree
    roots: list[dict[str, Any]] = []
    for guid, node in processes.items():
        parent_guid = node["parent_process_guid"]
        if parent_guid and parent_guid in processes and parent_guid != guid:
            processes[parent_guid]["children"].append(node)
        else:
            roots.append(node)

    # Build React Flow graph (nodes + edges across endpoint, processes, sockets, files, alerts)
    rf_nodes: list[dict[str, Any]] = []
    rf_edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    def add_node(
        node_id: str, node_type: str, label: str, x: int, y: int, data: dict[str, Any]
    ) -> None:
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        rf_nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "position": {"x": x, "y": y},
                "data": {"label": label, "kind": node_type, **data},
            }
        )

    ep_node_id = f"endpoint:{endpoint_id}"
    add_node(
        ep_node_id,
        "endpoint",
        endpoint["hostname"] if endpoint else endpoint_id,
        80,
        40,
        dict(endpoint) if endpoint else {"endpoint_id": endpoint_id},
    )

    for idx, (guid, proc) in enumerate(processes.items()):
        p_id = f"process:{guid}"
        add_node(
            p_id,
            "process",
            f"{proc['process_name']} ({proc['pid']})",
            80 + (idx % 3) * 280,
            180 + (idx // 3) * 140,
            {
                "pid": proc["pid"],
                "sha256": proc["sha256"],
                "signature_status": proc["signature_status"],
                "alert_count": len(proc["alerts"]),
            },
        )
        parent = proc["parent_process_guid"]
        if parent and parent in processes:
            rf_edges.append(
                {
                    "id": f"e-{parent}-{guid}",
                    "source": f"process:{parent}",
                    "target": p_id,
                    "label": "spawned",
                }
            )
        else:
            rf_edges.append(
                {
                    "id": f"e-ep-{guid}",
                    "source": ep_node_id,
                    "target": p_id,
                    "label": "executes",
                }
            )

        for sock in proc["network_connections"]:
            ip_node = f"socket:{sock['remote_addr']}:{sock['remote_port']}"
            add_node(
                ip_node,
                "network",
                f"{sock['remote_addr']}:{sock['remote_port']}",
                760,
                180 + len(rf_nodes) * 40,
                sock,
            )
            rf_edges.append(
                {
                    "id": f"e-net-{guid}-{sock['socket_id']}",
                    "source": p_id,
                    "target": ip_node,
                    "label": f"{sock['protocol'].upper()} {sock['state']}",
                }
            )

    # Add file & alert nodes linked to evidence events
    ev_ids: list[str] = []
    for idx, a in enumerate(alerts):
        a_id = f"alert:{a['alert_id']}"
        add_node(
            a_id,
            "alert",
            f"{a['rule_id']}: {a['rule_name']}",
            440,
            40 + idx * 95,
            {
                "severity": a["severity"],
                "confidence": a["confidence"],
                "risk_score": a["risk_score"],
                "mitre_techniques": json.loads(a["mitre_techniques_json"] or "[]"),
            },
        )
        src = f"process:{a['process_guid']}" if a["process_guid"] in processes else ep_node_id
        rf_edges.append(
            {
                "id": f"e-alt-{a['alert_id']}",
                "source": src,
                "target": a_id,
                "label": a["severity"].upper(),
            }
        )
        ev_ids.extend(json.loads(a["evidence_event_ids_json"] or "[]"))

    if ev_ids:
        placeholders = ",".join("?" for _ in set(ev_ids))
        file_rows = conn.execute(
            f"SELECT DISTINCT file_path, sha256 FROM telemetry_events "
            f"WHERE event_id IN ({placeholders}) AND file_path IS NOT NULL",
            tuple(set(ev_ids)),
        ).fetchall()
        for idx, fr in enumerate(file_rows[:20]):
            fpath = str(fr["file_path"])
            f_node = f"file:{fpath}"
            add_node(
                f_node,
                "file",
                fpath.split("\\")[-1].split("/")[-1],
                760,
                40 + idx * 80,
                {"file_path": fpath, "sha256": fr["sha256"]},
            )
            rf_edges.append(
                {
                    "id": f"e-file-{idx}",
                    "source": ep_node_id,
                    "target": f_node,
                    "label": "file_activity",
                }
            )

    return {
        "incident_id": incident_id,
        "endpoint_id": endpoint_id,
        "process_tree": roots,
        "process_count": len(processes),
        "graph": {
            "nodes": rf_nodes,
            "edges": rf_edges,
        },
    }
