# ANDHAK EDR — Detection & Integrity Architecture

---

## 1. Multi-Engine Detection Pipeline

| Engine | Mechanism | Output & Provenance |
| :--- | :--- | :--- |
| **YARA-X Scanner** | Native `yara-x` (`>=1.24`) compilation & in-memory scanning (20 MB limit) | Rule ID, namespace, matched string offsets, author, MIT/BSD-3-Clause license, MITRE tags |
| **EMBER Static PE Classifier** | `pefile` + `numpy` 2381-dim EMBER-aligned vector + calibrated `HistGradientBoostingClassifier` (`andhak-ember-gbdt-v1.0`) | Advisory score (`0.0–1.0`), PE summary (section entropies, RWX flags, suspicious imports), provenance, explicit non-proof caveat |
| **File Integrity Monitoring (FIM)** | Policy-configured SHA-256 baseline capture & real-time filesystem drift comparison | Tracks `created`, `modified`, `deleted`, `renamed`, `signature_changed` with Authenticode degradation escalation |
| **Behavioral Engine** | Stateful + sliding-window rules (`BEH-001`–`BEH-008`) | Encoded commands, unusual parent-child, unexpected executable drops, persistence, abnormal outbound traffic, sensitive path access, rapid file-write bursts, Temp execution |
| **Threat Intelligence** | Local SQLite IOC watchlist (`ip`, `domain`, `url`, `file_hash`) + policy-gated feeds | External lookups (`MalwareBazaar`, `AbuseIPDB`, `VirusTotal`) disabled by default; private files never uploaded |

---

## 2. Risk Scoring Model

Alerts store `severity` (`critical | high | medium | low | info`) and `confidence` (`0.0–1.0`) as separate attributes, paired with a computed `risk_score` (`0–100`):

```text
risk_score = clamp(0, 100, round(severity_base * (0.45 + 0.55 * confidence) + min(15, corroborating_signals * 5)))
```

Every emitted alert persists exact cited `evidence_event_ids`, `dedup_key` (hourly suppression bucket), `mitre_tactics`, `mitre_techniques`, and deterministic `recommended_actions`.
