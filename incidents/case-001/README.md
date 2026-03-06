# Incident Investigation: Case 001 — Phishing → Initial Access

**Date:** 2026-03-06
**Severity:** Medium — Phishing email delivered malicious attachment; no confirmed execution
**Status:** Closed
**Analyst:** Bhargav Baranda

---

## Executive Summary

A phishing email delivering a malicious Office attachment was identified through email gateway logs and Suricata IDS alerts. Analysis confirmed delivery via spearphishing (T1566.001) with a macro-enabled lure document designed to execute a payload on open. No confirmed execution was observed. The email was quarantined and IOCs blocked at the perimeter.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Observed Procedure |
|--------|-----------|--------------|-------------------|
| Initial Access | T1566 — Phishing | T1566.001 — Spearphishing Attachment | Macro-enabled Office document delivered via email |
| Execution | T1204 — User Execution | T1204.002 — Malicious File | User prompted to enable macros on document open |

---

## Technical Analysis

### OSI Layer Analysis

| Layer | Observation |
|-------|-------------|
| Layer 7 — Application | SMTP delivery of .docm attachment; subject line uses urgency lure |
| Layer 4 — Transport | TCP connection to mail server; standard port 25/587 |
| Layer 3 — Network | Source IP cross-referenced against GreyNoise — flagged as suspicious |
| Layer 2 — Data Link | N/A — perimeter detection, no internal host compromise confirmed |

### Detection Opportunity
Suricata IDS rule triggered on outbound connection attempt from mail gateway to known C2 infrastructure. ELK Stack correlation confirmed single delivery, no lateral spread.

---

## IOC Package

| Type | Value | Confidence | Source |
|------|-------|:----------:|--------|
| IP | [Redacted — lab exercise] | Probable | GreyNoise |
| Domain | [Redacted — lab exercise] | Probable | OTX AlienVault |
| File hash (SHA256) | [Redacted — lab exercise] | Confirmed | VirusTotal |

---

## Detection Rules

### Sigma
```yaml
title: Suspicious Office Macro Execution
status: experimental
description: Detects macro-enabled Office document execution — potential phishing payload
references:
  - https://attack.mitre.org/techniques/T1566/001/
tags:
  - attack.initial_access
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
  condition: selection
falsepositives:
  - Legitimate macro-enabled documents in business workflows
level: high
```

### Splunk SPL
```spl
index=windows EventCode=4688
| where ParentProcessName IN ("WINWORD.EXE","EXCEL.EXE")
  AND NewProcessName IN ("cmd.exe","powershell.exe","wscript.exe")
| stats count by _time, host, ParentProcessName, NewProcessName, CommandLine
| where count > 0
```

### Microsoft Sentinel KQL
```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName has_any ("WINWORD.EXE", "EXCEL.EXE")
| where NewProcessName has_any ("cmd.exe", "powershell.exe", "wscript.exe")
| project TimeGenerated, Computer, ParentProcessName, NewProcessName, CommandLine
```

---

## Business Impact Assessment

- **Systems affected:** 1 mail gateway endpoint
- **Data at risk:** None confirmed — no execution
- **Regulatory exposure:** GDPR Article 33 — notification not required (no personal data breach confirmed)
- **Estimated remediation cost:** £0 — contained at perimeter
- **Detection gap identified:** No automated quarantine rule for macro-enabled attachments from external senders

---

## Remediation Playbook

**Immediate (0–4hr)**
- [x] Email quarantined by gateway
- [x] IOCs blocked at perimeter firewall and DNS
- [x] Sender domain blacklisted

**Short-term (24–72hr)**
- [x] Sigma rule deployed to ELK Stack
- [x] Email gateway policy updated — block .docm from external senders

**Long-term**
- [ ] User awareness training on macro-enabled document lures
- [ ] Review email gateway ruleset for coverage gaps

---

## Security+ Connection

**Domain 2.0 — Threats, Vulnerabilities & Mitigations**
Objective 2.4 — Given a scenario, analyse indicators of malicious activity
- Social engineering: phishing, spearphishing
- Malware delivery via Office macros

---

## YouTube Companion

🔄 Video in production — Granger Security
