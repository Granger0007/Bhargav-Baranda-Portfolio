<div align="center">

# 🔴 Case-001 — Spearphishing Attack: A Story in Seven Layers

**A real incident investigation, written so anyone can understand it.**

![Severity](https://img.shields.io/badge/Severity-High-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Closed-brightgreen?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1566.001-orange?style=flat-square)
![Detection](https://img.shields.io/badge/Detection-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## 📋 Investigation Summary

| Field | Details |
|-------|---------|
| **Case ID** | 001 |
| **Date** | 2026-03-06 |
| **Attack Type** | Spearphishing → Macro Execution → RAT Deployment |
| **Severity** | High |
| **Status** | Closed |
| **Analyst** | Bhargav Baranda |
| **Framework** | MITRE ATT&CK, OSI Model |
| **Detection Tools** | Suricata IDS, ELK Stack, Email Gateway |

---

## 🎯 Executive Summary

A finance department employee at a UK bank received a spearphishing email impersonating the CFO. The email delivered a macro-enabled Excel attachment designed to deploy a Remote Access Trojan (RAT) on execution. The RAT was configured to beacon outbound over port 443 — blending into legitimate HTTPS traffic — back to attacker-controlled Command and Control infrastructure.

This investigation traces the attack through all seven OSI layers, from the physical cables the email travelled on to the application-layer deception that made the victim open the file. Every layer produced evidence. Every layer offered a detection opportunity. Not all of them were taken.

**The attacker needed one layer to fail. The defender needed all seven to hold.**

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Observed Procedure |
|--------|-----------|--------------|-------------------|
| Reconnaissance | T1589 | T1589.002 — Email Addresses | Attacker researched CFO name, email format, and communication style |
| Initial Access | T1566 | T1566.001 — Spearphishing Attachment | Macro-enabled Excel (.xlsm) delivered via spoofed CFO email |
| Execution | T1204 | T1204.002 — Malicious File | Victim opened attachment; macro prompted to enable content |
| Execution | T1059 | T1059.005 — Visual Basic | VBA macro executed PowerShell payload on document open |
| Defense Evasion | T1027 | T1027.010 — Command Obfuscation | Macro obfuscated to evade signature-based AV detection |
| Defense Evasion | T1036 | T1036.005 — Match Legitimate Name | RAT beacon used port 443 to mimic HTTPS traffic |
| Command & Control | T1071 | T1071.001 — Web Protocols | RAT communicated via HTTPS on port 443 |
| Command & Control | T1573 | T1573.001 — Symmetric Cryptography | C2 traffic encrypted with TLS — content not readable in transit |
| Persistence | T1053 | T1053.005 — Scheduled Task | RAT installed scheduled task for persistence across reboots |

---

## 📖 The Attack — What Actually Happened

It's a Tuesday morning. A finance employee at a large UK bank opens their email and sees a message from the CFO — "Urgent: Q4 Budget Approval Needed." Same name. Same tone. Same format as every other email he sends.

They open the Excel attachment.

**That's the moment the attack succeeded.**

The email wasn't from the CFO. A threat actor had researched the organisation — the CFO's name, email format, writing style, and the finance team's likely responsibilities. They crafted a message that felt personal and urgent. When the victim opened the attachment and clicked "Enable Content," a VBA macro executed silently in the background, establishing a connection back to the attacker's server.

This is **spearphishing**. Not a mass email blast — a targeted, researched, personalised attack against a specific individual at a specific organisation.

---

## 🌐 OSI Layer Analysis — The Attack Traced Through Every Layer

> The OSI model gives security professionals a shared language to describe where in a network something happened. This investigation traces the attack through all seven layers.

---

### Layer 1 — Physical: The Roads the Data Travelled On

**What this layer is:** The actual physical hardware carrying data — copper cables, fibre optics, Wi-Fi radio waves. It doesn't understand what data means. It just carries it.

**What happened:** The phishing email travelled as electrical signals and light pulses through physical infrastructure — undersea cables, data centres, routers, the office Wi-Fi. Layer 1 carried the attack silently, invisibly.

**What a defender finds here:** Usually nothing during a phishing attack. However, sophisticated state-sponsored actors have been known to tap cables, plant hardware implants, or deploy rogue Wi-Fi access points. For this investigation, Layer 1 was passive.

---

### Layer 2 — Data Link: The Local Delivery Network

**What this layer is:** The local delivery system. Uses MAC addresses — unique hardware identifiers burned into every network card — to move data between devices on the same local network. Think of it as the postman who delivers to your specific door once the letter has arrived in your neighbourhood.

**What happened:** As the email hopped between switches inside the bank, each switch read the MAC address of the next destination and forwarded it. Unremarkable during delivery. More significant after compromise — the RAT's lateral movement would operate here.

**Attack technique at this layer:** ARP poisoning — tricking nearby machines into routing their traffic through the attacker's machine instead of the legitimate gateway. Like a fraudulent postman intercepting letters meant for your neighbours.

**What a defender finds here:**
- Unusual ARP table entries
- Duplicate MAC addresses on the network
- Unexpected traffic between machines that shouldn't be communicating

---

### Layer 3 — Network: The Postal Address System

**What this layer is:** IP addresses and routing. Every packet of data has a source and destination IP. Routers read these addresses and pass each packet one step closer to its destination — like a postal sorting office reading a postcode.

**What happened:** The phishing email left the attacker's server — a legitimate third-party mail server they had previously compromised — with a source IP that looked clean. Reputation-based security systems that block known malicious IPs wouldn't flag it. The attacker deliberately laundered their sending infrastructure through an innocent victim's server.

**Critical detection opportunity — SPF records:**

SPF (Sender Policy Framework) allows domain owners to publish a list of IP addresses authorised to send email on their behalf. The compromised third-party server's IP would not appear on the spoofed domain's SPF record. A properly configured email security gateway would catch this — before the email reached the victim's inbox.

```
Expected SPF check result:
FAIL — sending IP not authorised for this domain
Action: Quarantine and alert
```

**What a defender finds here:**
- SPF check failure on inbound email
- Source IP not matching the claimed sending domain
- Threat intelligence hit on the sending IP's prior abuse history

---

### Layer 4 — Transport: The Reliable Delivery Service

**What this layer is:** TCP — Transmission Control Protocol. Breaks data into numbered segments, sends them, confirms delivery, and retransmits anything lost. Establishes connections via the three-way handshake: SYN → SYN-ACK → ACK.

**What happened:** TCP delivered the email reliably to the bank's mail server. More critically — after the macro executed and the RAT was running — it used TCP on **port 443** to establish its C2 connection. Port 443 is the standard port for HTTPS web browsing. The attacker chose this deliberately.

> Almost every firewall in the world allows outbound connections on port 443. The attacker smuggled their C2 traffic inside a port that gets waved through every checkpoint.

**What a defender finds here — beaconing behaviour:**

A compromised workstation making repeated short outbound connections to an unfamiliar IP — even on port 443 — is suspicious. The RAT checks in with its master on a regular interval. That pattern is detectable.

```
Suspicious pattern:
finance-workstation-04 → 185.220.101.47:443
Connection every 60 seconds
Duration: 847 connections over 14 hours
→ This is not a human browsing the web. This is a beacon.
```

---

### Layer 5 — Session: The Ongoing Conversation Manager

**What this layer is:** Manages sessions — ongoing dialogues between two computers. Handles starting, maintaining, and ending conversations. If a connection drops briefly, the session layer resumes it rather than forcing a reconnect.

**What happened:** Once the RAT was running, it maintained a **persistent session** with the C2 server — kept alive with periodic low-frequency check-ins. The digital equivalent of a prisoner in a cell tapping the wall every 60 seconds to signal they're still there.

**What a defender finds here:**

Normal web browsing creates many short sessions — you load a page, the session closes. A RAT creates a single long-lasting session that stays open for hours or days. Network analysis tools like Zeek can detect these anomalous session durations.

```
Anomaly detected:
Session from 192.168.1.47 to 185.220.101.47
Duration: 14 hours, 23 minutes
Normal expected max session duration: 10 minutes
→ Escalate for investigation
```

---

### Layer 6 — Presentation: The Translator and the Lockbox

**What this layer is:** Handles translation, encryption, and decryption. When you see "https://" — that encryption lives here. TLS (Transport Layer Security) is a Layer 6 protocol.

**What happened — three things:**

1. **The email attachment was MIME-encoded** — a standard format for packaging attachments so they survive transit through email servers.

2. **The C2 traffic was TLS-encrypted** — anyone intercepting the RAT's connection would see scrambled gibberish, not the commands being issued. The attacker hid their orders inside traffic indistinguishable from normal secure web browsing.

3. **The macro was obfuscated** — deliberately written in a scrambled, confusing way designed to defeat signature-based antivirus. Traditional AV recognises known malicious code patterns. Obfuscation breaks those patterns. The macro walked straight past the scanner.

**What a defender finds here:**
- TLS certificate anomalies — self-signed, recently created, or unusual Certificate Authority
- Sandbox detonation — opening the file in an isolated virtual environment reveals what the macro actually does, regardless of obfuscation
- Certificate transparency logs — C2 domains often have newly issued certificates with no history

---

### Layer 7 — Application: Where the Human Meets the Attack

**What this layer is:** The layer you interact with. Email clients. Web browsers. The protocols: SMTP (email delivery), HTTP/HTTPS (web), DNS (translating domain names to IPs).

**What happened:** The finance employee's email client received the phishing message via SMTP and rendered it as a convincing CFO impersonation. They opened the attachment. The macro ran. The RAT established its HTTPS beacon — Layer 7 protocol, encrypted at Layer 6, delivered reliably via TCP at Layer 4, routed by IP at Layer 3 — all the way back to the attacker.

**What a defender finds here — the richest evidence layer:**

| Evidence Type | What It Contains |
|---------------|-----------------|
| Email headers | Complete travel history — every server, original sending IP, timestamps, SPF/DKIM results |
| Proxy logs | Every outbound web request from every machine on the network |
| DNS logs | Every domain lookup — the RAT had to resolve the C2 domain before connecting. That query is logged. |
| SMTP logs | Sender, recipient, attachment name, attachment hash, delivery path |

The DNS query is often the earliest indicator. Before the RAT can connect to its C2 server, it has to look up the C2 domain in DNS. **That lookup happens before the connection. It's a breadcrumb that arrives before the fire.**

---

## 🔍 Complete Attack Flow

```
ATTACKER                    NETWORK LAYERS              VICTIM (BANK)
    |                                                        |
    |── Researches CFO name, email format (Layer 7/OSINT) ──>|
    |                                                        |
    |── Compromises third-party mail server (Layer 3) ──────>|
    |                                                        |
    |── Sends spoofed CFO email via SMTP (Layer 7) ─────────>|
    |   [SPF FAIL — if checked]                              |
    |   [Source IP suspicious — if threat intel checked]     |
    |                                                        |
    |                              Victim opens .xlsm file   |
    |                              Clicks "Enable Content"   |
    |                              VBA macro executes        |
    |                                                        |
    |<── RAT installed, persistence via scheduled task ──────|
    |                                                        |
    |<── HTTPS beacon, port 443, every 60 seconds ───────────|
    |   [Encrypted TLS — content hidden (Layer 6)]           |
    |   [Port 443 — passes most firewalls (Layer 4)]         |
    |   [Long session anomaly — detectable (Layer 5)]        |
    |   [Beacon pattern — detectable (Layer 4)]              |
    |   [DNS query logged — earliest indicator (Layer 7)]    |
```

---

## 🛡️ Detection Rules

### Sigma — Office Child Process Spawning

```yaml
title: Macro-Enabled Office Document Spawning Suspicious Child Process
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects VBA macro execution resulting in suspicious child processes.
  Primary indicator of spearphishing payload delivery via T1566.001.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/005/
author: Bhargav Baranda (Granger0007)
date: 2026/03/06
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059.005
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\MSPUB.EXE'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate business macros launching scripts — whitelist by hash
  - Developer environments with Office automation
level: high
```

### Splunk SPL — C2 Beacon Detection

```spl
| Comment: T1071.001 — Suspicious outbound beaconing behaviour
| Comment: Detects regular interval connections indicative of C2 activity
| Comment: Author: Bhargav Baranda | Date: 2026-03-06

index=network earliest=-24h
| eval connection_hour=strftime(_time, "%Y-%m-%d %H")
| stats
    count AS connections,
    dc(src_port) AS unique_src_ports,
    values(dest_port) AS dest_ports,
    range(_time) AS session_duration_secs
    BY src_ip, dest_ip, connection_hour
| where connections > 10
    AND unique_src_ports > 5
    AND session_duration_secs > 3600
| eval beacon_score=case(
    connections > 100, 90,
    connections > 50,  75,
    connections > 20,  60,
    true(),            40
  )
| sort - beacon_score
| table connection_hour, src_ip, dest_ip, connections,
        unique_src_ports, dest_ports, session_duration_secs, beacon_score
```

### Microsoft Sentinel KQL — TLS Certificate Anomaly

```kql
// T1573.001 — Suspicious TLS certificate on outbound C2 connection
// Author: Bhargav Baranda (Granger0007) | Date: 2026-03-06

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
| join kind=leftouter (
    DeviceEvents
    | where ActionType == "SslCertificateInspected"
    | extend CertAge = datetime_diff('day', now(), todatetime(AdditionalFields.ValidFrom))
    | extend IsSelfSigned = tobool(AdditionalFields.IsSelfSigned)
    | project Timestamp, DeviceId, RemoteIP, CertAge, IsSelfSigned
  ) on DeviceId
| where CertAge < 30 or IsSelfSigned == true
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemoteUrl,
    CertAge,
    IsSelfSigned,
    InitiatingProcessFileName
| sort by Timestamp desc
```

---

## 📦 IOC Package

| Type | Value | Confidence | Source | Notes |
|------|-------|:----------:|--------|-------|
| Sending IP | [Redacted] | Confirmed | Email headers | Compromised third-party mail server |
| C2 IP | [Redacted] | Confirmed | Firewall logs | RAT beacon destination |
| C2 Domain | [Redacted] | Confirmed | DNS logs | Resolved 14hr before detection |
| File hash (SHA256) | [Redacted] | Confirmed | Sandbox | Macro-enabled Excel attachment |
| TLS Certificate | [Redacted] | Probable | Proxy logs | Self-signed, issued 3 days prior |
| Scheduled Task | `\Microsoft\Windows\UpdateCheck` | Confirmed | EDR | RAT persistence mechanism |

> IOCs redacted in public portfolio. Full package available on request for legitimate security research.

---

## 💼 Business Impact Assessment

| Factor | Assessment |
|--------|-----------|
| **Systems affected** | 1 finance workstation — confirmed. Full network scope under investigation at time of containment. |
| **Data at risk** | Financial data, internal communications, potential access to banking infrastructure |
| **Dwell time** | 14 hours before detection |
| **Regulatory exposure** | GDPR Article 33 — 72hr ICO notification required if personal data confirmed exfiltrated |
| **Potential fine** | Up to 4% global annual turnover under GDPR Article 83 |
| **Estimated remediation** | £15,000–£45,000 (forensic investigation, system rebuild, policy updates) |
| **Reputational risk** | High — financial sector breach carries significant customer trust implications |

---

## 🔧 Remediation Playbook

### Immediate (0–4 hours)
- [x] Isolate compromised workstation from network
- [x] Block C2 IP and domain at perimeter firewall and DNS sinkhole
- [x] Revoke active sessions and reset credentials for compromised account
- [x] Preserve forensic evidence — memory dump, full disk image, log export
- [x] Delete malicious scheduled task — terminate RAT persistence

### Short-term (24–72 hours)
- [x] Full scope review — confirm no lateral movement to other hosts
- [x] Deploy Sigma rule to all SIEM environments
- [x] Update email gateway — block macro-enabled attachments from external senders
- [x] ICO notification assessment — confirm whether personal data was exfiltrated
- [ ] Mandatory security awareness communication to finance team

### Long-term (weeks/months)
- [ ] Implement DMARC enforcement on all company email domains
- [ ] Enable SPF hard fail (`-all`) rather than soft fail (`~all`)
- [ ] Deploy application allowlisting on finance workstations
- [ ] Quarterly tabletop exercise — spearphishing scenario
- [ ] Review and update email security gateway rule set
- [ ] Enable macro execution logging via Group Policy

---

## 🎓 What a Well-Defended Organisation Would Have Done

A layered defence would have caught this attack at multiple points:

| Layer | Detection | Tool | Would Have Caught |
|-------|-----------|------|-------------------|
| Layer 3/7 | SPF check failure | Email gateway | Email before delivery |
| Layer 6 | Sandbox detonation | Attachment sandbox | Macro on receipt |
| Endpoint | Office spawning PowerShell | EDR | On macro execution |
| Layer 4/5 | Beacon pattern anomaly | SIEM | Within first hour of RAT running |
| Layer 7 | DNS query to new C2 domain | DNS security | Before first C2 connection |

**Defence in depth.** The attacker must defeat every control simultaneously. Each one that holds narrows their window.

---

## 📚 Security+ SY0-701 Connection

| Objective | Concept Demonstrated |
|-----------|-------------------|
| **2.2** — Threat vectors and attack surfaces | Spearphishing, social engineering, macro-enabled documents |
| **2.4** — Indicators of malicious activity | Beaconing, C2 communication patterns, obfuscated macros |
| **3.1** — Secure enterprise architecture | Defence in depth, layered controls |
| **4.1** — Security tools assessment | Suricata, ELK Stack, Wireshark, Sigma rules |
| **1.4** — Cryptography and PKI | TLS encryption, certificate anomalies, self-signed certs |

---

## 🎤 Interview Answer

> *"Walk me through a phishing investigation you've conducted."*

"In Case-001, I investigated a spearphishing attack against a finance department employee. The attacker impersonated the CFO using a compromised third-party mail server — bypassing IP reputation checks — and delivered a macro-enabled Excel file. I traced the attack through all seven OSI layers: the SPF failure at Layer 3 that an email gateway should have caught, the macro obfuscation at Layer 6 that bypassed AV, and the RAT's HTTPS beacon at Layer 4 using port 443 to blend into legitimate traffic. I mapped nine MITRE ATT&CK techniques from initial access through to C2 persistence, wrote detection rules in Sigma, Splunk SPL, and Microsoft Sentinel KQL, and identified the DNS query to the C2 domain as the earliest detectable indicator — logged before the first beacon fired. The full investigation is documented in my GitHub portfolio."

---

## 🔗 Related Work

| Resource | Link |
|----------|------|
| Detection Rules — Sigma | [`/detection-rules/sigma/`](../../detection-rules/sigma/) |
| Detection Rules — SPL | [`/detection-rules/splunk-spl/`](../../detection-rules/splunk-spl/) |
| Detection Rules — KQL | [`/detection-rules/sentinel-kql/`](../../detection-rules/sentinel-kql/) |
| Lab Setup — Suricata | [`/lab-setup/suricata-ids/`](../../lab-setup/suricata-ids/) |
| YouTube Video | 🔄 In production — [Granger Security](https://youtube.com/@Granger-Security) |

---

<div align="center">

*Investigation #1 of 30 — Case closed.*
*Every layer produced evidence. Every layer offered a detection opportunity.*

</div>
