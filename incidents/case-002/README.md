<div align="center">

# 🟡 Case-002 — TCP Traffic Analysis: I Watched My Own Computer Talk to Google

**What really happens inside your network when you visit a website — and what it teaches a SOC analyst about catching attackers.**

![Severity](https://img.shields.io/badge/Severity-Medium-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Closed-brightgreen?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1040_%7C_T1071.001_%7C_T1557-orange?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square)
![Detection](https://img.shields.io/badge/Detection-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## 📋 Investigation Summary

| Field | Details |
|-------|---------|
| **Case ID** | 002 |
| **Date** | 2026-03-06 |
| **Lab Type** | Network Traffic Analysis |
| **Tool** | Wireshark |
| **Environment** | Kali Linux ARM64 — VirtualBox — MacBook Pro Apple Silicon |
| **Network Interface** | eth0 — IP: 192.168.64.3 |
| **Target** | http://google.com → 192.178.223.102 |
| **Analyst** | Bhargav Baranda |
| **Packets Captured** | 10 |

---

## 🎯 Executive Summary

Using Wireshark on Kali Linux, live network traffic was captured from a single HTTP request to Google. Ten packets revealed the complete TCP connection lifecycle — three-way handshake, data transfer, and connection termination — across all seven OSI layers simultaneously.

Two security findings emerged: an unencrypted HTTP initiation creating an SSL stripping vulnerability window, and an unknown outbound destination IP requiring threat intelligence verification. Both findings map directly to SOC analyst workflows used daily in enterprise environments.

**The key insight: every network connection — no matter how mundane — leaves a trail with structure, meaning, and evidence.**

---

## 🖥️ Lab Environment

```
MacBook Pro (Apple Silicon M-series)
└── VirtualBox
    └── Kali Linux ARM64
        ├── Interface: eth0
        ├── IP Address: 192.168.64.3
        ├── Tool: Wireshark
        └── Command: curl http://google.com
```

**Wireshark filter applied:** `tcp.stream eq 0`

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Relevance |
|--------|-----------|--------------|-----------|
| Collection | T1040 — Network Sniffing | — | Packet capture is what attackers do after compromising a network switch |
| Command & Control | T1071 — Application Layer Protocol | T1071.001 — Web Protocols | HTTP/HTTPS used for both legitimate traffic and C2 beaconing |
| Credential Access | T1557 — Adversary-in-the-Middle | T1557.002 — ARP Cache Poisoning | SSL stripping attack identified in Finding 1 |

---

## 📦 The Ten Packets — A Complete Connection Story

> One HTTP request. Ten packets. Less than 200 milliseconds. The complete story of a TCP connection from knock to goodbye.

---

### 🤝 The Three-Way Handshake (Packets 1–3)

```
MY KALI (192.168.64.3:38530)        GOOGLE (192.178.223.102:80)
         |                                    |
Packet 1 |─────────── [SYN] ──────────────>  | "Can we connect?"
Packet 2 |  <──────── [SYN, ACK] ──────────  | "Yes. Ready."
Packet 3 |─────────── [ACK] ──────────────>  | "Connected."
         |                                    |
         |    ← HANDSHAKE COMPLETE (38ms) →   |
```

**Packet 1 — SYN**
- Source: `192.168.64.3:38530` → Destination: `192.178.223.102:80`
- Port 80 = standard HTTP — a permanent, well-known address
- Port 38530 = **ephemeral port** — randomly assigned by the OS for this one conversation, discarded when done
- **SOC relevance:** Malware beaconing to a C2 server uses this exact mechanism. An internal machine repeatedly connecting to the same external IP on different ephemeral ports is a signature C2 beacon pattern.

**Packet 2 — SYN-ACK**
- Google acknowledges the SYN and synchronises its own side simultaneously
- Direction reverses — two-way communication now confirmed
- Both computers know the other is present and ready

**Packet 3 — ACK**
- Connection officially established
- Three packets. Three messages. Under one millisecond.
- **This handshake happens billions of times every second across the internet. Every website. Every email. Every stream.**

---

### 💬 The Data Exchange (Packets 4–7)

**Packet 4 — HTTP GET Request**
```
GET / HTTP/1.1
Host: google.com
```
- First actual content request — everything before was setup
- Travelled **completely unencrypted** across the network
- ⚠️ **Security concern raised here — see Finding 1 below**

**Packet 5 — ACK**
- Google confirms receipt of the GET request
- No response yet — pure TCP reliability confirmation
- If no ACK arrived, TCP would automatically retransmit

**Packet 6 — HTTP 301 Moved Permanently**
```
HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
```
- Google refuses to serve content over unencrypted HTTP
- Redirects to HTTPS version
- **Critical:** The redirect arrives *after* the unencrypted GET was already sent. The vulnerability window already opened and closed.

**Packet 7 — ACK**
- Redirect acknowledged. TCP confirming delivery.

---

### 👋 The Clean Goodbye (Packets 8–10)

```
MY KALI (192.168.64.3)              GOOGLE (192.178.223.102)
         |                                    |
Packet 8 |─── [FIN, ACK] ────────────────>   | "I'm done sending."
Packet 9 |  <─── [FIN, ACK] ───────────────  | "Me too."
Packet10 |─── [ACK] ─────────────────────>   | "Goodbye."
         |                                    |
         |    ← CONNECTION CLOSED (113ms) →   |
```

**FIN = Finished.** Both sides mutually agree the conversation is over.

**SOC relevance — clean vs abrupt termination:**
- ✅ Legitimate traffic: Clean FIN-ACK sequence (as seen here)
- ⚠️ Suspicious traffic: Abrupt RST (Reset) — forced termination
- RST floods indicate: malware being killed by EDR, unstable C2 channels, attacker cutting connection during detection

---

## 🌐 The Complete Picture

```
MY KALI MACHINE (192.168.64.3)     GOOGLE'S SERVER (192.178.223.102)
       |                                        |
       |──────────── [SYN] ─────────────────>  | "Can we connect?"
       |  <───────── [SYN, ACK] ─────────────  | "Yes, ready."
       |──────────── [ACK] ─────────────────>  | "Connected."
       |                                        |
       |  ←────── HANDSHAKE COMPLETE ─────────> |
       |                                        |
       |──────────── [GET /] ───────────────>  | "Give me your homepage."
       |  <───────── [ACK] ──────────────────  | "Request received."
       |  <───────── [301 Redirect] ──────────  | "Use HTTPS instead."
       |──────────── [ACK] ─────────────────>  | "Redirect received."
       |                                        |
       |  ←────── DATA TRANSFER DONE ─────────> |
       |                                        |
       |──────────── [FIN, ACK] ────────────>  | "I'm done."
       |  <───────── [FIN, ACK] ─────────────  | "Me too."
       |──────────── [ACK] ─────────────────>  | "Goodbye."
       |                                        |
       |  ←────── CONNECTION CLOSED ──────────> |
```

---

## 🔍 Reading One Packet Across All OSI Layers

> Packet 1 (SYN) — analysed at every layer simultaneously in Wireshark's detail panel.

| OSI Layer | Name | Evidence Found in Packet 1 |
|-----------|------|--------------------------|
| **Layer 1** | Physical | Captured on `eth0` — electrical signals on network card. Capture timestamp confirms exact transmission moment. |
| **Layer 2** | Data Link | Source MAC: `ee:7b:19:5a:69:12` — Kali VM's network card. Unique hardware identifier permanently assigned to this interface. |
| **Layer 3** | Network | Source IP: `192.168.64.3` — Kali machine's address. This is how Google knew where to send the SYN-ACK response. |
| **Layer 4** | Transport | Source port: `38530` (ephemeral). Destination port: `80` (HTTP). Together with IPs, these four values form the **socket pair** — the unique identifier of this TCP connection. |
| **Layer 5** | Session | Session establishment begins with this SYN. Session manager tracks state throughout the lifecycle. |
| **Layer 6** | Presentation | No encryption — plaintext HTTP. Contrast with HTTPS where this layer shows TLS encryption. |
| **Layer 7** | Application | HTTP protocol. The actual GET request arrives in Packet 4, but the application-layer handshake begins here. |

**The socket pair — four values that uniquely identify every TCP connection on earth:**
```
Source IP:        192.168.64.3
Source Port:      38530
Destination IP:   192.178.223.102
Destination Port: 80

No two active connections share the same four values simultaneously.
```

---

## 🚨 Security Findings

---

### Finding 1 — Unencrypted HTTP Initiation

**Severity:** Medium
**MITRE:** T1557 — Adversary-in-the-Middle

**The issue:**
Packet 4 — the GET request — travelled across the network completely unencrypted before Google's 301 HTTPS redirect arrived in Packet 6. The vulnerability window lasted approximately 37 milliseconds. Brief. But real.

**The SSL stripping attack scenario:**

An attacker with network access (via ARP poisoning at Layer 2) could:
1. Intercept Packet 4 — the unencrypted GET request — in transit
2. Block Packet 6 — the 301 redirect — from reaching the victim
3. Maintain the victim on HTTP permanently
4. Read all subsequent traffic in cleartext

The victim's browser shows HTTP. They never know they should have been on HTTPS. The attacker reads everything — session cookies, authentication tokens, request content.

**Why this matters in a corporate environment:**

That unencrypted request wasn't to Google — it was to an internal system. It contained session cookies in the headers. The attacker, sitting on a compromised network switch, is reading every unencrypted packet in real time.

**Detection opportunity:**
```
Alert: HTTP traffic (port 80) from corporate workstations
Policy: All web traffic must default to HTTPS
Trigger: Any plaintext HTTP initiation from internal host
Action: Log, alert, block at proxy
```

**Remediation:**
- Enforce HSTS (HTTP Strict Transport Security) at web server and browser level
- Configure corporate proxy to upgrade all HTTP to HTTPS automatically
- Deploy network monitoring for HTTP protocol violations
- Group Policy: disable HTTP for all managed browsers

---

### Finding 2 — Unknown Outbound Destination IP

**Severity:** Medium
**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols

**The issue:**
My machine connected to `192.178.223.102`. In this lab context, that's known to be Google. In a live SOC monitoring environment, an analyst sees only an internal machine making an outbound connection to an unfamiliar IP. That requires verification before any assumption of legitimacy.

**The threat intelligence verification workflow:**

| Tool | Query | Purpose |
|------|-------|---------|
| VirusTotal | `192.178.223.102` | Check against 90+ security vendor databases |
| AbuseIPDB | `192.178.223.102` | Community-reported malicious activity |
| AlienVault OTX | `192.178.223.102` | Known threat actor infrastructure mapping |
| Shodan | `192.178.223.102` | Services running, organisation, exposed ports |

**Result in this case:** Clean across all platforms — confirmed Google infrastructure.

**The principle that doesn't change:**
The verification workflow is **identical** whether the destination is Google or a ransomware C2 server in Eastern Europe. You run the lookup. You verify. You document. You never assume.

> "Unknown outbound IP gets a threat intelligence lookup before anything else. Thirty seconds of checking can be the difference between catching an active intrusion and letting a RAT beacon go unnoticed for eight months."

---

## 🛡️ Detection Rules

### Sigma — Unencrypted Outbound HTTP from Corporate Workstation

```yaml
title: Unencrypted HTTP Connection from Corporate Workstation
status: experimental
description: >
  Detects plaintext HTTP connections from internal workstations.
  Policy violation and potential SSL stripping interception indicator.
references:
  - https://attack.mitre.org/techniques/T1557/
author: Bhargav Baranda (Granger0007)
date: 2026/03/06
tags:
  - attack.credential_access
  - attack.t1557
logsource:
  product: zeek
  service: conn
detection:
  selection:
    dest_port: 80
    proto: tcp
  filter_internal:
    src_ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection and filter_internal
falsepositives:
  - Legacy applications that do not support HTTPS
  - Software update checks that use HTTP
level: medium
```

### Splunk SPL — C2 Beacon Pattern Detection

```spl
| Comment: T1071.001 — Detecting regular-interval outbound connections
| Comment: Beacon pattern: same destination, different ephemeral ports, regular timing
| Comment: Author: Bhargav Baranda | Date: 2026-03-06

index=network earliest=-24h
| eval bucket_5min=strftime(_time,"%Y-%m-%d %H:%M")
| stats
    count AS connections,
    dc(src_port) AS unique_src_ports,
    range(_time) AS duration_secs
    BY src_ip, dest_ip, dest_port
| where connections > 20
    AND unique_src_ports > 10
    AND duration_secs > 3600
| eval beacon_indicator=if(
    connections > 50 AND unique_src_ports > 20, "HIGH",
    connections > 20 AND unique_src_ports > 10, "MEDIUM",
    "LOW"
  )
| where beacon_indicator IN ("HIGH","MEDIUM")
| sort - connections
| table src_ip, dest_ip, dest_port, connections,
        unique_src_ports, duration_secs, beacon_indicator
```

### Microsoft Sentinel KQL — Abrupt Connection Termination (RST Flood)

```kql
// T1071.001 — Detecting RST-based abrupt connection termination
// Indicator of: malware termination, unstable C2, attacker evasion
// Author: Bhargav Baranda (Granger0007) | Date: 2026-03-06

CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction == "RST" or AdditionalExtensions contains "TCPFlags=RST"
| summarize
    RSTCount = count(),
    TargetIPs = make_set(DestinationIP),
    Ports = make_set(DestinationPort)
    by SourceIP, bin(TimeGenerated, 5m)
| where RSTCount > 10
| extend RiskLevel = case(
    RSTCount > 100, "High",
    RSTCount > 50,  "Medium",
    "Low"
  )
| project TimeGenerated, SourceIP, RSTCount, TargetIPs, Ports, RiskLevel
| sort by RSTCount desc
```

---

## 💼 Business Impact Assessment

| Factor | Assessment |
|--------|-----------|
| **Finding 1 scope** | Any workstation using HTTP — potentially entire organisation |
| **Data at risk** | Session cookies, auth tokens, unencrypted request content |
| **Regulatory exposure** | GDPR Article 5(1)(f) — integrity and confidentiality principle. Unencrypted personal data in transit is a compliance failure. |
| **Remediation cost** | Low — HSTS enforcement and proxy configuration |
| **SSL stripping risk** | Medium — requires attacker network access (post-compromise or rogue AP) |

---

## 🔧 Remediation Playbook

### Immediate (0–4 hours)
- [ ] Identify all workstations generating HTTP (port 80) outbound traffic
- [ ] Check proxy logs for any HTTP sessions that contained authentication headers

### Short-term (24–72 hours)
- [ ] Deploy HSTS enforcement across all managed web applications
- [ ] Configure corporate proxy to block or upgrade HTTP to HTTPS
- [ ] Enable HTTP policy violation alerting in SIEM

### Long-term (weeks/months)
- [ ] Browser hardening policy — disable HTTP for all managed devices
- [ ] Network segmentation review — limit ARP poisoning attack surface
- [ ] Security awareness: brief staff on HTTP vs HTTPS and phishing via rogue Wi-Fi

---

## 📚 Security+ SY0-701 Connection

| Objective | Concept Demonstrated |
|-----------|-------------------|
| **4.1** — Apply appropriate tool to assess security | Wireshark for network traffic analysis |
| **2.2** — Threat vectors and attack surfaces | SSL stripping, C2 beaconing patterns, ARP poisoning |
| **1.1** — Security controls | Network monitoring, egress filtering, HSTS |
| **3.3** — Secure network architecture | Protocol enforcement, proxy controls |

---

## 💡 The Lesson That Surprised Me

> I started this lab thinking I was going to learn about TCP handshakes. I ended it understanding something much more important.

Every network connection — every single one, no matter how mundane — leaves a trail. The trail has structure. The structure has meaning. And meaning, to a trained analyst, is evidence.

The curl command took less than a second. In that second, my machine generated 10 packets revealing: my IP address, my MAC address, my ephemeral port, the destination, the protocol, whether encryption was in use, how the connection opened, what data was requested, what response arrived, and how it closed.

**An attacker running a RAT generates the same trail.** Different destination. Different connection pattern. But the same fundamental structure. Packets. Flags. Ports. Timing. Trail.

A SOC analyst who understands what legitimate traffic looks like can spot what illegitimate traffic looks like. **That contrast is the entire job.**

---

## 🎤 Interview Answer

> *"Describe your home lab. What's the most complex thing you've detected?"*

"I run Wireshark on Kali Linux ARM64 in VirtualBox on Apple Silicon — a setup that required documented workarounds to get working, which are published on my GitHub. In a traffic analysis exercise I captured a complete TCP connection lifecycle across ten packets and read the evidence at every OSI layer simultaneously. I identified two security findings: an unencrypted HTTP initiation creating an SSL stripping vulnerability window, and an unknown outbound IP requiring threat intelligence verification. I mapped both to MITRE ATT&CK and wrote detection rules in Sigma, SPL, and KQL. The key insight was that legitimate traffic and malicious traffic share identical packet-level structure — the difference is destination, timing, and pattern. That contrast is how SOC analysts catch C2 beacons."

---

## 🔗 Related Work

| Resource | Link |
|----------|------|
| Case-001 — Phishing Investigation | [`../case-001/`](../case-001/) |
| Detection Rules — Sigma | [`/detection-rules/sigma/`](../../detection-rules/sigma/) |
| Detection Rules — SPL | [`/detection-rules/splunk-spl/`](../../detection-rules/splunk-spl/) |
| Detection Rules — KQL | [`/detection-rules/sentinel-kql/`](../../detection-rules/sentinel-kql/) |
| Lab Setup — Wireshark | [`/lab-setup/kali-virtualbox/`](../../lab-setup/kali-virtualbox/) |
| YouTube Video | 🔄 In production — [Granger Security](https://youtube.com/@Granger-Security) |

---

<div align="center">

*Investigation #2 of 30 — Case closed.*
*Ten packets. Every layer. The trail was always there.*

</div>
