# Investigation 001: Phishing Email Traced Through OSI Model

## Executive Summary

A spearphishing campaign targeting UK financial services was analyzed by tracing a single malicious email through all seven layers of the OSI model. The investigation identified four distinct MITRE ATT&CK techniques and documented specific defender evidence available at each network layer. This analysis demonstrates how understanding network fundamentals enables comprehensive threat detection across the entire attack chain.

**Key Findings:**
- Initial access via spearphishing attachment (T1566.001)
- Command and control over encrypted HTTPS (T1071.001)
- Defense evasion through file obfuscation (T1027)
- Infrastructure acquisition via compromised third-party server (T1583.004)

---

## Incident Overview

| Field | Details |
|-------|---------|
| **Incident ID** | 001 |
| **Date Analyzed** | February 2026 |
| **Attack Type** | Spearphishing with Macro-Enabled Attachment |
| **Target** | Finance employee at UK banking institution |
| **Severity** | 🔴 Critical |
| **MITRE Tactics** | Initial Access, Execution, Defense Evasion, Command & Control |

---

## Attack Scenario

**Threat Actor Objective:** Establish persistent remote access to corporate network

**Attack Chain:**
1. Adversary sends spearphishing email impersonating CFO
2. Email contains malicious Excel attachment with embedded macro
3. Email delivered via compromised third-party mail server
4. Employee opens attachment and enables macro execution
5. Macro downloads and executes Remote Access Trojan (RAT)
6. RAT establishes C2 beacon over HTTPS port 443

---

## OSI Model Layer Analysis

### Layer 7 — Application Layer

**What Happened:**
The finance employee's email client (using SMTP protocol) receives and renders the phishing email. The message displays as a convincing CFO impersonation. Upon opening the Excel attachment, the embedded macro executes. The RAT payload initiates C2 communication using HTTPS over port 443, blending with legitimate web traffic.

**Protocols Involved:**
- SMTP (Simple Mail Transfer Protocol) - Email delivery
- HTTPS (HTTP Secure) - C2 communication
- DNS - Domain resolution for C2 server

**Defender Evidence:**
- Email security gateway logs (SMTP headers, sender reputation)
- Proxy logs showing HTTPS connections to suspicious domains
- DNS query logs revealing unknown C2 infrastructure
- Email attachment metadata (file hashes, macro detection)

**MITRE ATT&CK Mapping:**
- **T1566.001** - Phishing: Spearphishing Attachment
- **T1071.001** - Application Layer Protocol: Web Protocols (HTTPS C2)

**Detection Opportunities:**
```
High-value indicators:
- Sender Policy Framework (SPF) failures
- DMARC authentication failures  
- Suspicious attachment file types (.xlsm, .docm)
- Unusual outbound HTTPS connections post-email delivery
- DNS queries to recently registered domains
```

---

### Layer 6 — Presentation Layer

**What Happened:**
The malicious Excel attachment is encoded for network transmission and decoded upon arrival at the victim's system. The RAT's C2 traffic is encrypted using TLS to evade network inspection. The macro code within the Excel file is obfuscated to bypass signature-based detection.

**Protocols Involved:**
- TLS (Transport Layer Security) - Encryption wrapper
- Character encoding (UTF-8, Base64) - Data representation

**Defender Evidence:**
- Encrypted payloads delivered to endpoints not typically receiving encrypted files
- Unusual encoding schemes in email attachments
- TLS certificate anomalies (self-signed certs, unusual issuers)
- Obfuscated macro code detected by sandboxing

**MITRE ATT&CK Mapping:**
- **T1027** - Obfuscated Files or Information
- **T1573** - Encrypted Channel (for C2 traffic)

**Detection Opportunities:**
```
High-value indicators:
- File entropy analysis (high entropy = possible encryption/obfuscation)
- TLS inspection revealing suspicious certificate chains
- Sandbox detonation detecting obfuscated VBA macros
- Unexpected data encoding in email MIME parts
```

---

### Layer 5 — Session Layer

**What Happened:**
An SMTP session is established between the attacker's compromised mail server and the victim organization's mail server. Authentication occurs, and the email transfer session is maintained until completion. Post-compromise, the RAT maintains a persistent session with the C2 server, periodically sending keepalive beacons to maintain the connection.

**Defender Evidence:**
- Abnormally long-duration sessions to external IPs
- Session persistence patterns inconsistent with normal user behavior
- Authentication logs showing mail server sessions from suspicious sources
- Frequent reconnection attempts after initial access

**MITRE ATT&CK Mapping:**
- **T1572** - Protocol Tunneling (maintaining C2 sessions inside legitimate protocols)

**Detection Opportunities:**
```
High-value indicators:
- Sessions lasting hours/days to unknown external IPs
- Beaconing behavior (regular interval connections)
- Session establishment from internal hosts to non-standard destinations
- Multiple session resets/reconnections in short timeframes
```

---

### Layer 4 — Transport Layer

**What Happened:**
TCP establishes a reliable connection via three-way handshake (SYN, SYN-ACK, ACK) between mail servers. Email data is segmented, transmitted with sequence numbers, and reassembled at the destination. The RAT beacon uses TCP port 443 to blend with legitimate HTTPS traffic. TCP ensures all C2 commands and responses are delivered reliably.

**Protocols Involved:**
- TCP (Transmission Control Protocol)

**Defender Evidence:**
- Network flow data showing connection establishment patterns
- Unusual port usage or port scanning activity
- TCP connection volumes inconsistent with baseline
- SYN/ACK patterns indicating potential reconnaissance

**MITRE ATT&CK Mapping:**
- **T1571** - Non-Standard Port (if C2 uses unusual ports)

**Detection Opportunities:**
```
High-value indicators:
- Outbound connections on port 443 from non-browser processes
- TCP sessions with minimal data transfer (C2 keepalives)
- Unexpected internal-to-internal TCP connections (lateral movement)
- Port scanning signatures (multiple SYN packets, no established connections)
```

---

### Layer 3 — Network Layer

**What Happened:**
The phishing email travels as IP packets from the attacker's compromised server (source IP) to the victim organization's mail server (destination IP). Each router along the path reads the destination IP address and makes forwarding decisions. The attacker deliberately used a compromised third-party server to obscure their true origin IP and complicate attribution.

**Protocols Involved:**
- IP (Internet Protocol) - IPv4/IPv6
- ICMP (Internet Control Message Protocol) - Error reporting

**Defender Evidence:**
- Source IP addresses in email headers
- Threat intelligence reputation checks (VirusTotal, AbuseIPDB)
- Geolocation data showing unusual sender origins
- Routing path analysis via traceroute

**MITRE ATT&CK Mapping:**
- **T1583.004** - Acquire Infrastructure: Server (compromised mail relay)

**Detection Opportunities:**
```
High-value indicators:
- Source IPs on threat intelligence blocklists
- Geolocation mismatches (claimed sender vs. actual IP location)
- IP reputation scores below organizational threshold
- Sender IPs with short domain registration history
```

---

### Layer 2 — Data Link Layer

**What Happened:**
Network traffic moves between devices as Ethernet frames. Each switch reads the destination MAC address and forwards frames to the appropriate port. In this phishing scenario, Layer 2 operates transparently during initial delivery. However, post-compromise, if the attacker attempts lateral movement, ARP poisoning or MAC spoofing attacks may occur at this layer.

**Protocols Involved:**
- Ethernet
- ARP (Address Resolution Protocol)

**Defender Evidence:**
- ARP cache anomalies (duplicate MAC addresses)
- Unexpected MAC address changes for critical systems
- Switch port security violations
- Rogue device detection on network segments

**MITRE ATT&CK Mapping:**
- **T1557.002** - Adversary-in-the-Middle: ARP Cache Poisoning

**Detection Opportunities:**
```
High-value indicators:
- ARP spoofing alerts from IDS (Suricata)
- Multiple MAC addresses claiming same IP
- Switches logging security violations
- Unexpected broadcast storms on network segments
```

---

### Layer 1 — Physical Layer

**What Happened:**
Electrical signals (copper Ethernet), light pulses (fiber optic), or radio waves (Wi-Fi) physically transmit the phishing email data across network infrastructure. The attack traffic appears identical to legitimate traffic at this layer—there is no inherent "malicious" electrical signal. Physical layer attacks in this scenario are unlikely but could include rogue Wi-Fi access points or hardware implants.

**Defender Evidence:**
- Physical port monitoring (unused ports suddenly active)
- Wireless intrusion detection (rogue access points)
- Data center physical security logs
- Cable plant integrity monitoring

**MITRE ATT&CK Mapping:**
- **T1200** - Hardware Additions (if physical implants used)

**Detection Opportunities:**
```
High-value indicators:
- Unexpected devices detected on physical network ports
- Rogue wireless access points broadcasting corporate SSIDs
- Unusual signal patterns in RF monitoring
- Physical security alerts (unauthorized data center access)
```

---

## Complete Attack Flow Visualization
```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 7: Application                                            │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Phishing email (SMTP) → Outlook renders → User opens Excel │ │
│ │ Macro executes → RAT beacons to C2 (HTTPS/443)             │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 6: Presentation                                           │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Attachment encoded → TLS encrypts C2 → Macro obfuscated    │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Session                                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ SMTP session established → RAT maintains persistent C2      │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Transport                                              │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ TCP 3-way handshake → Segments transmitted → Port 443 C2   │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Network                                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ IP routing → Compromised server source IP → Threat intel   │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Data Link                                              │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Ethernet frames → MAC addressing → Switch forwarding       │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Physical                                               │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Electrical signals → Fiber optic → Wi-Fi radio waves       │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name | OSI Layer(s) |
|--------|--------------|----------------|--------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Layer 7 |
| Execution | T1204.002 | User Execution: Malicious File | Layer 7 |
| Defense Evasion | T1027 | Obfuscated Files or Information | Layer 6 |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | Layer 7 |
| Command & Control | T1573 | Encrypted Channel | Layer 6 |
| Resource Development | T1583.004 | Acquire Infrastructure: Server | Layer 3 |

---

## Detection Rule Framework

### Suricata IDS Rule (Layer 2-4)
```
alert tcp any any -> any 443 (msg:"Possible RAT Beacon - Regular HTTPS Intervals"; 
  flow:established,to_server; 
  threshold:type both, track by_src, count 10, seconds 60; 
  classtype:trojan-activity; 
  sid:1000001; rev:1;)
```

### Sigma Rule (Layer 7 - Email Gateway)
```yaml
title: Spearphishing Attachment with Macro
id: phishing-001-macro-attachment
status: stable
description: Detects email delivery with macro-enabled Office attachments
author: Bhargav Baranda
date: 2026/02/10
logsource:
    product: email_gateway
    service: smtp
detection:
    selection:
        attachment_extension:
            - '.xlsm'
            - '.docm'
            - '.xlam'
        spf_result: 'fail'
    condition: selection
falsepositives:
    - Legitimate macro-enabled documents from trusted business partners
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
```

### ELK Query (Layer 7 - C2 Detection)
```kql
event.category:"network" AND 
destination.port:443 AND 
network.protocol:"https" AND 
NOT process.name:("chrome.exe" OR "firefox.exe" OR "msedge.exe") AND
network.bytes < 5000
```

---

## Remediation Playbook

### Immediate Actions (0-1 Hour)

1. **Quarantine affected endpoint** - Isolate from network to prevent C2 communication
2. **Block C2 infrastructure** - Add IP/domain to firewall blocklist at Layer 3
3. **Suspend compromised user account** - Prevent credential use for lateral movement
4. **Preserve forensic evidence** - Memory dump, disk image, network packet capture

### Short-Term Actions (1-24 Hours)

1. **Hunt for additional infections** - Search SIEM for similar C2 patterns across fleet
2. **Analyze macro payload** - Reverse engineer to identify full capabilities
3. **Review email gateway logs** - Identify all recipients of phishing campaign
4. **Update detection rules** - Deploy new Sigma/Suricata rules based on IOCs

### Long-Term Remediation (1-7 Days)

1. **Patch vulnerable applications** - Ensure Office macros disabled by default
2. **Deploy email authentication** - Implement strict SPF/DMARC/DKIM enforcement
3. **Conduct user awareness training** - Phishing simulation targeting finance team
4. **Improve Layer 7 inspection** - Upgrade email security gateway capabilities

---

## Lessons Learned

### What Worked Well

- Multi-layer defense strategy provided detection opportunities at Layers 3, 6, and 7
- Email gateway SPF checks flagged suspicious sender at Layer 7
- Network monitoring identified unusual C2 beaconing at Layer 4

### What Could Be Improved

- Endpoint protection should have blocked macro execution (Layer 7)
- TLS inspection at Layer 6 could have revealed encrypted C2 payload
- User awareness training needed—finance employees high-value targets

### Recommendations

1. **Layer 7 Enhancement:** Implement advanced email sandbox for detonating attachments pre-delivery
2. **Layer 6 Enhancement:** Deploy TLS inspection for outbound HTTPS traffic
3. **Layer 3 Enhancement:** Integrate threat intelligence feeds into email gateway for real-time IP reputation
4. **User Controls:** Enforce Group Policy to disable Office macros for standard users

---

## Security+ Knowledge Connection

**CompTIA Security+ SY0-701 Coverage:**

- **Objective 1.4** - Given a scenario, analyze potential indicators associated with network attacks
- **Objective 2.2** - Explain common threat vectors and attack surfaces
- **Objective 4.1** - Given a scenario, apply common security techniques to computing resources

**OSI Model Study Aid:**

**Bottom-to-Top Mnemonic:** "Please Do Not Throw Sausage Pizza Away"
- **P**hysical
- **D**ata Link  
- **N**etwork
- **T**ransport
- **S**ession
- **P**resentation
- **A**pplication

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- OSI Model RFC 1122: https://www.rfc-editor.org/rfc/rfc1122
- Suricata Rule Documentation: https://suricata.io/
- Sigma Detection Rule Repository: https://github.com/SigmaHQ/sigma

---

**Analysis Completed:** February 10, 2026  
**Analyst:** Bhargav Baranda  
**Investigation ID:** 001
