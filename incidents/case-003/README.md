<div align="center">

# 🟢 Case-003 — Network Segmentation Analysis: Dividing a Network Without a Calculator

**What subnetting actually is, why it matters, and how it catches attackers — explained without jargon.**

![Severity](https://img.shields.io/badge/Severity-Low-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Closed-brightgreen?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1021_%7C_T1018_%7C_T1210-orange?style=flat-square)
![Method](https://img.shields.io/badge/Method-Mental_Arithmetic-blue?style=flat-square)
![Detection](https://img.shields.io/badge/Detection-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## 📋 Investigation Summary

| Field | Details |
|-------|---------|
| **Case ID** | 003 |
| **Date** | 2026-03-06 |
| **Lab Type** | Network Fundamentals — Subnetting |
| **Method** | Mental arithmetic — no calculator |
| **Objective** | Divide 192.168.1.0/24 into four equal /26 subnets |
| **Skill Focus** | Network segmentation, IP addressing, lateral movement detection |
| **Analyst** | Bhargav Baranda |

---

## 🎯 Executive Summary

A /24 network (192.168.1.0) was divided into four equal /26 subnets using mental arithmetic — no calculator, no online tools. This exercise demonstrates the foundational network architecture knowledge required for real-time SOC operations: identifying which subnet a suspicious IP belongs to, spotting cross-boundary traffic that indicates lateral movement, and making these assessments in under ten seconds during an active incident.

**A SOC analyst who cannot read a network map cannot investigate an attack on one.**

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Relevance |
|--------|-----------|--------------|-----------|
| Lateral Movement | T1021 — Remote Services | T1021.002 — SMB/Windows Admin Shares | Cross-subnet SMB traffic is a primary lateral movement indicator |
| Discovery | T1018 — Remote System Discovery | — | Attackers scan across subnet boundaries to map target infrastructure |
| Lateral Movement | T1210 — Exploitation of Remote Services | — | Services exposed across improperly segmented subnets enable spread |

---

## 🏙️ The Street Analogy — What Subnetting Actually Is

Before any numbers: **subnetting is how networks are built.**

Think of the internet as a massive city. That city is divided into neighbourhoods, streets, and individual houses. Subnetting draws those neighbourhood boundaries — deciding which computers live together in the same zone, which zones can talk to each other, and where the fences go between them.

When a security alert fires, it includes an IP address. The analyst must instantly know:
- Which network segment does this device belong to?
- Which department or security zone is it in?
- Which firewall rules apply?
- Should this device be communicating with that destination?

All of those answers flow from subnetting.

---

## 📐 IP Addressing Fundamentals

### What is an IP Address?

```
192.168.1.0
```

Four numbers (octets) separated by dots. Each octet = 8 bits. Total = 32 bits.
Range per octet: 0–255.

### What Does /24 Mean?

```
/24 = 24 bits identify the network
      32 - 24 = 8 bits left for devices
      2⁸ = 256 possible addresses
```

### Reserved Addresses — The Two You Can Never Use

| Address | Name | Purpose | Analogy |
|---------|------|---------|---------|
| First (.0) | Network Address | Identifies the network itself | Street sign with the street name |
| Last (.255) | Broadcast Address | Sends to all devices simultaneously | Megaphone reaching every house |

**Result:** 256 total − 2 reserved = **254 usable addresses** per /24.

---

## 🧮 The Four-Step Mental Process

> Memorise this sequence. Answer any subnetting question under exam pressure or at 3am during an active incident.

```
STEP 1 — HOST BITS:       32 - prefix = host bits
                          32 - 24 = 8

STEP 2 — BITS TO BORROW:  2ⁿ ≥ subnets needed
                          2² = 4  →  borrow 2 bits

STEP 3 — NEW PREFIX:      original + borrowed
                          24 + 2 = /26

STEP 4 — BLOCK SIZE:      2^remaining host bits
                          2⁶ = 64 addresses per subnet
```

**Verification:** 4 subnets × 64 addresses = 256 ✅ — matches original /24 exactly. No overlap. No gaps.

---

## 🗺️ The Four Subnets — Complete Breakdown

### Subnet 1 — 192.168.1.0/26

```
Network Address:    192.168.1.0    ← Street sign — reserved
First Usable Host:  192.168.1.1
Last Usable Host:   192.168.1.62
Broadcast Address:  192.168.1.63  ← Megaphone — reserved
Usable Hosts:       62
```

### Subnet 2 — 192.168.1.64/26

```
Network Address:    192.168.1.64   ← Reserved
First Usable Host:  192.168.1.65
Last Usable Host:   192.168.1.126
Broadcast Address:  192.168.1.127  ← Reserved
Usable Hosts:       62
```

### Subnet 3 — 192.168.1.128/26

```
Network Address:    192.168.1.128  ← Reserved
First Usable Host:  192.168.1.129
Last Usable Host:   192.168.1.190
Broadcast Address:  192.168.1.191  ← Reserved
Usable Hosts:       62
```

### Subnet 4 — 192.168.1.192/26

```
Network Address:    192.168.1.192  ← Reserved
First Usable Host:  192.168.1.193
Last Usable Host:   192.168.1.254  ← Always one before .255
Broadcast Address:  192.168.1.255  ← Reserved
Usable Hosts:       62
```

> ⚠️ **Critical rule:** The last usable host is always **.254** — never .256. An octet never exceeds 255. This mistake is made once in practice. Never again.

---

## 📊 Complete Subnet Summary

| Subnet | Network Address | First Host | Last Host | Broadcast | Usable |
|:------:|----------------|------------|-----------|-----------|:------:|
| 1 /26 | 192.168.1.0 | 192.168.1.1 | 192.168.1.62 | 192.168.1.63 | 62 |
| 2 /26 | 192.168.1.64 | 192.168.1.65 | 192.168.1.126 | 192.168.1.127 | 62 |
| 3 /26 | 192.168.1.128 | 192.168.1.129 | 192.168.1.190 | 192.168.1.191 | 62 |
| 4 /26 | 192.168.1.192 | 192.168.1.193 | 192.168.1.254 | 192.168.1.255 | 62 |

**Verification:** 4 × 64 = 256 ✅

---

## 📋 The Cheat Sheet — 90% of Subnetting Questions

| Prefix | Block Size | Usable Hosts | Subnets from /24 |
|:------:|:----------:|:------------:|:----------------:|
| /25 | 128 | 126 | 2 |
| /26 | 64 | 62 | 4 ← **This lab** |
| /27 | 32 | 30 | 8 |
| /28 | 16 | 14 | 16 |
| /29 | 8 | 6 | 32 |
| /30 | 4 | 2 | 64 |

**The pattern:** Every step down — block size halves, number of subnets doubles. Once seen, the table writes itself.

---

## 🚨 Security Application — Lateral Movement Detection

> This is where subnetting stops being theory and becomes operational SOC skill.

### Live Alert Scenario

```
Timestamp:  2026-03-06 03:42:15 UTC
Source:     192.168.1.147
Destination: 192.168.1.200
Protocol:   SMB (Port 445)
Action:     Connection Established
```

### Instant Analysis — No Calculator

```
192.168.1.147 → falls between 128–191 → Subnet 3
192.168.1.200 → falls between 192–255 → Subnet 4

Traffic is crossing a subnet boundary.
```

**SMB traffic crossing subnet boundaries without firewall authorisation = potential lateral movement.**

### Investigation Actions

1. Query firewall logs — is `192.168.1.147 → 192.168.1.200` on port 445 authorised?
2. If no authorisation found → **escalate as potential lateral movement**
3. Check authentication logs on `192.168.1.200` — any successful logins from `.147`?
4. Review recent activity from `192.168.1.147` — is this machine already compromised?
5. Isolate both endpoints if compromise confirmed

**Total analysis time from alert to escalation decision: under 10 seconds.**

---

## 🛡️ Detection Rules

### Sigma — Cross-Subnet SMB Lateral Movement

```yaml
title: SMB Connection Crossing Subnet Boundary
status: experimental
description: >
  Detects SMB traffic crossing /26 subnet boundaries without
  corresponding firewall authorisation. Primary indicator of
  lateral movement post-initial-compromise.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: Bhargav Baranda (Granger0007)
date: 2026/03/06
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.discovery
  - attack.t1018
logsource:
  product: zeek
  service: conn
detection:
  selection:
    dest_port:
      - 445
      - 139
    proto: tcp
  filter_same_subnet:
    # Traffic within same /26 subnet — not suspicious
    src_ip|cidr:
      - '192.168.1.0/26'
    dest_ip|cidr:
      - '192.168.1.0/26'
  condition: selection and not filter_same_subnet
falsepositives:
  - Authorised cross-subnet file shares — whitelist by firewall rule
  - Domain controllers communicating across subnets
level: medium
```

### Splunk SPL — Subnet Boundary Crossing Detection

```spl
| Comment: T1021.002 — Cross-subnet SMB lateral movement detection
| Comment: Flags SMB traffic crossing /26 boundaries in 192.168.1.0/24
| Comment: Author: Bhargav Baranda | Date: 2026-03-06

index=network earliest=-24h dest_port IN (445, 139)
| eval src_subnet=case(
    cidrmatch("192.168.1.0/26",   src_ip), "Subnet_1_0-63",
    cidrmatch("192.168.1.64/26",  src_ip), "Subnet_2_64-127",
    cidrmatch("192.168.1.128/26", src_ip), "Subnet_3_128-191",
    cidrmatch("192.168.1.192/26", src_ip), "Subnet_4_192-255",
    true(), "External_or_Unknown"
  )
| eval dest_subnet=case(
    cidrmatch("192.168.1.0/26",   dest_ip), "Subnet_1_0-63",
    cidrmatch("192.168.1.64/26",  dest_ip), "Subnet_2_64-127",
    cidrmatch("192.168.1.128/26", dest_ip), "Subnet_3_128-191",
    cidrmatch("192.168.1.192/26", dest_ip), "Subnet_4_192-255",
    true(), "External_or_Unknown"
  )
| where src_subnet != dest_subnet
| stats
    count AS connection_count,
    values(dest_port) AS ports,
    values(dest_ip) AS destinations
    BY src_ip, src_subnet, dest_subnet
| sort - connection_count
| table src_ip, src_subnet, dest_subnet, connection_count, ports, destinations
```

### Microsoft Sentinel KQL — Internal Subnet Scanning

```kql
// T1018 — Remote System Discovery across subnet boundaries
// Detects internal scanning behaviour consistent with post-compromise recon
// Author: Bhargav Baranda (Granger0007) | Date: 2026-03-06

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (445, 139, 3389, 22, 80, 443)
| where RemoteIPType == "Private"
| extend SrcSubnet = case(
    ipv4_is_in_range(LocalIP,  "192.168.1.0",   "192.168.1.63"),  "Subnet1",
    ipv4_is_in_range(LocalIP,  "192.168.1.64",  "192.168.1.127"), "Subnet2",
    ipv4_is_in_range(LocalIP,  "192.168.1.128", "192.168.1.191"), "Subnet3",
    ipv4_is_in_range(LocalIP,  "192.168.1.192", "192.168.1.255"), "Subnet4",
    "Unknown"
  )
| extend DstSubnet = case(
    ipv4_is_in_range(RemoteIP, "192.168.1.0",   "192.168.1.63"),  "Subnet1",
    ipv4_is_in_range(RemoteIP, "192.168.1.64",  "192.168.1.127"), "Subnet2",
    ipv4_is_in_range(RemoteIP, "192.168.1.128", "192.168.1.191"), "Subnet3",
    ipv4_is_in_range(RemoteIP, "192.168.1.192", "192.168.1.255"), "Subnet4",
    "Unknown"
  )
| where SrcSubnet != DstSubnet
| summarize
    ConnectionCount = count(),
    TargetPorts = make_set(RemotePort),
    TargetIPs = make_set(RemoteIP)
    by DeviceName, LocalIP, SrcSubnet, DstSubnet
| where ConnectionCount > 5
| sort by ConnectionCount desc
```

---

## 💼 Business Impact Assessment

| Factor | Assessment |
|--------|-----------|
| **Scope** | Network-wide — applies to all subnets |
| **Lateral movement risk** | High if subnet boundaries are not enforced by firewall rules |
| **Detection gap** | Unmonitored cross-subnet traffic creates blind spots for post-compromise spread |
| **Regulatory exposure** | GDPR — lateral movement leading to data exfiltration triggers Article 33 ICO notification |
| **Remediation cost** | Low — firewall rule review and SIEM rule deployment |

---

## 🔧 Remediation Playbook

### Immediate (0–4 hours)
- [ ] Review firewall rules for authorised cross-subnet traffic
- [ ] Identify any undocumented SMB connections crossing subnet boundaries
- [ ] Deploy cross-subnet detection rule to SIEM immediately

### Short-term (24–72 hours)
- [ ] Document all authorised cross-subnet communication paths
- [ ] Implement default-deny firewall policy between subnets
- [ ] Enable SMB signing to prevent relay attacks

### Long-term (weeks/months)
- [ ] Implement microsegmentation — restrict east-west traffic by role
- [ ] Quarterly network architecture review
- [ ] Tabletop exercise: lateral movement scenario across segmented network

---

## ⚠️ The Mistake I Made — And Why It Matters

During this exercise, a broadcast address was written as `192.168.0.256`.

**That address does not exist.**

An IP address octet runs from 0 to 255. Writing .256 is an arithmetic error. The correct address was `192.168.0.255`.

**Rule:** The last subnet's broadcast is always .255. The last usable host is always .254.

This mistake is made once in practice. Under exam pressure or during an active incident, this error costs time and credibility. It is now permanently corrected.

---

## 📚 Security+ SY0-701 Connection

| Objective | Concept Demonstrated |
|-----------|-------------------|
| **3.3** — Secure network architecture | Subnetting, VLSM, network segmentation, microsegmentation |
| **2.2** — Threat vectors | Lateral movement patterns, subnet boundary crossing |
| **4.1** — Security tools | Network monitoring, firewall log analysis |

**Exam note:** Security+ does not allow calculators. Subnetting questions must be solved mentally using the four-step process documented in this lab.

---

## 🎤 Interview Answer

> *"How would you investigate a potential lateral movement alert?"*

"First, I analyse the source and destination IPs to determine whether they're in the same subnet or crossing boundaries. If I see traffic from 192.168.1.147 to 192.168.1.200 in a /24 network divided into /26 subnets, I immediately identify that as Subnet 3 communicating with Subnet 4 — a boundary crossing. I check firewall logs to verify whether that cross-subnet traffic is authorised. If there's no firewall rule permitting it, and it's SMB or RDP traffic, that's a strong indicator of lateral movement. I can do this analysis mentally in under ten seconds without a subnet calculator. The detection rule for this pattern is deployed in my home lab's SIEM and documented in my GitHub portfolio."

---

## 🔗 Related Work

| Resource | Link |
|----------|------|
| Case-001 — Phishing Investigation | [`../case-001/`](../case-001/) |
| Case-002 — TCP Traffic Analysis | [`../case-002/`](../case-002/) |
| Detection Rules — Sigma | [`/detection-rules/sigma/`](../../detection-rules/sigma/) |
| Detection Rules — SPL | [`/detection-rules/splunk-spl/`](../../detection-rules/splunk-spl/) |
| Detection Rules — KQL | [`/detection-rules/sentinel-kql/`](../../detection-rules/sentinel-kql/) |
| YouTube Video | 🔄 In production — [Granger Security](https://youtube.com/@Granger-Security) |

---

<div align="center">

*Investigation #3 of 30 — Case closed.*
*The network is divided. The boundaries are drawn. The attacker has nowhere to hide.*

</div>
