# Lab 008 — Nmap Port Scanning: What Attackers See in 30 Seconds

**Date:** 22 April 2026
**Author:** Bhargav (Granger) Baranda
**Environment:** Kali Linux ARM64 · UTM · MacBook Pro Apple Silicon
**Tools:** Nmap 7.99 · Wireshark 4.6.3
**MITRE ATT&CK:** T1046 — Network Service Discovery
**Security+ Objectives:** SY0-701 4.1 · 2.2 · 3.1 · 4.4
**Status:** ✅ Complete

---

## Executive Summary

This lab demonstrated the complete Nmap port scanning methodology used by both attackers conducting reconnaissance and defenders assessing their own attack surface. Starting from a clean Kali Linux installation with no open ports, SSH was deliberately started to simulate an exposed service, scanned with progressively deeper Nmap commands, and every result analysed in full detail.

An authorised external scan of `scanme.nmap.org` produced a complete intelligence profile — open ports, service versions, operating system, and firewall configuration — in under 30 seconds from a single command. The entire scan was captured in Wireshark, revealing exactly what port scanning looks like on the wire and why it is detectable by any competent IDS.

**Key finding:** A single `nmap -sV` command automatically probed for VMware vCenter (CVE-2021-21985, CVSS 9.8), router admin panels, and CMS platforms — without the operator requesting it.

The lab connected directly to Lab 006 (ports and protocols), Lab 007 (firewalls and DMZ architecture), and Lab 005 (HTTP traffic analysis), demonstrating how theoretical knowledge maps to real-world offensive and defensive technique.

---

## Legal and Ethical Framework

| Target | IP | Authorisation |
|---|---|---|
| localhost | 127.0.0.1 | Own machine — always legal |
| scanme.nmap.org | 45.33.32.156 | Explicitly authorised by Nmap project |

> The Computer Misuse Act 1990 governs all activities in this lab. Scanning any system without explicit authorisation is illegal under UK law regardless of the technical accessibility of the target. No other systems were scanned.

---

## Environment

```bash
$ nmap --version
Nmap version 7.99
Platform: aarch64-unknown-linux-gnu
Compiled with: liblua-5.4.8 openssl-3.6.1 libssh2-1.11.1
               libz-1.3.1 libpcre2-10.46 libpcap-1.10.6
               nmap-libdnet-1.18.0 ipv6
```

ARM64 confirmed. IPv6 support confirmed — relevant because `scanme.nmap.org` has both IPv4 and IPv6 addresses.

---

## The Four Port States

| State | TCP Response | SOC Significance |
|---|---|---|
| **Open** | SYN-ACK | Service actively listening. Attack surface exists. |
| **Closed** | RST | No service listening. Machine is reachable. Normal state. |
| **Filtered** | No response | Firewall actively dropping packets. Cannot determine state. More suspicious than closed. |
| **Open\|Filtered** | No response | Cannot distinguish open from filtered. Specific scan types only. |

**SOC note:** Filtered is more suspicious than closed during incident investigations. Closed = normal. Filtered = something is actively hiding.

---

## Scan 1 — Localhost (No Services)

```bash
nmap localhost
```

**Output:**
```
Host is up (0.0000020s latency).
Other addresses for localhost: ::1
Not shown: 1000 closed tcp ports (reset)
All 1000 scanned ports on localhost (127.0.0.1) are in ignored states.
Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
```

**Analysis:**
- `0.0000020s latency` — 2 microseconds. Loopback interface — no network hop, no cable, no router
- `::1` — IPv6 loopback. On dual-stack networks, services may listen on IPv6 only — always check both
- `1000 closed tcp ports (reset)` — every port responded with RST. Machine reachable, OS functioning, no services running
- `0.09 seconds` — Nmap sends probes in parallel, hundreds in flight simultaneously
- **Clean machine = zero attack surface. This is the security ideal.**

---

## Scan 2 — Service Version Detection (No Services)

```bash
nmap -sV localhost
```

**Result:** Identical — 1,000 closed ports. Scan time increased from **0.09s to 0.20s**.

**Why timing matters:** Version detection sends additional probes per port. Even with no open ports, the overhead is measurable. An IDS recording scan timing patterns can distinguish basic host discovery from deeper service enumeration.

---

## Scan 3 — SSH Started, Version Detection Run

```bash
sudo systemctl start ssh
nmap -sV localhost
```

**Output:**
```
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 10.2p1 Debian 6 (protocol 2.0)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Field-by-field analysis:**

| Field | Value | Intelligence Extracted |
|---|---|---|
| Port | 22/tcp | Standard SSH. Not obfuscated. |
| State | open | SYN-ACK received. Service accepting connections. Attack surface. |
| Service | ssh | Confirmed by banner, not just port number. |
| Version | OpenSSH 10.2p1 | Exact version. Immediately CVE-searchable. |
| OS | Debian 6 | Distribution and packaging version. Narrows patch level. |
| CPE | cpe:/o:linux:linux_kernel | MITRE standard ID. Vulnerability scanners auto-match this. |

**One command extracted:** open port, service name, exact software version, OS distribution, and a machine-readable vulnerability identifier.

---

## Scan 4 — OS Fingerprinting

```bash
sudo nmap -sV -O localhost
```

**Output:**
```
No exact OS matches for host
OS:8P=aarch64-unknown-linux-gnu
Network Distance: 0 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 11.59 seconds
```

**Analysis:**
- No confident OS match — this machine runs **ARM64**. Nmap's fingerprint database has fewer ARM64 signatures than x86
- Even without a confident match, `aarch64-unknown-linux-gnu` reveals the CPU architecture
- `Network Distance: 0 hops` — scanning itself. In real investigations, distance reveals network topology
- Scan time jumped to **11.59 seconds** — multiple specialised probe packets, each waiting for full responses
- **Defender note:** OS fingerprinting can be defeated via TCP/IP stack normalisation at the firewall

---

## Scan 5 — Aggressive Scan

```bash
sudo nmap -A localhost
```

`-A` enables OS detection + version detection + script scanning + traceroute simultaneously.

**Result:** Similar to `-O`. NSE scripts returned nothing additional against OpenSSH 10.2p1 — a current, well-maintained version. **Keeping software current materially reduces what reconnaissance reveals.**

---

## Scan 6 — External Target: scanme.nmap.org

```bash
nmap -sV scanme.nmap.org
```

**Full output:**
```
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.19s latency).
Other addresses: 2600:3c01::f03c:91ff:fe18:bb2f

PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http       Apache httpd 2.4.7 ((Ubuntu))
113/tcp   filtered ident
427/tcp   filtered svrloc
9929/tcp  open     nping-echo Nping echo
31337/tcp open     tcpwrapped

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 29.45 seconds
```

---

## Intelligence Profile — scanme.nmap.org

### Complete Target Summary

| Item | Value |
|---|---|
| IP (IPv4) | 45.33.32.156 |
| IP (IPv6) | 2600:3c01::f03c:91ff:fe18:bb2f (dual-stack) |
| Latency | 0.19s (real internet — US-based server) |
| OS | Ubuntu Linux |
| Web server | Apache 2.4.7 — released **2013** |
| SSH | OpenSSH 6.6.1p1 — released **2014** |
| Firewall | Present — ports 113 and 427 filtered |
| Open ports | 22, 80, 9929, 31337 |
| CVE exposure | **HIGH** — both services are 10+ years old |

### Port-by-Port Analysis

**Port 22 — SSH — OPEN**
`OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)`

Released 2014. Twelve years old. My Kali machine runs OpenSSH 10.2p1 — the version gap is enormous. NVD search for `OpenSSH 6.6.1p1` returns multiple CVEs including memory corruption and authentication bypass conditions. A motivated attacker has an immediate, specific, researched attack path. The Ubuntu packaging suffix `2ubuntu2.13` further narrows the OS release and patch level.

**Port 80 — HTTP — OPEN**
`Apache httpd 2.4.7 (Ubuntu)`

Released 2013. Apache 2.4.7 has a documented CVE history across mod_status, mod_proxy, and core request handling. Serving unencrypted HTTP — identical to traffic analysed in Lab 005. Nmap's NSE scripts made real HTTP requests to this port during the scan.

**Port 113 — IDENT — FILTERED**
The IDENT protocol (RFC 1413) leaks user information and has no legitimate internet-facing purpose. A deliberate firewall rule blocks it. The filtering of this known-problematic legacy port while leaving 22 and 80 open reflects intentional architectural decision-making.

**Port 427 — SVRLOC — FILTERED**
Service Location Protocol. No legitimate external use. Also filtered. Pattern confirmed: the firewall selectively exposes ports 22 and 80 for their legitimate purposes, and filters everything else. This is correctly configured selective exposure.

**Port 9929 — Nping Echo — OPEN**
Part of the scanme.nmap.org test infrastructure. No real-world equivalent.

**Port 31337 — tcpwrapped — OPEN**
Port 31337 is "l33t" in hacker culture — historically the default port for Back Orifice (1998), one of the first RATs. Finding this in a real environment = immediate investigation. `tcpwrapped` = TCP handshake completed, service immediately closed the connection, no banner returned.

### Comparative Analysis

| | localhost | scanme.nmap.org |
|---|---|---|
| SSH version | OpenSSH 10.2p1 (2024) | OpenSSH 6.6.1p1 (2014) |
| HTTP server | Not running | Apache 2.4.7 (2013) |
| Firewall | None (direct scan) | Present (ports 113, 427 filtered) |
| Attack surface | Minimal (1 port) | Significant (4 open ports) |
| CVE exposure | Low | High |
| OS fingerprint | ARM64 (no match) | Ubuntu Linux (confirmed) |

---

## NSE Automatic Probes — The Hidden Reconnaissance

During the `-sV` scan, Nmap's NSE engine automatically made these HTTP requests to port 80:

```
GET  /                        — Basic probe, Apache fingerprint
POST /sdk                     — VMware vCenter API check
GET  /nmaplowercheck[random]  — 404 error fingerprinting
GET  /HNAP1                   — Router admin panel check
GET  /evox/about              — EvOX CMS check
GET  /                        — Additional probes
```

**The critical finding — `/sdk`:**

This endpoint is the VMware vSphere SDK API — the entry point for VMware vCenter Server. Three CVSS 9.8 vulnerabilities target it:
- **CVE-2021-21985** — unauthenticated RCE via Virtual SAN Health Check plugin
- **CVE-2021-21972** — unauthenticated arbitrary file upload
- **CVE-2021-22005** — unauthenticated arbitrary file write

Nmap probed for this **automatically**. The operator did not request it. Every `-sV` scan against any web server checks for vCenter, router admin panels, and CMS platforms simultaneously.

**SOC detection signature:**
```
/sdk + /HNAP1 + /nmaplowercheck[random] + /evox/about
= confirmed Nmap -sV scan
= IDS should fire immediately
```

No legitimate user ever requests `/HNAP1` on a corporate web server. These are unmistakable scanner fingerprints.

---

## Wireshark Capture

**File:** `lab-008-nmap-scan.pcap` | **Size:** 197KB | **Packets:** 2,328

Captured live using capture filter `host scanme.nmap.org` on `eth0`.

### Protocol Distribution

| Protocol | Packets | % | Meaning |
|---|---|---|---|
| Pure TCP | 2,306 | 99.1% | SYN probes + RST/SYN-ACK responses — the scan itself |
| HTTP | 14 | 0.6% | NSE version detection requests to port 80 |
| ICMP | 3 | 0.1% | Host discovery pings |
| SSH | 1 | <0.1% | Banner capture from port 22 |

**99% pure TCP with almost no application data = port scan fingerprint.** Legitimate traffic produces rich application layer content. A SOC analyst who sees this distribution knows immediately what they're looking at.

### TCP Flag Distribution

| Flags | Count | Meaning |
|---|---|---|
| `SYN` | 1,105 | Nmap probing ports |
| `ACK + RST` | 1,075 | Closed port responses |
| `ACK + SYN` | 18 | Open port confirmations |
| `ACK` | 56 | Connection maintenance during version detection |
| `ACK + PSH` | 31 | Data transmission (HTTP requests, SSH banner) |
| `ACK + FIN` | 21 | Clean connection closures |
| `RST` | 19 | Abrupt terminations (tcpwrapped behaviour) |

### The Defender's View in a SIEM

```
Source IP:         192.168.64.3
Destination:       45.33.32.156
Packets/second:    Hundreds
Duration:          29 seconds
Pattern:           Sequential port targeting, single source
Protocol:          TCP SYN packets predominantly
Response pattern:  Mix of RST (closed) and SYN-ACK (open)
```

Suricata IDS would fire immediately:
```
ET SCAN Nmap Scripting Engine User-Agent Detected
ET SCAN Potential SSH Scan OUTBOUND
ET SCAN Nmap -sV scan detected
GPL SCAN nmap TCP
```

---

## Detection Engineering

### Sigma Rule

```yaml
title: Nmap Port Scan Detected
id: a8f9b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c
status: production
description: Detects rapid sequential TCP SYN packets
             consistent with Nmap port scanning activity
references:
  - https://attack.mitre.org/techniques/T1046/
author: Granger Baranda
date: 2026-04-22
tags:
  - attack.reconnaissance
  - attack.t1046
logsource:
  category: network
  product: suricata
detection:
  selection:
    alert.signature|contains: 'ET SCAN'
    alert.signature|contains: 'nmap'
  timeframe: 60s
  condition: selection | count() > 10
falsepositives:
  - Authorised vulnerability scanning
  - Penetration testing with change control
  - Internal asset discovery tools
level: medium
```

### Splunk SPL

```spl
index=suricata sourcetype=suricata
| where signature like "%ET SCAN%"
| bin _time span=60s
| stats count by _time, src_ip, dest_ip
| where count > 100
| eval severity=case(
    count > 1000, "HIGH",
    count > 500,  "MEDIUM",
    true(),       "LOW"
  )
| table _time, src_ip, dest_ip, count, severity
| sort - count
```

### Microsoft Sentinel KQL

```kql
CommonSecurityLog
| where DeviceVendor == "Suricata"
| where Activity has "SCAN"
| summarize
    ScanCount     = count(),
    DistinctPorts = dcount(DestinationPort),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
    by SourceIP, DestinationIP, bin(TimeGenerated, 1m)
| where DistinctPorts > 50
| extend Duration = datetime_diff('second', LastSeen, FirstSeen)
| project TimeGenerated, SourceIP, DestinationIP,
          ScanCount, DistinctPorts, Duration
| order by ScanCount desc
```

---

## SOC Analyst Response Workflow

When a port scan alert fires:

```
Step 1 — CONFIRM
         Is this a real scan or a false positive?
         Check authorised scanner schedule (Nessus, Qualys, Rapid7).
         Check change control system.

Step 2 — IDENTIFY
         Internal or external source IP?
         Threat intel lookup: VirusTotal, AbuseIPDB, OTX, Shodan.
         Known scanner? Known malicious actor? Unknown?

Step 3 — ASSESS
         What ports did they find open?
         Cross-reference against asset register.
         Should those ports be open?

Step 4 — DETERMINE INTENT
         Single scan = likely background noise.
         Multiple scans over time = escalating reconnaissance.
         Scan followed by exploitation attempts = active attack.

Step 5 — ACT PROPORTIONATELY
         Background noise → document, monitor, no action.
         Persistent unknown → block IP at perimeter firewall.
         Active attack → full incident response (PICERL).
```

---

## Nmap Command Reference

```bash
# Basic scan — top 1000 ports
nmap [target]

# Service version detection
nmap -sV [target]

# OS fingerprinting (requires root)
sudo nmap -O [target]

# Aggressive — version + OS + scripts + traceroute
sudo nmap -A [target]

# Specific ports only
nmap -p 22,80,443 [target]

# All 65535 ports
nmap -p- [target]

# Fast scan — top 100 ports
nmap -F [target]

# Save output
nmap -sV [target] -oN output.txt

# Verbose
nmap -v -sV [target]
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Reconnaissance · Discovery |
| Technique | T1046 — Network Service Discovery |
| Tool | Nmap 7.99 |
| Sub-technique | None (base technique) |
| Observed | TCP SYN scan · service version detection · OS fingerprinting · NSE script execution |
| Detection | Suricata ET SCAN rules · SIEM high-volume SYN correlation · HTTP path signatures |

**CYBERUK 2026 context:** Richard Horne (NCSC CEO) confirmed that AI is compressing the window between vulnerability discovery and exploitation. An attacker who runs this scan and extracts `OpenSSH 6.6.1p1` can now feed that version number to an AI tool and receive a curated list of CVEs, exploitation techniques, and proof-of-concept code — in seconds. Reconnaissance detection is more time-critical than ever.

---

## Security+ Connection

| Objective | Coverage |
|---|---|
| SY0-701 4.1 | Nmap explicitly listed as an assessment tool |
| SY0-701 2.2 | Port scanning as a threat vector · version disclosure risk |
| SY0-701 3.1 | Attack surface management · network monitoring and detection |
| SY0-701 4.4 | SSH banner suppression · HTTP version header removal · firewall rules |

---

## Lab Connections

| Lab | Connection |
|---|---|
| Lab 002 | TCP handshake (SYN/SYN-ACK/ACK) now visible at scale — thousands of simultaneous handshakes |
| Lab 005 | NSE HTTP requests visible in Wireshark — same HTTP structure, now automated by reconnaissance tool |
| Lab 006 | Every port found on scanme.nmap.org (22, 80, 113, 31337) studied in detail in Lab 006 |
| Lab 007 | Filtered ports (113, 427) demonstrate the firewall architecture from Lab 007 in live action |

---

## Key Findings

1. **Version disclosure is the real risk.** Knowing port 22 is open gives an attacker a target. Knowing it runs `OpenSSH 6.6.1p1` gives them a specific, searchable attack path.

2. **NSE scripts probe automatically.** A standard `-sV` scan checked for VMware vCenter (CVSS 9.8 RCE), router admin panels, and CMS platforms without being asked.

3. **The wire pattern is unmistakable.** 99% pure TCP, hundreds of SYN packets per second from one source — any competent IDS fires immediately.

4. **ARM64 defeats OS fingerprinting.** Unusual hardware reduced reconnaissance accuracy. Non-standard infrastructure is a legitimate defensive consideration.

5. **Legal and ethical context is everything.** The same command is reconnaissance or assessment depending entirely on whether authorisation exists.

---

## Files in This Lab

```
lab-setup/nmap-labs/lab-008/
├── README.md                    ← This file
└── lab-008-nmap-scan.pcap       ← Wireshark capture (197KB, 2,328 packets)
```

---

## Commit Message

```
Add Lab-008: Nmap port scanning and service version detection
Scanned localhost and scanme.nmap.org, captured live scan
traffic in Wireshark, full MITRE T1046 mapping,
Sigma/SPL/KQL detection rules — 22 April 2026
```

---

*Lab 008 complete — 22 April 2026*
*Granger Baranda | MSc Information Security — Royal Holloway, University of London*
*[github.com/Granger0007](https://github.com/Granger0007) | [Granger Security (YouTube)](https://youtube.com/@Granger-Security)*
