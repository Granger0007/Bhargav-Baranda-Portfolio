# Lab 009 — I Read the Mind of a Port Scanner
## A Complete Forensic Analysis of Network Packet Capture Data

**Date:** 23 April 2026
**Author:** Bhargav (Granger) Baranda
**Environment:** Kali Linux ARM64 · UTM · MacBook Pro Apple Silicon
**Tools:** tshark 4.6.4 · Wireshark 4.6.4
**MITRE ATT&CK:** T1040 — Network Sniffing · T1557 — Adversary in the Middle · T1071 — Application Layer Protocol
**Security+ Objectives:** SY0-701 4.1 · 2.2 · 4.3
**Source File:** `lab-008-nmap-scan.pcap` (197KB · 2,328 packets)
**Status:** ✅ Complete

---

## Executive Summary

This lab conducted a complete forensic analysis of a real network packet capture file generated during Lab 008's Nmap port scan of `scanme.nmap.org`. Using tshark — the command-line packet analysis engine — and Wireshark's graphical interface, the capture was systematically interrogated to extract every piece of intelligence it contained.

The analysis revealed:
- The complete attack methodology of the scan reconstructed from TCP flags alone
- The exact SSH software version running on the target extracted directly from a single packet
- Every HTTP request Nmap's scripts made automatically — including a probe for VMware vCenter (CVE-2021-21985, CVSS 9.8)
- The full HTML content of the target web server reconstructed from raw packets via TCP stream following

**Core finding:** A single 197KB packet capture file contains enough intelligence to reconstruct an entire attack sequence — who scanned, what they found, what they probed, and what the target disclosed. This is the forensic capability SOC analysts use to investigate real incidents.

---

## Tools and Methodology

### Wireshark vs tshark

Both tools share the same packet analysis engine — same dissectors, same protocol parsers, same filtering syntax. The difference is the interface.

| Tool | Interface | Best for |
|---|---|---|
| **Wireshark** | Graphical | Exploration, visualisation, following individual conversations |
| **tshark** | Command-line | Automation, scripting, large file processing, field extraction |

In a real SOC environment, tshark processes capture files automatically — extracting all HTTP hosts, all DNS queries, all unique IPs — without a human clicking through thousands of packets. This lab uses both: tshark for rapid extraction and statistical analysis, Wireshark for following specific conversations and visual confirmation.

### Source File

```
File:     lab-008-nmap-scan.pcap
Size:     197KB
Created:  22 April 2026 at 21:35
Content:  Nmap -sV scan of scanme.nmap.org (45.33.32.156)
Capture:  eth0, capture filter: host scanme.nmap.org
Duration: ~30 seconds
```

---

## Part 1 — Initial Scale Assessment

### Packet Count

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap | wc
```

**Result:**
```
2328    36239    247155
```

| Metric | Value |
|---|---|
| Total packets | 2,328 |
| File size | 197KB |
| Average packet size | ~85 bytes |
| Scan duration | ~29 seconds |
| Packets per second | ~80 |

A real incident investigation may involve millions of packets across hours of traffic. The systematic extraction methodology applied here scales to any file size.

### IP Address Extraction

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap \
  -T fields -e ip.src -e ip.dst | sort -u
```

**Result:**
```
192.168.64.3    45.33.32.156
45.33.32.156    192.168.64.3
```

Exactly two IPs. The capture filter worked perfectly — only traffic between the Kali machine and `scanme.nmap.org`. In a real investigation, unexpected third-party IPs would immediately raise questions about the scope of an incident.

```
192.168.64.3   — Kali Linux VM (the scanner — our machine)
45.33.32.156   — scanme.nmap.org (the target)
```

---

## Part 2 — Protocol Distribution Analysis

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap \
  -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20
```

**Result:**
```
2306  eth:ethertype:ip:tcp
   7  eth:ethertype:ip:tcp:http:data-text-lines
   7  eth:ethertype:ip:tcp:http
   3  eth:ethertype:ip:tcp:icmp
   2  eth:ethertype:ip:tcp:http:data
   2  eth:ethertype:ip:tcp:data
   1  eth:ethertype:ip:tcp:ssh
```

### Analysis

| Protocol | Packets | % | Meaning |
|---|---|---|---|
| Pure TCP | 2,306 | 99.1% | SYN probes + RST/SYN-ACK responses — the scan itself |
| HTTP | 14 | 0.6% | NSE version detection requests to port 80 |
| ICMP | 3 | 0.1% | Host discovery pings |
| SSH | 1 | <0.1% | Banner capture from port 22 |

**99.1% pure TCP = the protocol fingerprint of a port scan.** Legitimate traffic — web browsing, email, file transfer — produces rich application layer content. A port scan produces almost none. This ratio is a reliable detection signature:

```
IF single source IP generates >500 TCP packets
   to single destination within 60 seconds
   AND application layer content < 1% of packets
THEN alert: probable port scan — T1046
Severity: Medium-High
```

---

## Part 3 — TCP Flag Analysis

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap \
  -T fields -e tcp.flags.str | sort | uniq -c | sort -rn
```

**Result:**
```
1105  ·······S··   SYN only
1075  ·····A·R··   ACK + RST
  56  ·····A····   ACK only
  31  ·····A·P··   ACK + PSH
  21  ·····A···F   ACK + FIN
  19  ·········R   RST only
  18  ·····A··S·   ACK + SYN (SYN-ACK)
   3  (other)
```

### Flag-by-Flag Breakdown

| Flags | Count | Meaning |
|---|---|---|
| `SYN` | 1,105 | Nmap probing 1,105 ports — the scan phase |
| `ACK+RST` | 1,075 | Server rejecting closed ports — "no service here" |
| `SYN-ACK` | 18 | Server accepting open ports — "come in" |
| `ACK` | 56 | Connection maintenance during version detection |
| `ACK+PSH` | 31 | Data transmitted — HTTP requests, SSH banner grab |
| `ACK+FIN` | 21 | Clean connection closures after version detection |
| `RST` | 19 | Abrupt closures — tcpwrapped behaviour on port 31337 |

### The Complete Attack Timeline — Reconstructed From Flags Alone

```
Phase 1 — Host Discovery
3 ICMP packets confirming target is alive

Phase 2 — Port Scanning
1105 SYN probes sent sequentially
1075 ACK+RST received (closed ports)
  18 SYN-ACK received (open ports found: 22, 80, 9929, 31337)

Phase 3 — Service Version Detection
  56 ACK maintaining established connections
  31 ACK+PSH transmitting probe data
  21 ACK+FIN clean closures after probing
  19 RST abrupt closures (tcpwrapped on port 31337)

Phase 4 — Application Protocol Analysis
  14 HTTP packets (NSE GET/POST requests + responses)
   1 SSH packet (banner: SSH-2.0-OpenSSH_6.6.1p1)
```

**A trained analyst reading only this flag distribution — without examining any packet content — can reconstruct the complete methodology of the scan.**

---

## Part 4 — HTTP Request Extraction

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap \
  -Y "http.request" \
  -T fields \
  -e http.request.method \
  -e http.host \
  -e http.request.uri
```

**Result:**
```
GET             /
POST    scanme.nmap.org   /sdk
GET     scanme.nmap.org   /nmaplowercheck1776889667
GET             /
GET     scanme.nmap.org   /HNAP1
GET     scanme.nmap.org   /evox/about
GET             /
GET     scanme.nmap.org   /
```

### Request-by-Request Analysis

**`GET /` (× 3)**
Nmap's baseline HTTP probe. Establishes web server functionality, captures response headers including `Server: Apache/2.4.7`. These requests produced the Apache version disclosure from Lab 008.

**`POST /sdk`**
The most significant request in the entire capture.

`/sdk` is the VMware vSphere Web Services SDK endpoint — the API for VMware vCenter Server, which controls virtual machines in corporate, healthcare, government, and financial environments. Three CVSS 9.8 CVEs target this exact path:

| CVE | Score | Impact |
|---|---|---|
| CVE-2021-21985 | 9.8 Critical | Unauthenticated RCE via Virtual SAN Health Check plugin |
| CVE-2021-21972 | 9.8 Critical | Unauthenticated arbitrary file upload → web shell |
| CVE-2021-22005 | 9.8 Critical | Unauthenticated arbitrary file write |

Nmap probed this endpoint automatically. The operator did not request it. Every `-sV` scan against any web server simultaneously checks for one of the most critical enterprise vulnerabilities in recent history.

**`GET /nmaplowercheck1776889667`**
Deliberate 404 fingerprinting. The random number guarantees this path cannot exist. Different web servers return 404 errors in subtly different ways — Apache, Nginx, IIS, Tomcat all behave differently. This response helps Nmap distinguish server types when the `Server:` header alone is insufficient. The number is generated fresh per session — WAFs cannot block this probe by path matching.

**`GET /HNAP1`**
Home Network Administration Protocol endpoint — used by D-Link, Linksys, Netgear, and Belkin routers. Nmap checked whether this internet-facing server was actually a router exposing its admin interface. HNAP vulnerabilities have allowed unauthenticated RCE across multiple device families.

**`GET /evox/about`**
EvOX CMS fingerprinting probe. Checks for a CMS with known vulnerabilities by requesting a path that exists only in EvOX installations.

### The SOC Detection Signature

```
/sdk + /HNAP1 + /nmaplowercheck[random] + /evox/about
= confirmed Nmap -sV scan
= IDS should fire immediately
```

No legitimate user ever requests `/HNAP1` on a corporate web server. No legitimate application POSTs to `/sdk` unless it is a VMware management interface. These are unmistakable scanner fingerprints.

---

## Part 5 — SSH Banner Extraction

```bash
tshark -r ~/Desktop/lab-008-nmap-scan.pcap \
  -Y "ssh" \
  -T fields \
  -e ssh.protocol
```

**Result:**
```
SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
```

This single line — extracted from one packet in 2,328 — is what Nmap reported as the SSH version in Lab 008. Not a heuristic, not a guess. RFC 4253 requires SSH servers to transmit a version identification string verbatim at the start of every connection.

**Decoded:**

| Component | Value | Significance |
|---|---|---|
| `SSH-2.0` | Protocol version 2 | Version 1 deprecated — cryptographically broken |
| `OpenSSH_6.6.1p1` | Software and version | Released March 2014. 12 years old. Multiple CVEs. |
| `Ubuntu-2ubuntu2.13` | Packaging suffix | Reveals Ubuntu LTS release and patch level |

The Ubuntu suffix alone allows cross-referencing the kernel version, libc version, and overall patch currency. What appears to be a simple banner contains enough to profile the complete OS stack.

**Remediation:** Configure SSH to return only `SSH-2.0` — the protocol version required by the standard — and nothing else. SSH banner suppression eliminates trivial version disclosure.

---

## Part 6 — Wireshark Visual Analysis

### Display Filter 1 — SYN Packets Only (The Scan)

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Result: 1,105 packets (47.5% of capture)**

Visual confirmation of tshark analysis. 1,105 rows — all from `192.168.64.3` to `45.33.32.156`, all with different destination port numbers, all within a 30-second window.

### Display Filter 2 — Open Ports Only (SYN-ACK)

```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

**Result: 18 packets (0.8% of capture)**

Ports 80, 22, 9929, and 31337 repeat across 18 rows — each representing a connection attempt during version detection. The ratio of 1,105 probes to 18 confirmations visually demonstrates that 98.4% of ports were closed.

### TCP Stream Following — HTTP Conversation Reconstructed

Following the first HTTP conversation revealed the complete exchange:

**Request (client — red):**
```http
GET / HTTP/1.0
```

**Response (server — blue):**
```http
HTTP/1.1 200 OK
Date: Wed, 22 Apr 2026 20:27:47 GMT
Server: Apache/2.4.7 (Ubuntu)
Accept-Ranges: bytes
Vary: Accept-Encoding
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<head>
<title>Go ahead and ScanMe!</title>
...
```

**Total conversation: 7,168 bytes · 1 client packet · 5 server packets · 1 turn.**

The title "Go ahead and ScanMe!" is the Nmap team's explicit authorisation built into the page content itself.

TCP stream reconstruction demonstrates Wireshark's most powerful forensic capability — reassembling raw packet fragments into a readable conversation. In real investigations, this technique reads commands an attacker typed after gaining shell access, data exfiltrated over FTP, or credentials submitted over HTTP.

### Conversation Statistics

**Statistics → Conversations → TCP: 1,107 conversations total**

| Port | Packets | Bytes | Type |
|---|---|---|---|
| 31337 | 10 | 665 | tcpwrapped — multiple reconnects |
| 9929 | 8 | 640 | nping-echo |
| 22 | 3 | 170 | SSH banner grab |
| 80 | 3 | 170 | HTTP |
| Any (closed) | 2 | 112 | SYN + RST — identical across all closed ports |

The contrast is visually striking: closed ports = identical 2-packet, 112-byte rows; open ports = larger conversations with full data exchange.

1,107 conversations from 1,000 ports — the extra 107 from Nmap reconnecting to open ports during version detection.

---

## Part 7 — Complete Intelligence Extracted

Everything recovered from this 197KB file:

```
INFRASTRUCTURE:
  Target IP:          45.33.32.156
  Operating System:   Ubuntu Linux
  Web Server:         Apache 2.4.7 (2013)
  SSH Software:       OpenSSH 6.6.1p1 (2014)
  SSH Protocol:       Version 2.0

NETWORK:
  Open Ports:         22, 80, 9929, 31337
  Closed Ports:       996+ (confirmed RST)
  Filtered Ports:     113, 427 (firewall dropping packets)
  Network Distance:   Low latency (US-based server)

VULNERABILITY SURFACE:
  VMware vCenter:     Probed — /sdk endpoint checked
  Router Admin:       Probed — /HNAP1 checked
  EvOX CMS:          Probed — /evox/about checked
  SSH CVE exposure:   HIGH — 12-year-old version
  Apache CVE exposure: HIGH — 13-year-old version

SCAN METHODOLOGY:
  Tool:               Nmap 7.99
  Type:               SYN scan + service version detection
  Duration:           ~29 seconds
  Probes sent:        1,105 SYN packets
  Open ports found:   4 (via SYN-ACK)
  HTTP probes:        8 automatic NSE requests
```

---

## Part 8 — MITRE ATT&CK Mapping

### T1040 — Network Sniffing

Capturing this pcap file is itself T1040. An attacker positioned on the same network segment — through ARP poisoning, a compromised switch, or physical access — would capture identical traffic. The SSH banner, HTTP responses, and application data extracted in this lab are exactly what a network sniffer yields.

### T1557 — Adversary in the Middle

The TCP stream following capability shows what a MitM attacker would read. An attacker intercepting the connection to port 80 would see the exact HTML reconstructed in the Follow TCP Stream window — 7,168 bytes of web content and server intelligence. For unencrypted protocols, being in the middle means reading everything.

### T1071 — Application Layer Protocol

HTTP requests to `/sdk`, `/HNAP1`, and `/evox/about` demonstrate T1071 — using legitimate application layer protocols to conduct reconnaissance. These probes are indistinguishable from normal web traffic at the network level. Only the specific paths and their combination reveal intent. This is the technique sophisticated attackers use to hide reconnaissance and C2 inside legitimate protocol traffic.

---

## Part 9 — Detection Engineering

### Sigma Rule

```yaml
title: Nmap NSE HTTP Fingerprinting Detected
id: c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f
status: production
description: Detects Nmap NSE script scanning via characteristic
             HTTP request paths generated during -sV service detection
references:
  - https://attack.mitre.org/techniques/T1046/
  - https://attack.mitre.org/techniques/T1071/
author: Granger Baranda
date: 2026-04-23
tags:
  - attack.reconnaissance
  - attack.t1046
  - attack.t1071.001
logsource:
  category: webserver
  product: apache
detection:
  selection_paths:
    http.uri|contains:
      - '/sdk'
      - '/HNAP1'
      - '/evox/about'
      - '/nmaplowercheck'
  timeframe: 60s
  condition: 2 of selection_paths
falsepositives:
  - Authorised vulnerability scanning with change control
  - Internal security team assessments
level: high
```

### Splunk SPL

```spl
index=web_logs sourcetype=access_combined
| where uri="/sdk"
  OR uri="/HNAP1"
  OR uri="/evox/about"
  OR uri like "/nmaplowercheck%"
| bin _time span=60s
| stats
    count as total_probes
    dc(uri) as unique_probe_paths
    values(uri) as paths_hit
    by _time src_ip dest_host
| where unique_probe_paths >= 2
| eval severity=case(
    unique_probe_paths >= 4, "CRITICAL — Full NSE scan",
    unique_probe_paths >= 3, "HIGH — Partial NSE scan",
    true(), "MEDIUM — Possible NSE scan"
  )
| table _time src_ip dest_host total_probes unique_probe_paths paths_hit severity
| sort - unique_probe_paths
```

### Microsoft Sentinel KQL

```kql
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where TimeGenerated > ago(1h)
| where requestUri_s has_any (
    "/sdk",
    "/HNAP1",
    "/evox/about",
    "/nmaplowercheck"
  )
| summarize
    ProbeCount  = count(),
    UniquePaths = dcount(requestUri_s),
    PathsHit    = make_set(requestUri_s),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated)
    by clientIP_s, bin(TimeGenerated, 1m)
| where UniquePaths >= 2
| extend
    ScanDuration = datetime_diff('second', LastSeen, FirstSeen),
    Severity     = iff(UniquePaths >= 3, "High", "Medium")
| project TimeGenerated, clientIP_s,
          ProbeCount, UniquePaths, PathsHit,
          ScanDuration, Severity
| order by UniquePaths desc
```

---

## Part 10 — The SOC Analyst Forensic Workflow

```
Step 1 — Establish Scale
  tshark file.pcap | wc
  How many packets? What time period? What is the scope?

Step 2 — Identify Participants
  tshark -T fields -e ip.src -e ip.dst | sort -u
  Who was talking to whom? Any unexpected third parties?

Step 3 — Protocol Distribution
  tshark -T fields -e frame.protocols | sort | uniq -c
  What traffic types occurred? Does the distribution match normal?

Step 4 — TCP Flag Analysis
  tshark -T fields -e tcp.flags.str | sort | uniq -c
  Scanning? Data transfer? Command and control?

Step 5 — Application Layer Extraction
  tshark -Y "http.request" -T fields -e http.*
  tshark -Y "ssh" -T fields -e ssh.protocol
  What did the applications do? What data was exchanged?

Step 6 — Visual Investigation
  Open in Wireshark
  Apply targeted display filters
  Follow TCP streams for full conversation content
  Review conversation statistics for scope

Step 7 — Document and Produce
  Write the incident report
  Build detection rules from findings
  Commit to GitHub
```

---

## tshark Command Reference

```bash
# Count packets
tshark -r file.pcap | wc

# Extract unique IPs
tshark -r file.pcap -T fields -e ip.src -e ip.dst | sort -u

# Protocol distribution
tshark -r file.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn

# TCP flag analysis
tshark -r file.pcap -T fields -e tcp.flags.str | sort | uniq -c | sort -rn

# Extract HTTP requests
tshark -r file.pcap -Y "http.request" -T fields \
  -e http.request.method -e http.host -e http.request.uri

# Extract SSH banner
tshark -r file.pcap -Y "ssh" -T fields -e ssh.protocol

# Filter by IP
tshark -r file.pcap -Y "ip.addr == 45.33.32.156"

# Export specific conversation
tshark -r file.pcap -Y "tcp.stream eq 0" -w conversation.pcap
```

---

## Security+ Connection

| Objective | Coverage |
|---|---|
| SY0-701 4.1 | tshark and Wireshark as forensic assessment tools |
| SY0-701 2.2 | SSH version disclosure · VMware vCenter as high-value target · HTTP as reconnaissance vector |
| SY0-701 4.3 | Pcap analysis workflow · TCP stream following · Conversation statistics · Evidence extraction |

---

## Lab Connections

| Lab | Connection |
|---|---|
| Lab 002 | TCP three-way handshake now visible at scale — 18 SYN-ACK responses vs one in Lab 002 |
| Lab 004 | `/HNAP1` probe connects to DNS lab — infrastructure exposed via both DNS and HTTP |
| Lab 005 | TCP stream following reconstructs same HTTP structure analysed in Lab 005 |
| Lab 006 | Every port confirmed in conversation stats (22, 80, 9929, 31337) studied in Lab 006 |
| Lab 007 | Filtered ports (113, 427) visible as *absence* of traffic — firewall architecture in action |
| Lab 008 | This lab is the forensic twin of Lab 008. Lab 008 = attacker's view. Lab 009 = defender's view. |

---

## Key Findings

1. **Flag analysis alone reconstructs the full attack timeline.** No packet content needed — just the TCP flag distribution tells the complete story.

2. **One packet contained the full SSH intelligence.** The server broadcasted `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` in its first transmission. This is a protocol requirement — and a security liability.

3. **NSE probed VMware vCenter automatically.** A standard `-sV` scan POST'd to `/sdk` without operator instruction. Defenders need to watch for this path in web server logs.

4. **99.1% pure TCP is the scan fingerprint.** This ratio never appears in legitimate traffic. It is immediately recognisable.

5. **TCP stream following reads the full conversation.** 7,168 bytes of HTML reconstructed from 6 raw packets. This is how analysts read data exfiltrated over unencrypted protocols.

---

## Files in This Lab

```
lab-setup/wireshark-labs/lab-009/
├── README.md                    ← This file
└── lab-008-nmap-scan.pcap       ← Source capture (197KB, 2,328 packets)
```

---

## Commit Message

```
Add Lab-009: Forensic pcap analysis with tshark and Wireshark
2328 packets, TCP flag distribution, Nmap NSE HTTP fingerprints
including VMware vCenter probe, SSH banner extraction,
TCP stream following — T1040 T1557 T1071 — 23 April 2026
```

---

*Lab 009 complete — 23 April 2026*
*Granger Baranda | MSc Information Security — Royal Holloway, University of London*
*[github.com/Granger0007](https://github.com/Granger0007) | [Granger Security (YouTube)](https://youtube.com/@Granger-Security)*
