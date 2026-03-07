# Lab 005 — I Watched a Password Travel Across the Internet

**Category:** Network Traffic Analysis  
**Platform:** Kali Linux ARM64 · Wireshark  
**Difficulty:** Foundational  
**MITRE ATT&CK:** T1040, T1557.002, T1595.001  

---

## What This Lab Demonstrates

Three experiments run side by side:

1. **HTTP traffic capture** — plain text request and response, server version disclosure
2. **Credential interception** — login form submitted over HTTP, credentials read from packet capture with zero effort
3. **HTTPS traffic capture** — TLS handshake, encrypted application data, certificate inspection, SNI leakage

The same data. The same network. Two completely different exposure levels.

---

## Lab Environment

| Component | Detail |
|---|---|
| OS | Kali Linux ARM64 |
| Tool | Wireshark |
| Target (HTTP) | httpforever.com — plain HTTP test site |
| Target (HTTPS) | google.com |
| Interface | eth0 (live network capture) |

---

## Experiment 1 — HTTP Traffic Analysis

### What I Did

Visited a plain HTTP site using curl, captured the full exchange in Wireshark.

**Total packets captured:** 14

### Packet Breakdown

| Packet | Direction | Content |
|:------:|-----------|---------|
| 1–3 | Both | TCP three-way handshake — SYN / SYN-ACK / ACK |
| 4 | Client → Server | HTTP GET request |
| 8 | Server → Client | HTTP 200 OK response |

### Packet 4 — The Request (Fully Readable)

```
GET / HTTP/1.1
Host: httpforever.com
User-Agent: curl/8.18.0
Accept: */*
```

Every field readable. No decryption. No special tools. Just looking.

### Packet 8 — The Response (Fully Readable)

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html
Content-Length: 5124
```

**Security finding:** The `Server` header discloses software name and exact version. Any attacker who knows vulnerabilities in nginx/1.18.0 on Ubuntu now has a confirmed target. Secure servers suppress this header entirely.

---

## Experiment 2 — Credential Interception

### What I Did

Submitted a login form over HTTP using curl with a POST request. Captured the packet in Wireshark and read the form data.

### What Wireshark Showed

```
Form item: "username" = "granger"
Form item: "password" = "test123"
```

Both fields. Plain text. Highlighted in Wireshark. Requiring zero effort to read.

**This is not a demonstration of a sophisticated attack.** This is the default behaviour of HTTP. Anyone on the same network running Wireshark would see the same output.

### Server Response

```
HTTP/1.1 405 Method Not Allowed
```

The server rejected the login because the test site doesn't process logins — but the credentials had already been transmitted and captured before the rejection arrived. The 405 came too late to matter.

### Why This Is Critical

| Scenario | Risk |
|---|---|
| Home WiFi | Router admin or compromised device could capture traffic |
| Office network | Internal threat actor or misconfigured tap |
| Public WiFi (coffee shop, hotel, airport) | Anyone on the same network. Wireshark is free. Takes 10 minutes to learn |

---

## Experiment 3 — HTTPS Traffic Analysis

### What I Did

Captured a connection to google.com over HTTPS (port 443). Compared packet content to the HTTP capture.

**Total packets captured:** 31

### The TLS Handshake

| Message | Direction | Meaning |
|---------|-----------|---------|
| Client Hello | Client → Server | "Here are the encryption methods I support. My name is this machine. I want to talk to google.com." |
| Server Hello | Server → Client | "Here is my digital certificate proving I am Google. We will use this encryption method." |
| Certificate | Server → Client | Google's identity document — subject, validity dates, issuing authority |
| Application Data | Both | Encrypted. Unreadable. Content completely hidden. |

### Google's Certificate

```
Subject:     *.google.com
Valid from:  February 2, 2026
Valid until: April 27, 2026
Issued by:   Google Trust Services
```

The certificate is Google's proof of identity. It is issued by a trusted authority (Google Trust Services), valid for the domain, and in date. The browser padlock confirms all three checks passed.

### What Wireshark Could Read vs HTTP

| Data | HTTP | HTTPS |
|---|:---:|:---:|
| Destination (where you're going) | ✅ Visible | ✅ Visible (SNI) |
| HTTP method (GET, POST) | ✅ Visible | ❌ Encrypted |
| URL path | ✅ Visible | ❌ Encrypted |
| Request headers | ✅ Visible | ❌ Encrypted |
| Username / password | ✅ Visible | ❌ Encrypted |
| Response content | ✅ Visible | ❌ Encrypted |
| Server software version | ✅ Visible | ❌ Encrypted |

**The one thing HTTPS cannot hide:** The destination. The Client Hello message contains the SNI (Server Name Indication) field — `google.com` — visible to anyone monitoring the network. Encryption hides what you are doing. It does not hide where you are going.

---

## Experiment 4 — TCP Retransmission Pattern

### What Happened

My first HTTP capture attempt failed. The target server never responded. Wireshark showed my computer sending repeated SYN packets over 35 seconds — the same connection request, retried automatically.

```
[SYN]          → server
[retransmission] → server (no response)
[retransmission] → server (no response)
[retransmission] → server (no response)
... (continues for 35 seconds)
```

### Security Relevance

This pattern is a detection signal:

| Pattern | Legitimate behaviour | Attacker behaviour |
|---------|---------------------|-------------------|
| TCP retransmissions | A few retries, then gives up | Hundreds of SYNs across many ports — port scan |
| Failed connection + retry | Occasional, to known hosts | Systematic, to unknown or multiple hosts |
| 35 seconds of retransmissions to one host | Unusual | Could indicate persistence or automated tool |

A SOC analyst who sees retransmission storms across multiple destinations in their SIEM is looking at a scanner. The shape of the traffic reveals intent before any content is read.

---

## HTTP Status Codes as Security Evidence

| Code | Meaning | Security Relevance |
|:----:|---------|-------------------|
| 200 | Success | Normal — baseline for comparison |
| 301 | Permanent redirect | Legitimate — HTTP → HTTPS upgrade is typically a 301 |
| 404 | Not found | Hundreds of sequential 404s = directory enumeration |
| 405 | Method not allowed | Login attempt rejected — but credentials already transmitted |
| 500 | Server error | Flood of 500s can indicate exploitation attempt or fuzzing |

Status code patterns in logs are detection opportunities. A single 405 is noise. Thousands of 404s in alphabetical sequence is a web scanner. A sudden spike in 500s after normal baseline is a potential attack.

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed |
|-----------|:--:|---------|
| Network Sniffing | T1040 | Wireshark capture of credentials on HTTP |
| Adversary-in-the-Middle — Network Sniffing | T1557.002 | Plain text credential exposure on HTTP POST |
| Active Scanning — Scanning IP Blocks | T1595.001 | TCP retransmission pattern consistent with scanning |

---

## Key Takeaways

**HTTP vs HTTPS is not a technicality.** It is the difference between:
- Your password being readable by anyone on your network
- Your password being encrypted and unreadable in transit

**The padlock in your browser means three things:**
1. The connection is encrypted — content is hidden
2. The server's identity has been verified — you're talking to who you think you are
3. The certificate is valid — it has not expired and was issued by a trusted authority

**Encryption cannot hide the destination.** SNI in the TLS Client Hello reveals the hostname. Organisations that require complete destination privacy use VPNs or Tor to mask this.

**TCP retransmissions are a detection signal.** The shape of traffic reveals attacker behaviour independently of content inspection.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Packet capture and analysis |
| curl | HTTP/HTTPS request generation |
| Kali Linux ARM64 | Lab platform |

---

*Lab 005 complete.*  
*HTTP exposes everything. HTTPS encrypts everything except the destination. The padlock is not decoration.*
