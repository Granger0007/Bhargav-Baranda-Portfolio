<div align="center">

# 🔍 Lab-004 — DNS Enumeration: I Interrogated the Internet and It Told Me Everything

**How a few simple commands reveal the hidden architecture behind any website on earth — and why this is one of the most powerful tools in a security analyst's arsenal.**

![Type](https://img.shields.io/badge/Type-Threat_Intelligence_%7C_Reconnaissance-purple?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-dig_%7C_nslookup-1679A7?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1590.002_%7C_T1498.002_%7C_T1071.004-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux_ARM64-557C94?style=flat-square)
![Detection](https://img.shields.io/badge/Detection-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## 📋 Lab Summary

| Field | Details |
|-------|---------|
| **Lab ID** | 004 |
| **Date** | 2026-03-06 |
| **Type** | DNS Enumeration — Threat Intelligence & Reconnaissance |
| **Tool** | `dig` (Domain Information Groper) |
| **Environment** | Kali Linux ARM64 — UTM VM — MacBook Pro Apple Silicon |
| **Targets** | google.com, bbc.co.uk |
| **Session timestamp** | Friday 06 March 2026, 14:23:59 GMT |
| **Analyst** | Bhargav Baranda |

---

## 🎯 Executive Summary

Using the `dig` command-line tool on Kali Linux, full DNS intelligence profiles were extracted for google.com and bbc.co.uk. No hacking. No special access. No credentials. DNS is a public system — and it stores a complete portrait of an organisation's digital infrastructure.

From two domains, the following was extracted without touching a single threat intelligence database:
- CDN providers and server locations
- Email security vendors and routing architecture
- Complete third-party technology stacks
- Compliance posture indicators
- Infrastructure redundancy architecture
- SPF/DKIM email security configuration

**DNS is the first filter in every SOC investigation. It is fast, free, publicly available, and extraordinarily informative.**

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Relevance |
|--------|-----------|--------------|-----------|
| Reconnaissance | T1590 — Gather Victim Network Information | T1590.002 — DNS | DNS enumeration reveals target infrastructure before any attack |
| Impact | T1498 — Network Denial of Service | T1498.002 — Reflection Amplification | DNS ANY query attack — experienced the defensive countermeasure firsthand |
| Command & Control | T1071 — Application Layer Protocol | T1071.004 — DNS | C2 communication tunnelled through DNS queries |

---

## 🌐 What is DNS and Why Does It Matter for Security?

### The World's Biggest Phonebook

Every device on the internet has an IP address. Computers navigate using numbers. Humans navigate using names. DNS is the translation system between them.

```
You type:    google.com
DNS returns: 142.250.151.102
Your browser connects to: 142.250.151.102
You see:     Google's homepage
```

Without DNS, you would need to memorise the IP address of every website you visit.

### Why DNS Matters for Security

DNS doesn't store one piece of information per domain. It stores many different record types — each answering a different question:

| Question | DNS Record | Security Value |
|----------|-----------|----------------|
| Where is this website? | A / AAAA | IP ownership, hosting provider, age |
| Who handles their email? | MX | Email provider, security posture |
| Who controls their DNS? | NS | Bulletproof hosting vs legitimate provider |
| What servers can send their email? | TXT (SPF) | Phishing detection, email forgery identification |
| What technology do they use? | TXT (verification) | Full tech stack from domain verification records |
| What name resolves from this IP? | PTR | Reverse lookup — confirms or contradicts forward DNS |

**For a SOC analyst investigating a suspicious domain — DNS is the first place to look.**

---

## 🔧 Tools Used

### dig — Domain Information Groper

`dig` is available on Linux and Mac. It sends DNS queries and displays the full, unfiltered response — the answer, the record type, the TTL, the responding server, and query duration.

```bash
# Basic syntax
dig [domain] [record type]

# Clean incident response format — no metadata noise
dig [domain] [record type] +nocmd +noall +answer

# Reverse lookup
dig -x [IP address]

# ASN lookup — who owns this IP block?
dig txt [reverse IP].origin.asn.cymru.com
```

### nslookup vs dig

| Tool | Platform | Detail Level | Use Case |
|------|----------|-------------|----------|
| `nslookup` | Windows + Linux | Basic | Quick lookups, Windows environments |
| `dig` | Linux + Mac | Comprehensive | Professional investigation, full response analysis |

---

## 🌍 The DNS Hierarchy — Understanding the Chain of Authority

```
YOU TYPE: google.com
    ↓
ROOT SERVER: "Ask the .com TLD server"
    ↓
.COM TLD SERVER: "Ask Google's nameserver"
    ↓
GOOGLE'S NAMESERVER: "Here's the IP: 142.250.151.102"
    ↓
YOUR BROWSER: connects to 142.250.151.102
    ↓
GOOGLE'S HOMEPAGE: appears on screen
```

| Level | Name | Role |
|-------|------|------|
| 1 | Root Servers | 13 servers — point to the right TLD |
| 2 | TLD Servers | Handle .com, .uk, .org — point to authoritative NS |
| 3 | Authoritative Nameservers | Hold actual records for a specific domain |
| 4 | Your Answer | IP address, mail server, or other record delivered |

**The root nameservers confirmed in this lab session:**
`e.root-servers.net` through `d.root-servers.net` — the authoritative starting point for every DNS lookup on earth.

---

## 📖 DNS Record Types — The Language of the Internet

| Record | Full Name | Answers | Security Use |
|--------|-----------|---------|-------------|
| **A** | Address | IPv4 address for this domain | IP ownership, hosting, load balancing |
| **AAAA** | IPv6 Address | IPv6 address for this domain | Modern infrastructure identification |
| **MX** | Mail Exchange | Which server handles email | Email provider, security outsourcing |
| **NS** | Nameserver | Who controls this domain's DNS | Bulletproof hosting detection |
| **TXT** | Text | SPF, DKIM, verification records | Email security, full tech stack |
| **PTR** | Pointer | Reverse: IP → domain name | Validate forward DNS, spot mismatches |

---

## 🔬 Investigation 1 — google.com

### A Record — How Many Googles Are There?

```bash
dig google.com
```

**Result:** Six IP addresses returned.

```
142.250.151.102
142.250.151.113
142.250.151.139
142.250.151.138
142.250.151.100
142.250.151.101
TTL: 355 seconds (≈ 6 minutes)
```

**Six IPs for one domain = round-robin DNS load balancing.**

Google has thousands of servers globally. DNS returns a different IP each time, distributing visitors automatically. Short TTL (355 seconds) allows rapid traffic redirection if a server fails.

---

### MX Record — Google's Mail Infrastructure

```bash
dig google.com MX +nocmd +noall +answer
```

```
google.com.   MX   10   smtp.google.com.
```

One mail server. Priority 10. Fully in-house. Google handles all its own email — no third-party provider.

---

### NS Record — Google Controls Its Own DNS

```bash
dig google.com NS +nocmd +noall +answer
```

```
ns1.google.com.
ns2.google.com.
ns3.google.com.
ns4.google.com.
TTL: 4502 seconds (≈ 75 minutes)
```

Four nameservers. All Google-owned. Google cannot afford a third-party DNS outage to affect operations. TTL of 75 minutes — nameservers change rarely, so longer TTL is appropriate.

---

### TXT Records — Google's Technology Portrait

```bash
dig google.com TXT +nocmd +noall +answer
```

**13 TXT records returned.** Key findings:

**SPF Record:**
```
"v=spf1 include:_spf.google.com ~all"
```
- Authorised senders defined in `_spf.google.com`
- `~all` = soft fail — unauthorised senders flagged but not rejected

**Technology stack revealed from verification records:**

| Verification Record | Technology Identified |
|--------------------|----------------------|
| Facebook domain verification | Google runs Facebook advertising campaigns |
| Cisco domain verification | Google uses Cisco email security |
| Apple domain verification | Google services integrate with Apple platforms |
| OneTrust verification | GDPR compliance management via OneTrust |
| Microsoft verification | Microsoft 365 or Azure integrations |
| DocuSign verification | Digital contract signing |
| GlobalSign verification | Email certificate signing authority |

**From one DNS query — advertising platforms, security vendors, compliance tools, contract system, and certificate authority. All public. All free.**

---

### Reverse Lookup — The Unexpected Discovery

```bash
dig -x 142.250.151.102
```

**Result:** `st-in-f102.1e100.net.`

Not google.com. A completely different domain.

**What this is:** `1e100` is scientific notation for a googol — 1 followed by 100 zeros, the number Google's name derives from. `1e100.net` is Google's internal infrastructure domain used for server hostnames rather than public-facing services.

**The lesson:** A result that looks suspicious without context can be completely legitimate with context. A SOC analyst seeing `1e100.net` in firewall logs without this knowledge might escalate a false positive.

**Knowledge of legitimate infrastructure is as important as knowledge of malicious infrastructure.**

---

## 🔬 Investigation 2 — bbc.co.uk

### A Record — Four IPs With a Mathematical Secret

```bash
dig bbc.co.uk A +nocmd +noall +answer
```

```
151.101.64.81
151.101.128.81
151.101.192.81
151.101.0.81
TTL: 142 seconds (≈ 2 minutes)
```

Four IPs. Look at the third octet: **64, 128, 192, 0** — exactly 64 apart.

Those numbers match the /26 subnet boundaries from Lab-003. This is not coincidence — this is CDN architecture built on precise IP allocation planning.

**TTL of 142 seconds = extremely aggressive cache expiry.**

The BBC uses a CDN (Content Delivery Network) — thousands of servers globally. When a story breaks and millions of people rush to read it, the CDN redistributes traffic across available servers every two minutes. Ultra-short TTL = near real-time traffic management.

---

### ASN Lookup — Who Actually Owns Those IPs?

```bash
dig txt 151.101.64.81.origin.asn.cymru.com
```

**Result:** `"15557 | 81.64.0.0/14 | FR | ripencc | 2002-01-03"`

Five facts decoded:

| Field | Value | Meaning |
|-------|-------|---------|
| ASN | 15557 | SFR — Société Française du Radiotéléphone, France |
| IP Block | 81.64.0.0/14 | Over 260,000 IPs — massive scale |
| Country | FR | Servers physically in France |
| Registry | RIPE NCC | European IP allocation — UK GDPR relevant |
| Registration date | 2002-01-03 | 23+ years old — significant legitimacy signal |

**The BBC uses Fastly CDN running on SFR's French infrastructure to deliver their website globally.**

Malicious infrastructure is almost never 23 years old.

---

### MX Records — BBC Email Security Outsourced

```bash
dig bbc.co.uk MX +nocmd +noall +answer
```

```
bbc.co.uk.   MX   10   cluster1.eu.messagelabs.com.
bbc.co.uk.   MX   20   cluster1a.eu.messagelabs.com.
```

Two mail servers. Neither BBC-owned. Both **Symantec Messagelabs** — one of the world's largest cybersecurity companies.

- Priority 10 = primary. Priority 20 = automatic failover.
- `.eu.` in server names = European cluster — UK GDPR data residency compliance
- Every email sent to `@bbc.co.uk` passes through Symantec security scanning first

**The BBC handles its own DNS but outsources all email security to Symantec.**

---

### NS Records — Eight Servers, Dual-Domain Redundancy

```bash
dig bbc.co.uk NS +nocmd +noall +answer
```

```
dns1.bbc.co.uk    dns1.bbc.com
ddns0.bbc.co.uk   ddns0.bbc.com
ddns1.bbc.co.uk   ddns1.bbc.com
dns0.bbc.co.uk    dns0.bbc.com
TTL: 1127 seconds (≈ 18 minutes)
```

Three observations:

1. **BBC runs its own DNS** — unlike email, DNS is kept entirely in-house
2. **Every nameserver exists in both .co.uk AND .com** — if the entire .co.uk domain became unreachable, .com nameservers keep everything running. Business continuity engineering built directly into DNS.
3. **Eight servers vs Google's four** — double the redundancy. The BBC's website is critical national infrastructure during elections, disasters, and major events.

---

### TXT Records — The BBC's Complete Technology Stack

```bash
dig bbc.co.uk TXT +nocmd +noall +answer
```

**21 TXT records.** Response so large it automatically switched from UDP to TCP.

**SPF Record decoded:**
```
"v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16
+include:spf.sis.bbc.co.uk
+include:spf.messagelabs.com ~all"
```

| SPF Element | Meaning |
|-------------|---------|
| `ip4:212.58.224.0/19` | BBC-owned range — 8,192 addresses |
| `ip4:132.185.0.0/16` | BBC-owned range — 65,536 addresses |
| `include:spf.messagelabs.com` | Symantec authorised — matches MX records |
| `~all` | Soft fail on unauthorised senders |

**Complete technology stack from all 21 TXT records:**

| Record Type | Technology |
|-------------|-----------|
| apple-domain-verification | Apple services |
| msfpkey | Microsoft 365 |
| docker-verification | Docker containers |
| slack-domain-verification | Internal Slack communication |
| asv= | PCI DSS approved scanning vendor |
| mongodb-site-verification | MongoDB database |
| _globalsign-domain-verification | GlobalSign SSL certificates |
| yahoo-verification-key | Yahoo advertising |
| docusign (×2) | Digital contract signing |
| google-site-verification (×3) | Google Search Console, Analytics |
| dropbox-domain-verification | Dropbox file storage |
| adobe-idp-site-verification | Adobe Creative Cloud |
| atlassian-domain-verification | Jira and Confluence |
| Huddle | Collaboration platform |

**Internal communication, database, containers, design tools, project management, contract management, certificate authority, advertising, compliance scanning — all from one DNS query. No hacking. All public.**

---

## ⚠️ The Discovery That Teaches the Most — The ANY Query That Failed

```bash
dig bbc.co.uk ANY
```

**Result: Timeout.**

This wasn't a failure. **It was a security countermeasure — and the story behind it is one of the most important lessons in this lab.**

### The DNS Amplification Attack

The ANY query used to work perfectly. Then attackers discovered:
- A tiny ANY query (40 bytes) could generate a response thousands of bytes long
- By forging the source address to show a victim's IP, the attacker could direct massive responses to that victim
- Thousands of DNS servers worldwide would simultaneously flood the victim with responses they never requested

**This is DNS reflection amplification — using innocent DNS servers as unwitting weapons.**

MITRE ATT&CK: **T1498.002 — Network Denial of Service: Reflection Amplification**

**The internet's response:** RFC 8482 (2019) formally deprecated the ANY query type. Most modern DNS servers now return minimal responses or timeout.

> "The absence of an expected result is itself intelligence. A security professional who understands why something fails learns as much as one who only studies success."

---

## 🧹 The Clean Incident Response Command

When your manager is standing behind you asking "what does that domain resolve to?" — this is the command:

```bash
dig bbc.co.uk +nocmd +noall +answer
```

**Output:**
```
bbc.co.uk.   293   IN   A   151.101.192.81
bbc.co.uk.   293   IN   A   151.101.0.81
bbc.co.uk.   293   IN   A   151.101.64.81
bbc.co.uk.   293   IN   A   151.101.128.81
```

No headers. No metadata. No version info. Just the answer. Read it in two seconds.

**Extends to every record type:**
```bash
dig domain.com MX  +nocmd +noall +answer
dig domain.com TXT +nocmd +noall +answer
dig domain.com NS  +nocmd +noall +answer
dig -x [IP]        +nocmd +noall +answer
```

---

## 🦠 Legitimate vs Malicious — The Contrast

| Factor | Legitimate (BBC) | Malicious C2 Domain |
|--------|-----------------|---------------------|
| A Records | 4 IPs, CDN distributed | 1 IP, recently allocated |
| TTL | 142 seconds — managed | 60 seconds — hiding, rotating |
| MX Records | Symantec Messagelabs | Empty — no mail infrastructure |
| NS Records | BBC in-house, 8 servers | Anonymous bulletproof hosting |
| TXT/SPF | Rich — 21 records, known vendors | Empty — no vendor relationships |
| Reverse DNS | CDN infrastructure — expected | No PTR record |
| IP Age | Registered 2002 — 23 years | Registered 3 days ago |
| ASN | SFR France — legitimate telco | Known bulletproof hoster |

**Legitimate domains look rich, established, and consistent.**
**Malicious domains look empty, new, and evasive.**

The contrast is the entire skill.

---

## 🔍 The Seven-Step SOC Analyst DNS Workflow

When an alert fires with an unknown domain or IP — this is the complete sequence:

```bash
# Step 1 — What does it resolve to?
dig domain.com +nocmd +noall +answer

# Step 2 — Who handles their email?
dig domain.com MX +nocmd +noall +answer

# Step 3 — What's their security configuration?
dig domain.com TXT +nocmd +noall +answer

# Step 4 — Who controls their DNS?
dig domain.com NS +nocmd +noall +answer

# Step 5 — What does the IP reverse-resolve to?
dig -x [IP] +nocmd +noall +answer

# Step 6 — Who owns that IP block?
dig txt [reverse IP].origin.asn.cymru.com

# Step 7 — Cross-reference threat intelligence
# → VirusTotal, AbuseIPDB, AlienVault OTX
```

**Seven steps. Under two minutes. Enough intelligence to confirm legitimate or escalate to active incident.**

---

## 📊 Intelligence Profiles — Final Summary

### google.com

| Field | Finding |
|-------|---------|
| A Records | 6 IPs — Google-owned, round-robin load balancing |
| TTL | 355 seconds |
| MX | smtp.google.com — fully in-house |
| NS | ns1–ns4.google.com — fully in-house |
| SPF | include:_spf.google.com ~all |
| Reverse DNS | st-in-f102.1e100.net (Google internal) |
| Tech Stack | Cisco, OneTrust, DocuSign, GlobalSign, Facebook, Apple, Microsoft |
| Email | Fully in-house |
| DNS | Fully in-house |

### bbc.co.uk

| Field | Finding |
|-------|---------|
| A Records | 4 IPs — Fastly CDN via SFR France |
| TTL | 142 seconds — rapid failover |
| IP Age | Registered 2002-01-03 (23 years) |
| IP Registry | RIPE NCC — European allocation |
| MX | Symantec Messagelabs EU cluster (priority 10/20) |
| NS | 8 servers — BBC in-house, dual .co.uk/.com |
| SPF | BBC IP ranges + Messagelabs ~all |
| Compliance | PCI DSS scanning vendor present |
| Tech Stack | Docker, MongoDB, Slack, Jira, Atlassian, Adobe, Dropbox, DocuSign, GlobalSign, Google, Microsoft, Apple, Yahoo, Huddle |
| Email | Outsourced to Symantec — UK GDPR EU routing |
| DNS | In-house — BBC-owned |

---

## 🛡️ Detection Rules

### Sigma — DNS Enumeration Reconnaissance

```yaml
title: Suspicious DNS Enumeration — Multiple Record Types
status: experimental
description: >
  Detects rapid DNS queries across multiple record types from a
  single source — indicator of automated reconnaissance.
references:
  - https://attack.mitre.org/techniques/T1590/002/
author: Bhargav Baranda (Granger0007)
date: 2026/03/06
tags:
  - attack.reconnaissance
  - attack.t1590.002
logsource:
  product: zeek
  service: dns
detection:
  selection:
    qtype_name:
      - 'MX'
      - 'NS'
      - 'TXT'
      - 'ANY'
      - 'AXFR'
  timeframe: 60s
  condition: selection | count() by src_ip > 10
falsepositives:
  - Legitimate DNS management tools
  - Security scanners on authorised assessments
level: medium
```

### Splunk SPL — DNS C2 Tunnelling Detection

```spl
| Comment: T1071.004 — DNS tunnelling C2 detection
| Comment: Unusually long DNS queries or high query volume indicate tunnelling
| Comment: Author: Bhargav Baranda | Date: 2026-03-06

index=dns earliest=-1h
| eval query_length=len(query)
| stats
    count AS query_count,
    avg(query_length) AS avg_query_len,
    max(query_length) AS max_query_len,
    dc(query) AS unique_queries
    BY src_ip, answer
| where query_count > 100
    OR avg_query_len > 50
    OR max_query_len > 100
| eval risk=case(
    max_query_len > 100 AND query_count > 200, "HIGH",
    avg_query_len > 50  OR  query_count > 100, "MEDIUM",
    true(), "LOW"
  )
| where risk IN ("HIGH","MEDIUM")
| sort - query_count
| table src_ip, answer, query_count, avg_query_len, max_query_len, unique_queries, risk
```

### Microsoft Sentinel KQL — DNS Amplification Attack Detection

```kql
// T1498.002 — DNS reflection amplification detection
// Large DNS responses to spoofed source IPs
// Author: Bhargav Baranda (Granger0007) | Date: 2026-03-06

DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "ANY"
| summarize
    QueryCount = count(),
    UniqueTargets = dcount(ClientIP),
    AvgResponseSize = avg(ResponseSize)
    by bin(TimeGenerated, 5m), ServerIP
| where QueryCount > 100
    or AvgResponseSize > 3000
| extend RiskLevel = case(
    QueryCount > 500, "Critical",
    QueryCount > 200, "High",
    "Medium"
  )
| project TimeGenerated, ServerIP, QueryCount,
          UniqueTargets, AvgResponseSize, RiskLevel
| sort by QueryCount desc
```

---

## 🔗 Cross-Lab Connections

| Lab | Connection |
|-----|-----------|
| **Case-001 — Phishing** | SPF records found today are the exact mechanism that would have detected the phishing attack. The attacker used a compromised third-party server not listed in the spoofed domain's SPF record. |
| **Case-002 — TCP Analysis** | DNS resolution happens before TCP connection. The RAT had to resolve the C2 domain in DNS before Packet 1 (SYN) was ever sent. That DNS query is the earliest detectable indicator. |
| **Case-003 — Subnetting** | BBC IPs — 151.101.0.81, 151.101.64.81, 151.101.128.81, 151.101.192.81 — are spaced exactly 64 apart. Same /26 subnet block boundaries from the subnetting lab. DNS and network architecture are built on identical mathematical foundations. |

---

## 📚 Security+ SY0-701 Connection

| Objective | Concept Demonstrated |
|-----------|-------------------|
| **4.1** — Security tools | `dig` for DNS investigation and threat intelligence |
| **2.2** — Threat vectors | DNS spoofing, DNS amplification, C2 via DNS tunnelling |
| **3.1** — Enterprise security concepts | DNS security, SPF/DKIM/DMARC |

---

## 🎤 Interview Answer

> *"Walk me through how you'd investigate a suspicious domain."*

"I run DNS enumeration as the first step of any domain investigation. Using dig, I query A, MX, NS, and TXT records to build an infrastructure profile, then run reverse lookups and ASN queries to confirm IP ownership and age. In a lab investigation of bbc.co.uk, I identified their CDN provider, email security vendor, nameserver architecture, full technology stack, and SPF configuration from public DNS records alone — before touching any threat intelligence database. That workflow takes under two minutes. Legitimate domains look rich, established, and consistent — many records, known vendors, old IP allocations. Malicious domains look empty, new, and evasive — one IP, no MX records, anonymous nameservers, registered days ago. The contrast between those two profiles is the entire skill. My seven-step DNS investigation workflow is documented in my GitHub portfolio."

---

<div align="center">

*Lab 004 complete. The internet answered every question.*
*Seven commands. Under two minutes. Intelligence without a single login.*

</div>
