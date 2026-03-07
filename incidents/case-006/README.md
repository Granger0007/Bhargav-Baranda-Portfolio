# Lab 006 — Port Security Analysis
## Twenty Entry Points. One Rule: Find Them First.

**Author:** Bhargav Baranda  
**Date:** March 2026  
**Classification:** Portfolio — Public  
**Platform:** Kali Linux ARM64  

---

## Executive Summary

Every computer connected to the internet exposes up to 65,535 numbered entry points called ports. Each one is a door. Some doors should be open — they are the doors the internet runs on. Some doors should be sealed permanently. Some should face only the inside of the building. Some should have the best possible lock even when they must face outside.

This report documents 20 of the most security-critical ports on the internet. For each: what it does, how it gets exploited, and what the consequences look like when it is misconfigured. The analysis is anchored by the WannaCry attack of 2017 — a single open port, one unpatched vulnerability, and £92 million in damage to the National Health Service.

The job of a security analyst is to know which doors are which — and find the wrong ones before an attacker does.

---

## Table of Contents

1. [Methodology](#methodology)
2. [Critical Risk Ports](#critical-risk)
3. [High Risk Ports](#high-risk)
4. [Medium Risk Ports](#medium-risk)
5. [Low Risk Ports](#low-risk)
6. [Complete Reference Table](#complete-reference-table)
7. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
8. [Connections to Previous Labs](#connections-to-previous-labs)
9. [Key Findings](#key-findings)

---

## Methodology

Three principles frame every port assessment in this report.

**Open is not the same as dangerous.** A web server needs ports 80 and 443. A mail server needs port 25. Databases need their own ports internally. Open ports are normal and necessary. Risk is determined by context — which ports are open, what faces the internet versus the internal network, whether the service is patched, and whether it is monitored.

**Protocol age predicts risk.** Almost every major internet protocol was designed when the internet consisted of a handful of university computers whose users trusted each other completely. Security was not considered. When the internet became public and adversarial, these protocols became attack surfaces. Every insecure protocol eventually received a secure replacement. The insecure versions still run on millions of systems.

**Detection is the second line of defence.** When a port cannot be closed — because a legacy system requires it, or because the business depends on it — detection becomes the control. Understanding what normal traffic looks like on each port is the foundation for identifying what is abnormal.

---

## Critical Risk

> Ports in this category represent immediate, high-probability threat vectors. Any of these found internet-facing constitutes a critical finding requiring same-day remediation.

---

### Port 23 — Telnet

| Field | Detail |
|-------|--------|
| **Purpose** | Remote command-line access |
| **Created** | 1969 |
| **Encrypted** | ❌ No |
| **Risk** | 🔴 Critical |
| **Action** | Close immediately. Replace with SSH on port 22. |

**What it does.** Telnet allows an administrator to control a remote computer by typing commands as if physically present at the machine. When it was created in 1969, the internet consisted of a few dozen computers at universities. Everyone on the network was a known colleague. Security was not a consideration.

**Why it is indefensible today.** Telnet transmits everything in plain text — the username, the password, every command typed, every response returned. There is no encryption to break. An analyst running a packet capture on the same network segment reads an administrator's entire session in real time, as it happens. A compromised router anywhere along the route between the administrator and the server captures the complete session silently.

**The verdict.** There is no legitimate reason for Telnet to exist on any modern network. Finding port 23 open is an automatic critical finding. The remediation is immediate closure and replacement with SSH.

---

### Port 445 — SMB (Server Message Block)

| Field | Detail |
|-------|--------|
| **Purpose** | Windows file and printer sharing |
| **Encrypted** | Partial (version-dependent) |
| **Risk** | 🔴 Critical |
| **Action** | Never expose to the internet. Patch all systems. Segment with firewall rules. |

**What it does.** SMB is the technology behind every shared drive in a Windows network — the system that lets you open a file stored on a central server from your desk. It is fundamental infrastructure in almost every organisation running Windows.

**How it became the most dangerous port on the internet.** In 2013, the United States National Security Agency discovered a critical vulnerability in SMB. Rather than disclosing it for remediation, they weaponised it as a tool codenamed EternalBlue. EternalBlue could compromise a machine with no credentials whatsoever — no username, no password, no user interaction. A single specially crafted packet to port 445. Complete control.

In 2017, a group called Shadow Brokers stole and published NSA hacking tools. EternalBlue became public. Within weeks, criminal groups combined it with ransomware and released WannaCry.

**The WannaCry incident — May 2017.**

| Metric | Figure |
|--------|--------|
| Machines infected globally | 230,000+ |
| Countries affected | 150 |
| Time to global spread | Hours |
| NHS estimated financial damage | £92 million |
| NHS surgeries cancelled | Thousands |
| Ambulances diverted | Confirmed |
| Patch availability before attack | 2 months |

WannaCry's mechanism was automated: infect a machine via EternalBlue, encrypt all files, scan the network for other machines with port 445 open, repeat. No human involvement. No way to stop it without disconnecting from the network entirely.

Every machine that had applied the available patch was immune. Every machine that had not was destroyed.

**The verdict.** Port 445 must never be accessible from the internet. Patch management is not optional — it is the difference between immunity and £92 million in damage.

---

### Port 3389 — RDP (Remote Desktop Protocol)

| Field | Detail |
|-------|--------|
| **Purpose** | Full visual remote control of Windows machines |
| **Encrypted** | ✅ Yes (transport-level) |
| **Risk** | 🔴 Critical |
| **Action** | Never expose directly to the internet. Require VPN as prerequisite. |

**What it does.** RDP gives a user the complete visual experience of another Windows computer — the desktop, the mouse, the keyboard — from anywhere in the world. IT support, server administration, and remote working all depend on it.

**The threat.** Criminal organisations maintain automated tools that continuously scan the entire internet — all 4.3 billion publicly accessible addresses — looking specifically for port 3389. When they find it, they pursue three attack paths simultaneously: credential brute-forcing using common password lists, credential stuffing using databases of previously breached usernames and passwords purchased on dark web markets, and exploitation of known vulnerabilities in older RDP versions that allow access without credentials.

Once inside, the attacker has full administrator visibility. They map the network, locate and destroy backups, identify every other system, and deploy ransomware simultaneously across the environment.

**The COVID-19 correlation.** In March 2020, millions of organisations rapidly enabled remote working by exposing RDP directly to the internet. Ransomware incidents increased immediately and proportionally. The causal link was direct and documented.

**The verdict.** RDP must sit behind a VPN. Employees authenticate to the VPN first, then access RDP within the protected network. Port 3389 open on an internet-facing scan is a critical finding.

---

### Port 6379 — Redis

| Field | Detail |
|-------|--------|
| **Purpose** | In-memory data cache — session tokens, API keys, application data |
| **Encrypted** | ❌ No (by default) |
| **Authenticated** | ❌ No (by default) |
| **Risk** | 🔴 Critical |
| **Action** | Never expose to the internet. Enable authentication. Bind to localhost only. |

**What it does.** Redis stores frequently accessed data in memory rather than on disk, providing near-instant retrieval. Almost every large-scale website runs Redis. It holds session tokens that keep users logged in, API keys that allow access to other services, and cached data from database queries.

**The catastrophic design assumption.** Redis was built with one assumption: it would only ever be accessible from a trusted internal network. On this basis, the designers made a decision that is reasonable in a sealed environment and catastrophic outside one — Redis has no authentication by default. Connect to port 6379 and everything stored is accessible immediately.

Worse, Redis includes a command that writes data to server storage. An attacker with access can write their own SSH keys into the server's authorised keys file — establishing a permanent backdoor that survives password resets, patch cycles, and security reviews.

Security researchers conducting regular internet scans consistently find tens of thousands of Redis installations directly accessible with no authentication. The majority are compromised within hours of exposure.

**The verdict.** Port 6379 must never be internet-facing. Authentication must be enabled. Redis should bind to localhost or a private network interface only.

---

## High Risk

> Ports in this category represent significant vulnerabilities. Internet exposure constitutes a high-severity finding. Internal exposure warrants review and monitoring.

---

### Port 21 — FTP (File Transfer Protocol)

| Field | Detail |
|-------|--------|
| **Purpose** | File transfer between computers |
| **Created** | 1971 |
| **Encrypted** | ❌ No |
| **Risk** | 🟠 High |
| **Replacement** | SFTP on port 22 |

FTP transmits authentication credentials in plain text — the same vulnerability demonstrated in Lab 005 with HTTP. Credential capture from FTP traffic is identical in method and effort. Additionally, FTP servers configured for anonymous access require no credentials, allowing anyone to browse stored files without authentication. Replace with SFTP: identical functionality, fully encrypted.

---

### Port 5900 — VNC (Virtual Network Computing)

| Field | Detail |
|-------|--------|
| **Purpose** | Full visual remote control — cross-platform |
| **Encrypted** | ⚠️ Version-dependent |
| **Risk** | 🟠 High |
| **Action** | Never internet-facing. Strong unique credentials. Current software version. |

Older VNC versions use authentication mechanisms that automated tools defeat rapidly. Default installations shipped with passwords set to `password`, `1234`, or nothing at all. Automated scanners find port 5900, try the ten most common default passwords, and frequently gain full visual control of the machine within seconds. Finding default credentials on VNC during a security assessment is an instant critical finding.

---

### Port 1433 — MSSQL (Microsoft SQL Server)

| Field | Detail |
|-------|--------|
| **Purpose** | Enterprise database — patient records, financial data, customer information |
| **Encrypted** | ✅ Yes (when configured) |
| **Risk** | 🟠 High |
| **Action** | Never internet-facing. Firewall to application servers only. |

Databases are internal infrastructure. Port 1433 appearing on an internet-facing scan means the database is exposed directly.

SQL Server's `xp_cmdshell` feature allows database queries to execute operating system commands on the underlying server — a database becomes a backdoor into the host.

**SOC detection signal:** A workstation making outbound connections to an external IP address on port 1433 is highly anomalous. Normal workstations do not initiate external database connections. This pattern indicates either data exfiltration disguised as database traffic, or command-and-control communication using a port that firewalls often permit outbound.

---

### Port 3306 — MySQL

| Field | Detail |
|-------|--------|
| **Purpose** | Open-source database — powers ~40% of all websites |
| **Risk** | 🟠 High |
| **Action** | Never internet-facing. Strong credentials. Bind to application servers only. |

MySQL's default installation historically included a `root` account with no password and remote access enabled. Millions of production installations shipped this configuration unchanged. Customer names, email addresses, and password hashes were accessible to anyone who connected and attempted `root` with no password. The lesson was taught through countless breaches. It still applies wherever default configurations remain in place.

---

### Port 139 — NetBIOS

| Field | Detail |
|-------|--------|
| **Purpose** | Legacy Windows network discovery and naming |
| **Risk** | 🟠 High |
| **Action** | Block at internet perimeter. Restrict internally. |

NetBIOS answers queries without requiring authentication. A standard enumeration tool querying port 139 receives: every computer name on the network, the domain name, every user account, every group, the password policy, and all accessible shares — without a single credential.

For an attacker who has gained any internal foothold, port 139 is the complete organisational map: the employee directory, the network layout, the list of targets, all delivered freely by the target's own systems.

---

### Port 389 — LDAP (Lightweight Directory Access Protocol)

| Field | Detail |
|-------|--------|
| **Purpose** | Active Directory queries — all users, computers, permissions in a Windows environment |
| **Encrypted** | ❌ No |
| **Risk** | 🟠 High |
| **Replacement** | LDAPS on port 636 |

Plain LDAP is unencrypted. Every query and response is readable on the network. An attacker who gains any foothold inside a corporate environment immediately queries LDAP — within minutes they hold the complete organisational structure: every employee, every administrator account with elevated privileges, every security group, every machine on the network. The organisation's own directory system delivers the attacker's reconnaissance.

---

## Medium Risk

> Ports in this category carry significant risk when misconfigured or unmonitored. Each has a secure alternative or a documented configuration standard.

---

### Port 25 — SMTP (Simple Mail Transfer Protocol)

SMTP was designed with no mechanism to verify that a sender controls the address they claim to be sending from. This is the technical foundation of email spoofing. The phishing attack investigated in Lab 001 exploited exactly this gap. The defences developed in response — SPF records, DKIM signatures, DMARC policies, all analysed in Lab 004 — exist specifically to compensate for SMTP's original design.

A compromised or misconfigured system with port 25 accessible can become a spam relay — sending phishing emails in a legitimate organisation's name until the domain is blacklisted and legitimate email delivery fails.

---

### Port 110 — POP3 (Post Office Protocol)

Plain POP3 transmits authentication credentials in plain text. Identical vulnerability to FTP and Telnet. Secondary concern: emails downloaded via POP3 are deleted from the server and exist only on the local device — hardware failure means permanent loss. Replace with POP3S on port 995.

---

### Port 143 — IMAP (Internet Message Access Protocol)

IMAP is the modern, correct approach to email — messages stay on the server, synchronised across every device, backed up centrally. The only remaining problem is plain IMAP on port 143 transmits credentials unencrypted. The architecture is right. The transport is not. Replace with IMAPS on port 993.

---

### Port 8080 — HTTP Alternate

Port 8080 is the development and testing entrance. A developer builds a test environment on port 8080, the production version launches on port 80, and the test environment is forgotten — running unpatched, unmonitored, with debug features enabled, default credentials unchanged, sometimes connected to the production database. Attackers scan for port 8080 specifically because forgotten servers are soft targets: not hardened for production exposure, not watched.

---

### Port 80 — HTTP

As demonstrated in Lab 005: HTTP transmits everything in plain text. Credentials submitted through an HTTP login form appear in a packet capture window within seconds, highlighted, completely readable, requiring no special skills or tools. On any shared network — a coffee shop, a hotel, an office — anyone running Wireshark reads every HTTP credential submitted while they are connected.

**Replace all login forms and data submission with HTTPS on port 443.**

---

### Port 22 — SSH (Secure Shell)

SSH is the correct, encrypted replacement for Telnet. The transport is secure. The risk is credential-based: servers with port 22 exposed to the internet receive thousands of automated login attempts every day. Automated tools cycle through millions of common password combinations against any accessible SSH service.

The mitigation is decisive: key-based authentication eliminates passwords entirely. Combined with software that blocks repeated failed attempts, SSH becomes the most defensible service on this list. Of the three most commonly exploited remote access ports — 22, 445, and 3389 — SSH with key-based authentication is the last priority for remediation. The others are more immediately dangerous.

---

### Port 53 — DNS

As analysed in Lab 004, DNS translates human-readable addresses into IP addresses. Every internet connection begins with a DNS lookup. Firewalls that block DNS break internet connectivity entirely — making DNS an unavoidable outbound channel in almost every network.

Attackers exploit this by encoding exfiltrated data inside DNS queries. Stolen information leaves the network disguised as routine address lookups — a technique called DNS tunnelling. The destination is a domain controlled by the attacker; the query itself carries the payload. Detection requires monitoring DNS traffic for anomalous query patterns: unusual query lengths, high query volume to unfamiliar domains, or queries containing encoded strings.

---

## Low Risk

> Ports in this category represent correct, secure configurations. Finding these in use is a positive indicator of security maturity.

---

### Port 995 — POP3S

Port 110 with encryption applied. Credentials and email content protected in transit. Finding 995 in use instead of 110 indicates the organisation chose the secure option when both were available.

---

### Port 993 — IMAPS

Port 143 with encryption applied. Modern email synchronisation with full transport security. Finding 993 in use instead of 143 is the expected standard on any well-configured mail infrastructure.

---

### Port 443 — HTTPS

The gold standard for web communication. As demonstrated in Lab 005: the difference between port 80 and port 443 is the difference between credentials visible in Wireshark in three seconds and 31 packets of completely unreadable Application Data.

One limitation: the destination domain remains visible in the initial TLS handshake via the Server Name Indication (SNI) field. The content of the session is completely protected; where you are connecting is not. VPNs address this for environments requiring complete destination privacy.

Every login form, every payment page, every submission of personal information must use port 443. The padlock in the browser is not decoration — it is confirmation that this protection is active.

---

## Complete Reference Table

| Port | Service | Risk | Core Issue | Remediation |
|:----:|---------|:----:|-----------|-------------|
| 23 | Telnet | 🔴 Critical | Plain text everything | Close. Replace with SSH |
| 445 | SMB | 🔴 Critical | EternalBlue / WannaCry entry | Never internet-facing. Patch. |
| 3389 | RDP | 🔴 Critical | #1 ransomware entry point | VPN required as prerequisite |
| 6379 | Redis | 🔴 Critical | No authentication by default | Never internet-facing. Enable auth. |
| 21 | FTP | 🟠 High | Plain text credentials | Replace with SFTP on port 22 |
| 5900 | VNC | 🟠 High | Default credentials exploited | Never internet-facing. Strong auth. |
| 1433 | MSSQL | 🟠 High | Database never internet-facing | Firewall to app servers only |
| 3306 | MySQL | 🟠 High | Default credentials historically blank | Firewall to app servers only |
| 139 | NetBIOS | 🟠 High | Full network map without credentials | Block at perimeter |
| 389 | LDAP | 🟠 High | Unencrypted AD queries | Replace with LDAPS on port 636 |
| 25 | SMTP | 🟡 Medium | Foundation of email spoofing | SPF, DKIM, DMARC — all three |
| 110 | POP3 | 🟡 Medium | Plain text credentials | Replace with POP3S on port 995 |
| 143 | IMAP | 🟡 Medium | Plain text credentials | Replace with IMAPS on port 993 |
| 8080 | HTTP Alt | 🟡 Medium | Forgotten servers — easy targets | Audit regularly. Close if unused. |
| 80 | HTTP | 🟡 Medium | Plain text credentials | Move all login forms to port 443 |
| 22 | SSH | 🟡 Medium | Brute force when password-based | Key-based authentication only |
| 53 | DNS | 🟡 Medium | DNS tunnelling, amplification | Monitor query anomalies |
| 995 | POP3S | 🟢 Low | Correct — encrypted POP3 | Maintain current configuration |
| 993 | IMAPS | 🟢 Low | Correct — encrypted IMAP | Maintain current configuration |
| 443 | HTTPS | 🟢 Low | Correct — encrypted web | The standard. Use everywhere. |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance to This Lab |
|--------|-----------|:--:|----------------------|
| Discovery | Network Service Discovery | T1046 | Port scanning — identifying open services across a target |
| Lateral Movement | Remote Services — RDP | T1021.001 | Port 3389 as ransomware entry and lateral movement vector |
| Lateral Movement | Remote Services — SMB/Windows Admin Shares | T1021.002 | Port 445 — EternalBlue exploitation path |
| Exfiltration | Exfiltration Over Alternative Protocol — DNS | T1048.003 | DNS tunnelling via port 53 to bypass firewall controls |
| Initial Access | Exploit Public-Facing Application | T1190 | Unpatched services on exposed ports — WannaCry vector |
| Persistence | External Remote Services | T1133 | RDP, VNC, SSH exposed to internet as persistent access mechanisms |

---

## Connections to Previous Labs

| Lab | Connection |
|-----|-----------|
| **Lab 001** — Spearphishing | Port 25 (SMTP) is the technical foundation of email spoofing — the delivery mechanism for the phishing attack investigated in that case |
| **Lab 004** — DNS Enumeration | Port 53 extended — DNS tunnelling as an exfiltration channel, and the amplification attack directly experienced when the ANY query timed out |
| **Lab 005** — HTTP vs HTTPS | Port 80 versus port 443 directly demonstrated — credentials readable in Wireshark in seconds on HTTP, completely unreadable on HTTPS |

---

## Key Findings

**Finding 1 — Protocol age is a reliable risk indicator.**  
Ports 23, 21, 110, and 143 share a common characteristic: they were built before the internet was adversarial. Every one of them transmits credentials in plain text. Every one of them has an encrypted replacement available. Finding any of these in active use on a modern network is a finding.

**Finding 2 — The WannaCry incident is a patch management case study.**  
Port 445 with the EternalBlue vulnerability was exploitable for two months before WannaCry was released. The patch was available. The infection was preventable. £92 million in NHS damage and thousands of cancelled surgeries are the documented cost of that delay. The security control that would have prevented it was routine patch management.

**Finding 3 — Default configurations are the attacker's first guess.**  
Redis with no authentication, MySQL with a blank root password, VNC with `password` as the password — these are not theoretical vulnerabilities. They are the first credentials tried by every automated scanner. Default configurations must be changed before any system is connected to a network.

**Finding 4 — Some ports cannot be closed — detection becomes the control.**  
Port 53 cannot be blocked without breaking internet connectivity. Port 25 is required for email. Port 22 is necessary for server management. For ports that must remain open, the security control is monitoring: baseline normal traffic patterns, build detection logic for anomalies, and alert on deviations. A workstation making outbound connections on port 1433 to an unknown external IP is not noise. It is a signal.

---

*Lab 006 complete.*  
*Twenty ports. Some open. Some sealed. Some monitored. All understood.*  
*Know what is open before the attacker does — that is the job.*
