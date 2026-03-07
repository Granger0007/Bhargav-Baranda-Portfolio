# Lab 007 — Firewall Architecture & Network Segmentation
## The Invisible Walls Inside Every Computer Network

**Author:** Bhargav Baranda  
**Date:** March 2026  
**Classification:** Portfolio — Public  
**Platform:** Kali Linux ARM64  
**MITRE ATT&CK:** T1190, T1021.002, T1041, T1571, T1599  

---

## Executive Summary

A firewall on the perimeter of a network is necessary. It is not sufficient.

When WannaCry struck the NHS in May 2017, it did not overcome a particularly sophisticated perimeter defence. It found one vulnerable machine, exploited a known flaw in Windows file sharing, and spread automatically to every other machine on the same flat network. One entry point. No internal walls. £92 million in damage, thousands of cancelled surgeries, and patient records inaccessible across a national health system.

This report documents what should have been there: firewall fundamentals, stateful versus stateless inspection, three-zone network architecture, traffic flow design, the principle of least privilege, and the analytical framework that underpins every network security investigation. It closes with the practical skill of communicating technical findings to non-technical decision-makers — because a finding that cannot be communicated cannot be acted on.

---

## Table of Contents

1. [What a Firewall Is](#what-a-firewall-is)
2. [Stateless vs Stateful Inspection](#stateless-vs-stateful-inspection)
3. [Three-Zone Architecture](#three-zone-architecture)
4. [Traffic Flow Design](#traffic-flow-design)
5. [Least Privilege](#least-privilege)
6. [Attack Scenarios](#attack-scenarios)
7. [Communicating to Decision-Makers](#communicating-to-decision-makers)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Connections to Previous Labs](#connections-to-previous-labs)
10. [Key Findings](#key-findings)

---

## What a Firewall Is

### The Rulebook Model

A firewall is a rule-based filter applied to network traffic. Every piece of data crossing a network moves in small packets. Each packet carries a label showing its origin, its destination, and which port it wants to use. The firewall reads the label, checks its rulebook, and makes one of two decisions: allow or block.

No judgement. No intuition. No exceptions outside the rules.

The rulebook follows a consistent pattern for each type of traffic:

```
From [source]  →  To [destination]  →  Via [port]  →  Action [allow / block]
```

**Example rules:**

```
Allow  →  Anyone          →  Web server       →  Port 443  →  ALLOW
Allow  →  Anyone          →  Mail server      →  Port 25   →  ALLOW
Block  →  Anyone          →  Customer DB      →  Any port  →  BLOCK
Block  →  Anyone          →  Everything else  →  Any port  →  BLOCK  ← default deny
```

### The Default Deny Rule

The single most important line in any firewall configuration is the last one: **block everything not explicitly permitted**.

This is called the default deny rule. Its implications are significant:

| Approach | Who Has the Advantage |
|---|---|
| **Default deny** — allow only what is explicitly permitted | Defender — attacker must find something deliberately opened |
| **Default allow** — block only what is explicitly forbidden | Attacker — must find only one thing nobody thought to block |

Default deny means defenders write rules for legitimate traffic only. Everything else — every possible attack, every unexpected connection, every port an attacker might probe — is automatically blocked without anyone needing to anticipate it.

Default allow means defenders must predict every possible attack and write a rule against each one. The mathematics of that approach always favour the attacker.

**Every properly secured network ends with a default deny rule.**

---

## Stateless vs Stateful Inspection

### Stateless Firewalls — No Memory

A stateless firewall evaluates each packet in complete isolation. It reads the label. It applies the rules. It has no memory of previous packets and no concept of whether a packet belongs to an ongoing conversation or arrived uninvited.

**The problem this creates:**

When a computer visits a website, it sends a request outbound to a web server. The server sends a response back inbound. A stateless firewall sees that inbound response as an inbound packet from an external server — identical in form to an attacker sending unsolicited packets inbound.

A stateless firewall cannot distinguish between a response that was asked for and an attack packet pretending to be one. Attackers exploited this by crafting attack packets designed to look like legitimate responses.

### Stateful Firewalls — Connection Tracking

A stateful firewall maintains a connection tracking table — a live record of every approved outbound connection.

**Example connection tracking table:**

| Internal Host | Internal Port | External Destination | State |
|:-------------:|:-------------:|---------------------|:-----:|
| 192.168.1.50 | 54231 | google.com | Active |
| 192.168.1.72 | 38901 | bbc.co.uk | Active |
| 192.168.1.31 | 61204 | DNS server | Active |

When an inbound packet arrives, the firewall checks the table. If a matching outbound connection exists — legitimate response, allow it through. If no matching entry exists — this packet arrived uninvited. Block it, regardless of how legitimate it appears.

The spoofed response attack that defeated stateless firewalls finds no entry in the tracking table and is dropped silently.

**All modern firewalls are stateful. Finding a stateless firewall protecting a production network is itself a security finding.**

---

## Three-Zone Architecture

### The Core Problem with Single-Layer Defence

A single firewall between an organisation and the internet contains one catastrophic assumption: the barrier will never be breached.

Barriers are breached. Website vulnerabilities are found. Phishing emails reach employees. Suppliers with network access get compromised. Software bugs exist for years before discovery. History is a continuous record of security perimeters failing in ways nobody anticipated.

The question is not whether a breach will occur. The question is what happens when it does.

Three-zone architecture answers that question by designing for breach containment rather than breach prevention alone.

### The Three Zones

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ZONE 1 — THE INTERNET
  Trust level: Zero. Assume hostile.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                          │
              Permitted: Port 80, 443, 25, 53
              Everything else: BLOCKED
                          │
                 ┌────────▼────────┐
                 │   FIREWALL 1    │
                 │  Default deny   │
                 └────────┬────────┘
                          │
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ZONE 2 — THE DMZ (Demilitarised Zone)
  Trust level: Partial. Public-facing services only.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
       │               │               │
  ┌────▼────┐    ┌──────▼──────┐  ┌────▼────┐
  │  Web    │    │    Email    │  │   DNS   │
  │ Server  │    │   Server   │  │  Server │
  └─────────┘    └─────────────┘  └─────────┘
                          │
           Permitted: Specific DB query only
           Everything else: BLOCKED
                          │
                 ┌────────▼────────┐
                 │   FIREWALL 2    │
                 │ Strictest rules │
                 └────────┬────────┘
                          │
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ZONE 3 — THE INTERNAL NETWORK
  Trust level: High. No direct internet access.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
       │           │           │           │
  ┌────▼───┐  ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
  │Customer│  │Finance │  │  HR    │  │  User  │
  │   DB   │  │Systems │  │Systems │  │Directory│
  └────────┘  └────────┘  └────────┘  └────────┘
```

### What Lives in Each Zone

**Zone 1 — The Internet**

Public. Open to everyone. Legitimate users share this space with automated scanners, criminal botnets, and sophisticated attackers. Nothing from Zone 1 is trusted. Everything is assumed potentially hostile until it matches a specific permitted rule.

**Zone 2 — The DMZ**

The public-facing portion of the network. Three types of systems belong here:

| System | Purpose | Risk if Compromised |
|--------|---------|-------------------|
| Web server | Serves the public website | Attacker has the website — not the internal network |
| Email server | Receives and sends email | Attacker has email access — not the internal network |
| DNS server | Answers domain queries | Attacker can affect domain resolution — not the internal network |

All three systems must face the internet. The DMZ acknowledges this necessity and contains the risk — these systems are deliberately isolated from everything sensitive by a second, stricter firewall.

**Zone 3 — The Internal Network**

Where sensitive systems live. None of it reachable from the internet. None of it reachable from the DMZ except through one narrow, specific, monitored channel.

| System | Contents |
|--------|---------|
| Customer database | Every record the organisation holds on customers |
| Finance systems | Payments, accounts, payroll — systems that move money |
| HR systems | Employee personal data, salaries, disciplinary records |
| User directory (AD) | Every user account, administrator credential, and permission |

---

## Traffic Flow Design

### Inbound Traffic Rules

| From | To | Port | Decision | Rationale |
|:----:|:--:|:----:|:--------:|-----------|
| Internet | Web server | 443, 80 | ✅ Allow | Legitimate public access |
| Internet | Email server | 25 | ✅ Allow | Email delivery |
| Internet | DNS server | 53 | ✅ Allow | Domain resolution |
| Internet | Any other system | Any | ❌ Block | No legitimate inbound use case |
| DMZ | Customer DB | 3306 | ✅ Allow (specific) | Web server needs this — nothing else |
| DMZ | Finance systems | Any | ❌ Block | No legitimate DMZ→Finance path |
| DMZ | HR systems | Any | ❌ Block | No legitimate DMZ→HR path |
| DMZ | User directory | Any | ❌ Block | No legitimate DMZ→AD path |

### Outbound Traffic — The Forgotten Half

Most organisations focus on inbound controls and leave outbound largely unrestricted. This is a critical gap.

When a machine inside the organisation is compromised, malware's first action is to call home — establish an outbound connection to the attacker's server, receive instructions, and begin exfiltrating data. If the outbound rules permit all outbound connections, this call succeeds silently. The firewall watches it happen and does nothing.

**Outbound rules that prevent this:**

```
Block all outbound connections on port 1433 (MSSQL) from workstations → BLOCK + LOG
Block all outbound connections on port 3306 (MySQL) from workstations  → BLOCK + LOG
Block all outbound connections on port 445 (SMB) from workstations     → BLOCK + LOG
Alert security team on any trigger of the above rules
```

**The logging instruction is as important as the block.**

Every blocked outbound connection is a clue. One workstation attempting to reach an unusual external server at an unusual port — could be a misconfigured application. The same workstation making that same connection two hundred times in one hour at 3am — that is a compromised machine attempting to reach its controller. The pattern in the blocked attempts tells the story. Unlogged blocks leave no evidence.

---

## Least Privilege

The principle of least privilege is the framework behind every well-written firewall rule: **give only what is needed. Nothing more.**

### The Difference It Makes

**Poorly written rule:**
```
Allow traffic from DMZ → Internal network → Port 3306
```
This works for the web server's database query. It also allows every other DMZ system to reach every internal database — including finance and HR.

**Correctly written rule:**
```
Allow 192.168.2.10 (web server) → 192.168.3.50 (customer DB only) → Port 3306
```
The web server can query the customer database. Nothing else can. If the web server is compromised, the attacker can reach one database. The finance database, HR records, and user directory are each protected by a separate rule that doesn't exist for them.

**Least privilege is the difference between a breach that costs one database and one that costs the organisation.**

---

## Attack Scenarios

### Scenario 1 — The Rule That Doesn't Work

A junior engineer writes the following rule to allow the web server to query the customer database:

```
Allow traffic from DMZ → Internal network → Ports 80, 443
```

**Two problems:**

First — databases communicate on port 3306, not ports 80 or 443. This rule allows web traffic through to internal systems. The database is never actually reached. The website fails.

Second — even corrected to port 3306, "from DMZ" is too broad. Every system in the DMZ can now reach every internal system on that port — including finance and HR.

**The correct rule:**
```
Allow 192.168.2.10 → 192.168.3.50 → Port 3306 → ALLOW
Everything else    → Internal network → Any port → BLOCK
```
Minimum access. Specific source. Specific destination. Specific port.

---

### Scenario 2 — The 3am Alert

A workstation inside the organisation makes repeated outbound connections to an unknown external IP address on port 4444 — a port associated with Metasploit reverse shells — at 3am. The connections succeed.

**What this means:** The workstation is compromised. Malware is running. It has established a command-and-control channel to an attacker's server. The firewall is allowing it because no outbound rule blocks this port from internal workstations.

**The rule that would have prevented it:**
```
Block all outbound connections from internal workstations → Port 4444 → BLOCK + LOG
```

**The deeper issue:** Sophisticated attackers don't use unusual ports that security teams know to block. They hide communications inside port 443 — the encrypted HTTPS port that every firewall allows outbound, because blocking it would break internet browsing. The rule is one layer. Monitoring for unusual connection destinations, volumes, and timing is the layer that catches attackers using permitted ports.

---

### Scenario 3 — The Organisation With No Internal Walls

An organisation runs a single flat network — one firewall, no internal segmentation. Website server, customer database, finance systems, HR records, and Active Directory all sit on the same network segment, equally reachable by anything that gets through the perimeter.

The web server is compromised via an unpatched vulnerability.

**What the attacker can now do:**

| Action | Result |
|--------|--------|
| Query Active Directory | Every user account, administrator credential, and privilege level in the organisation |
| Access customer database | Every customer record |
| Access finance systems | Full access to payment and payroll systems |
| Access HR records | Every employee's personal data |
| Locate and destroy backups | Removes recovery capability before deploying ransomware |
| Deploy ransomware simultaneously across all systems | Complete operational shutdown |

**Regulatory consequence:** GDPR Article 33 requires notification to the ICO within 72 hours of discovering a breach. Potential fine: up to 4% of global annual turnover. Public disclosure of stolen customer data if ransom is not paid.

All of this from one vulnerable web server. All of it preventable with a second firewall and proper internal segmentation.

**With three-zone architecture:**

The same web server is compromised. The attacker attempts to reach Active Directory — blocked by Firewall 2. Finance systems — blocked. HR records — blocked. Every lateral movement attempt generates a log entry. The SIEM detects the pattern within minutes. An alert fires. The security analyst isolates the web server. Incident response begins.

The attacker has the web server. The internal network is sealed. The security team already knows they're there.

---

## Communicating to Decision-Makers

Technical accuracy is only useful if it reaches the people who control resources and decisions. A finding that cannot be communicated to a non-technical audience cannot be acted on.

### The Same Finding — Two Ways

**Finding:** Ports 445, 3389, and 22 are open on internet-facing infrastructure. A known ransomware group is actively scanning for these entry points.

---

**Ineffective communication:**

> *"We have open SMB, RDP, and SSH ports on our perimeter. The threat actor is using EternalBlue variants and credential stuffing against these attack surfaces. We need to update our ACLs immediately."*

A non-technical decision-maker hears: technical words requiring technical solutions. Urgency: unclear. Consequences of inaction: unclear. What to approve: unclear. Likely outcome: added to a backlog.

---

**Effective communication:**

> *"A ransomware group is actively scanning UK organisations for three specific weaknesses we currently have exposed. If they reach us before we close them, we're looking at a complete shutdown of our systems and a legal obligation to notify the regulator within 72 hours. I need 30 minutes and your authorisation to temporarily take three services offline."*

A non-technical decision-maker hears: ransomware, legal obligation, regulator, 30 minutes, specific authorisation needed. Urgency: clear. Consequences of inaction: clear. What to approve: clear. Likely outcome: immediate authorisation.

---

### The Three Elements That Made It Work

| Element | Ineffective Version | Effective Version |
|---------|--------------------|--------------------|
| **Consequence** | "Cyber risk" | "Complete shutdown of our systems" — something visible and concrete |
| **Regulatory hook** | Not mentioned | "Legal obligation to notify the regulator within 72 hours" — decision-makers in regulated industries respond to this immediately |
| **Concrete ask** | Vague concern | "30 minutes and your authorisation" — a specific decision that can be approved or declined |

A decision-maker cannot approve or decline a vague concern. They can approve or decline a specific request with a defined scope.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance |
|--------|-----------|:--:|-----------|
| Initial Access | Exploit Public-Facing Application | T1190 | Web server compromise as entry point into DMZ |
| Lateral Movement | Remote Services — SMB | T1021.002 | WannaCry propagation via port 445 across flat network |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Malware calling home via permitted outbound ports |
| Command and Control | Non-Standard Port | T1571 | C2 communication using unusual outbound ports to evade detection |
| Defence Evasion | Network Boundary Bridging | T1599 | Attacker attempting to move from DMZ to internal network |

---

## Connections to Previous Labs

| Lab | Connection |
|-----|-----------|
| **Lab 005** — HTTP vs HTTPS | Outbound monitoring scenario: encrypted C2 traffic on port 443 hides inside legitimate HTTPS — the same port discussed in the credential interception lab |
| **Lab 006** — Port Security | Every port in the twenty-door analysis maps directly to a firewall rule — ports 445, 3389, 6379, and 23 are the exact ports that must never be permitted through Firewall 1 |
| **Lab 001** — Spearphishing | The post-compromise lateral movement scenario in this lab is the "what happens next" after the phishing email in Lab 001 achieves initial access |

---

## Key Findings

**Finding 1 — The default deny rule is the most important line in any firewall configuration.**  
Default deny forces attackers to find something deliberately opened. Default allow forces defenders to predict every possible attack. The mathematics of the latter approach always favour the attacker.

**Finding 2 — Stateless firewalls are a security finding.**  
All modern firewalls should be stateful. A stateless firewall cannot distinguish between a legitimate response and a spoofed attack packet. Finding one protecting a production network requires immediate escalation.

**Finding 3 — Outbound controls are as important as inbound controls.**  
Malware phones home outbound. Data leaves outbound. C2 channels operate outbound. An organisation with strict inbound rules and permissive outbound rules has protected the front door and left the back door open. All blocked outbound attempts must be logged — the pattern in those logs is the evidence.

**Finding 4 — Least privilege contains breaches.**  
Broad rules that allow more access than the legitimate use case requires turn a contained breach into a cascading one. Every firewall rule should specify the minimum source, the minimum destination, and the minimum port required. Nothing broader.

**Finding 5 — Architecture, not just technology, determines outcomes.**  
WannaCry did not defeat a particularly sophisticated perimeter. It found a flat network with no internal walls. The same malware, against the same perimeter, on a properly segmented three-zone network, would have infected one machine and been detected and contained. The architecture determined whether the outcome was one compromised system or £92 million in damage.

---

*Lab 007 complete. The walls are understood.*  
*Firewall rules. Three zones. Default deny. Least privilege. Outbound monitoring.*  
*Next — Nmap. Finding out which walls other people forgot to build.*
