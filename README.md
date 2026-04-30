<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:EE3124&height=180&section=header&text=Security%20Operations%20Portfolio&fontSize=40&fontColor=ffffff&fontAlignY=38&desc=Bhargav%20Baranda%20%7C%20SOC%20Analyst%20%7C%20Detection%20Engineer&descSize=16&descAlignY=58&descColor=EE3124" />

[![ISC²](https://img.shields.io/badge/ISC²-Certified_in_Cybersecurity-00599C?style=for-the-badge&logoColor=white)](https://www.isc2.org/certifications/cc)
[![Security+](https://img.shields.io/badge/CompTIA-Security+_In_Progress-EE3124?style=for-the-badge)](https://www.comptia.org/certifications/security)
[![Royal Holloway](https://img.shields.io/badge/Royal_Holloway-MSc_Information_Security-003087?style=for-the-badge)](https://www.royalholloway.ac.uk)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhargav--baranda-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/bhargav-baranda)
[![YouTube](https://img.shields.io/badge/YouTube-Granger_Security-FF0000?style=flat-square&logo=youtube)](https://youtube.com/@Granger-Security)
[![GitHub](https://img.shields.io/badge/GitHub-Granger0007-181717?style=flat-square&logo=github)](https://github.com/Granger0007)

![Labs](https://img.shields.io/badge/Labs_Complete-9-EE3124?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Sub--technique_Level-orange?style=flat-square)
![Detection Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## What This Portfolio Demonstrates

Every investigation here was conducted in a purpose-built ARM64 home lab using enterprise-grade tools. This is not coursework — it is real detection engineering, documented to production standards.

Every piece of work meets the same bar:

- **MITRE ATT&CK** mapped at sub-technique level — tactic → technique → sub-technique → observed procedure
- **Detection triad** — Sigma (SIEM-agnostic) + Splunk SPL + Microsoft Sentinel KQL
- **Business impact** — systems affected, regulatory exposure (GDPR/ICO), £ estimate
- **Remediation playbook** — 0–4hr containment, 24–72hr eradication, long-term prevention
- **IOC package** — IPs, domains, hashes with confidence ratings

---

## Home Lab

```
MacBook Pro — Apple Silicon M-series (ARM64)
└── UTM Virtualisation
    └── Kali Linux ARM64
        ├── SIEM            →  Splunk (Docker/containerised)  +  ELK Stack 8.x
        ├── IDS / EDR       →  Suricata 7.x  +  Wazuh 4.x
        ├── Network         →  Wireshark 4.6.x · tcpdump · Nmap 7.99
        ├── Forensics       →  Volatility 3 · tshark · NetworkMiner
        ├── Detection Eng   →  Sigma · SPL · KQL
        ├── Offensive       →  Burp Suite · apktool · jadx · ADB
        └── Infrastructure  →  Docker containers — £0 cloud spend
```

> Enterprise SOC tools assume x86_64. My machine is Apple Silicon ARM64. Every workaround is documented and published — reproducible by any analyst on Apple Silicon.

---

## Lab Index

| # | Type | Title | Key Skills | Status |
|:-:|:----:|-------|-----------|:------:|
| 001 | 🔴 Investigation | [Spearphishing Attack — A Story in Seven Layers](./incidents/case-001/) | T1566.001 · T1204.002 · T1059.005 · T1027 · T1071.001 · T1573.001 · Sigma + SPL + KQL | ✅ |
| 002 | 🔴 Investigation | [TCP Traffic Analysis — SSL Stripping & C2 Beacon Detection](./incidents/case-002/) | T1040 · T1071.001 · T1557 · Wireshark packet analysis · Sigma + SPL + KQL | ✅ |
| 003 | 🔴 Investigation | [Network Segmentation — Lateral Movement Detection](./incidents/case-003/) | T1021.002 · T1018 · T1210 · Subnet boundary analysis · Sigma + SPL + KQL | ✅ |
| 004 | 🔵 Lab | [DNS Enumeration — Interrogating the Internet](./lab-setup/dns-enumeration/) | T1590.002 · T1498.002 · dig · nslookup · DNS record analysis · Threat intelligence | ✅ |
| 005 | 🔴 Investigation | [HTTP vs HTTPS — I Watched a Password Travel Across the Internet](./incidents/case-005/) | T1040 · T1557.002 · T1595.001 · Wireshark · Credential interception · TLS analysis | ✅ |
| 006 | 🔴 Investigation | [Twenty Doors — Port Security Analysis](./incidents/case-006/) | T1046 · T1021.001 · T1021.002 · T1048.003 · T1190 · T1133 · 20 ports risk-tiered | ✅ |
| 007 | 🔴 Investigation | [Firewall Architecture — The Invisible Walls Inside Every Network](./incidents/case-007/) | T1190 · T1021.002 · T1041 · T1571 · T1599 · Three-zone architecture · Default deny | ✅ |
| 008 | 🔵 Lab | [Nmap Port Scanning — What Attackers See in 30 Seconds](./lab-setup/nmap-labs/lab-008/) | T1046 · Nmap 7.99 · Wireshark · Service version detection · OS fingerprinting · VMware CVE probe | ✅ |
| 009 | 🔵 Lab | [Wireshark Deep Dive — Forensic PCAP Analysis](./lab-setup/wireshark-labs/lab-009/) | T1040 · T1557 · T1071 · tshark · TCP flag analysis · HTTP NSE extraction · SSH banner forensics | ✅ |
| 010 | 🔵 Lab | [Log Analysis Fundamentals](./lab-setup/log-analysis/lab-010/) | T1078 · T1110 · syslog · auth.log · Windows Event Logs · Event IDs 4624/4625/4688 | ✅ |

**Key:** 🔴 Incident Investigation &nbsp;·&nbsp; 🔵 Lab Setup &nbsp;·&nbsp; ✅ Complete &nbsp;·&nbsp; 🔄 In Progress

---

## MITRE ATT&CK Coverage

```
Reconnaissance   ████████░░  T1590 · T1046 · T1498 · T1595
Initial Access   ████░░░░░░  T1566.001 · T1190 · T1133
Execution        ██░░░░░░░░  T1204.002 · T1059.005
Defence Evasion  ████░░░░░░  T1036 · T1071 · T1573 · T1027
Credential Acc.  ████░░░░░░  T1110 · T1040 · T1557.002
Discovery        ██████░░░░  T1046 · T1590 · T1018 · T1210
Lateral Movement ██░░░░░░░░  T1021.001 · T1021.002
C2               ████░░░░░░  T1071.001 · T1071.004 · T1571
Exfiltration     ██░░░░░░░░  T1041 · T1048.003
```

Coverage expands with every lab. Full technique-to-investigation mapping in each case README.

---

## Projects

| | Project | Description | Stack | Status |
|:-:|---------|-------------|-------|:------:|
| 🛡️ | [OZONE Shield](https://github.com/Granger0007/ozone-shield) | Live AI scam detector — paste any suspicious message, receive an instant verdict with confidence score, reasons, and action guide | Claude AI · Netlify · Serverless · Node.js | 🔴 Live |

---

## Technical Skills

| Area | Skills |
|------|--------|
| **SIEM** | Splunk SPL (search, stats, eval, rex, timechart, correlation searches) · Microsoft Sentinel KQL · ELK Stack 8.x |
| **Detection Engineering** | Sigma · Splunk SPL · Microsoft Sentinel KQL · False positive tuning · Evasion gap analysis |
| **Incident Response** | NIST SP 800-61 lifecycle · Timeline reconstruction · Root cause analysis · GDPR Article 33 / ICO 72hr |
| **Threat Intelligence** | MITRE ATT&CK at sub-technique level · IOC extraction · CISA KEV · NCSC advisories · VirusTotal · OTX |
| **Network Analysis** | Wireshark · tshark · tcpdump · Suricata IDS · DNS enumeration · Packet forensics · TLS inspection |
| **Offensive Tools** | Nmap · Burp Suite · apktool · jadx · ADB · OWASP Top 10 / Mobile Top 10 |
| **Infrastructure** | Docker · Kali Linux ARM64 · UTM · Wazuh EDR |
| **Scripting** | Python · Bash · SPL · KQL · Sigma |

---

## Credentials

| Credential | Institution | Status |
|---|---|:---:|
| MSc Information Security | Royal Holloway, University of London (NCSC/GCHQ ACE-CSR) | ✅ Completed 2025 |
| Certified in Cybersecurity (CC) | ISC² | ✅ Active |
| CompTIA Security+ SY0-701 | CompTIA | 🔄 In Progress |
| Splunk Core Certified User | Splunk | 🎯 Planned Q2 2026 |

---

## Granger Security — YouTube

89 videos covering CVE analysis, threat intelligence, lab walkthroughs, and Security+ exam prep. Built for aspiring SOC analysts and career changers.

[![YouTube](https://img.shields.io/badge/▶_Watch-Granger_Security_(89_videos)-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Granger-Security)

Every investigation in this portfolio has a companion video. Links are in each case README.

---

## 2026 Roadmap

```
2025
 ├── ✅  MSc Information Security — Royal Holloway, University of London
 ├── ✅  ISC² Certified in Cybersecurity (CC)
 └── ✅  OZONE Shield — live AI scam detector (ozone-shield.netlify.app)

Q1–Q2 2026
 ├── 🔄  CompTIA Security+ SY0-701          ← active
 ├── 🔄  SOC Lab Programme — 9/76 complete  ← active
 └── 🔄  UK SOC Analyst job applications    ← active

Q2 2026
 ├── 🎯  Security+ passed
 ├── 🎯  Splunk Core Certified User
 └── 🎯  SOC Analyst role — UK market

Q3 2026
 ├── 🎯  Splunk Power User
 ├── 🎯  BTL1 / eJPT
 └── 🎯  Open-source Sigma contributions

2027
 ├── 🎯  CompTIA CySA+
 └── 🎯  Cloud Security — AZ-500 / AWS Security Specialty
```

---

## Contact

**Actively seeking SOC Analyst roles across the UK market.**

| | |
|---|---|
| LinkedIn | [linkedin.com/in/bhargav-baranda](https://www.linkedin.com/in/bhargav-baranda) |
| YouTube | [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security) |
| GitHub | [github.com/Granger0007](https://github.com/Granger0007) |
| Email | bbaranda055@gmail.com |

---

<div align="center">

*Built in public. Every rule, investigation, and writeup is free to use under the MIT License.*

![Labs](https://img.shields.io/badge/Labs_Complete-9-EE3124?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=for-the-badge)
![Commits](https://img.shields.io/badge/Commits-Building-brightgreen?style=for-the-badge)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:EE3124,50:1a1f2e,100:0d1117&height=100&section=footer"/>

</div>
