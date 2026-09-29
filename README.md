<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:EE3124&height=180&section=header&text=Security%20Operations%20Portfolio&fontSize=40&fontColor=ffffff&fontAlignY=38&desc=Bhargav%20Baranda%20%C2%B7%20Security%2B%20%C2%B7%20ISC%C2%B2%20CC%20%C2%B7%20MSc%20Information%20Security&descSize=16&descAlignY=58&descColor=EE3124" />

[![ISC²](https://img.shields.io/badge/ISC²-Certified_in_Cybersecurity-00599C?style=for-the-badge&logoColor=white)](https://www.isc2.org/certifications/cc)
[![Security+](https://img.shields.io/badge/CompTIA-Security+_Certified-EE3124?style=for-the-badge)](https://www.comptia.org/certifications/security)
[![Royal Holloway](https://img.shields.io/badge/Royal_Holloway-MSc_Information_Security-003087?style=for-the-badge)](https://www.royalholloway.ac.uk)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhargav--baranda-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/bhargav-baranda)
[![YouTube](https://img.shields.io/badge/YouTube-Granger_Security-FF0000?style=flat-square&logo=youtube)](https://youtube.com/@Granger-Security)
[![GitHub](https://img.shields.io/badge/GitHub-Granger0007-181717?style=flat-square&logo=github)](https://github.com/Granger0007)

![Labs](https://img.shields.io/badge/Labs_Complete-10-EE3124?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Sub--technique_Level-orange?style=flat-square)
![Detection Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)

</div>

---

## What's in This Portfolio

**Latest:** [Wazuh SOC Lab](./projects/wazuh-soc-lab/) — a full SIEM build on a cloud server, with two custom detections and an automatic SSH block that caught real attackers from the internet.

The ten labs below come from my own ARM64 home lab. They're a mix of two kinds of work:

- **Hands-on labs** — real captures, scans and logs from my own machines: Wireshark, tshark, Nmap, dig, syslog and Windows event logs.
- **Scenario-based investigations** — a realistic attack traced end to end, to practise the analysis and the response.

What each write-up covers:

- **MITRE ATT&CK** mapping at sub-technique level — tactic → technique → sub-technique → what was observed
- **Detection rules** — in seven of the ten, the same logic written three ways: Sigma (SIEM-agnostic), Splunk SPL and KQL
- **Remediation** — containment, eradication and longer-term prevention, where the lab calls for it
- **Business impact** — systems affected and regulatory exposure (GDPR / ICO) for the investigations

---

## Home Lab

> Enterprise SOC tools assume x86_64. My machine is an Apple Silicon Mac (ARM64) with 8 GB of RAM.
> So light work runs locally, and anything SIEM-sized goes on a cloud server. Every workaround is documented, so anyone on Apple Silicon can reproduce it.

```
MacBook Pro — Apple Silicon M-series (ARM64, 8 GB)
└── UTM
    └── Kali Linux ARM64
        ├── Network         →  Wireshark 4.6.x · tshark · tcpdump · Nmap 7.99
        ├── IDS             →  Suricata 7.x
        ├── SIEM (local)    →  Splunk in Docker (x86 emulation)
        ├── Forensics       →  Volatility 3 · NetworkMiner
        ├── Detection Eng   →  Sigma · SPL · KQL
        └── Offensive       →  Burp Suite · apktool · jadx · ADB

Vultr cloud servers — 2 vCPU / 8 GB / London, one per project
├── Wazuh 4.x           →  Wazuh challenge, Sept 2026: server + Ubuntu agent  (deleted after submission)
└── Elastic Stack       →  Elastic challenge: Elasticsearch · Kibana · Sysmon  (in progress)
```

Setup guides: [Kali on UTM](./lab-setup/kali-utm/) · [Wazuh on a cloud server](./lab-setup/wazuh-setup/) · [Splunk on ARM64](./lab-setup/splunk-arm64/) · [Suricata](./lab-setup/suricata-ids/)

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

**Key:** 🔴 Investigation &nbsp;·&nbsp; 🔵 Lab &nbsp;·&nbsp; ✅ Complete &nbsp;·&nbsp; 🔄 In Progress

---

## MITRE ATT&CK Coverage

Techniques covered across the labs, grouped by tactic:

| Tactic | Techniques |
|---|---|
| Reconnaissance | T1590.002 · T1595.001 |
| Resource Development | T1584.004 |
| Initial Access | T1566.001 · T1190 · T1133 · T1078 |
| Execution | T1204.002 · T1059.005 |
| Defence Evasion | T1027 · T1036 · T1599 |
| Credential Access | T1110 · T1040 · T1557.002 |
| Discovery | T1046 · T1018 · T1040 |
| Lateral Movement | T1021.001 · T1021.002 · T1210 |
| Command and Control | T1071.001 · T1071.004 · T1573.001 · T1571 |
| Exfiltration | T1041 · T1048.003 |
| Impact | T1498.002 |

Coverage grows with every lab. Each case README maps its techniques to what was actually observed.

---

## Projects

| | Project | Description | Stack | Status |
|:-:|---------|-------------|-------|:------:|
| 🔎 | [Wazuh SOC Lab — MYDFIR Wazuh Challenge](./projects/wazuh-soc-lab/) | Wazuh SIEM on a cloud server with Windows and Linux agents, file integrity monitoring, two custom detections and an automatic SSH block that caught real attackers | Wazuh 4.14 · Vultr · UTM · Windows 11 ARM64 · Ubuntu 24.04 | ✅ Completed |
| 🛡️ | [OZONE Shield](https://github.com/Granger0007/ozone-shield) | Free AI scam checker — paste a suspicious message, get a verdict with a confidence score, reasons and next steps | Claude API · Cloudflare Workers · Cloudflare AI Gateway | 🟢 Live |

---

## Technical Skills

| Area | Skills |
|------|--------|
| **SIEM** | Wazuh (cloud deployment, custom rules) · Elastic / ELK · Splunk SPL — search, stats, eval, rex, timechart |
| **Detection Engineering** | Sigma · Splunk SPL · KQL · Wazuh custom rules · MITRE ATT&CK mapping · False-positive tuning |
| **Incident Response** | NIST SP 800-61r3 · Timeline reconstruction · Root cause analysis · GDPR Article 33 / ICO 72-hour reporting |
| **Threat Intelligence** | MITRE ATT&CK at sub-technique level · IOC extraction · CISA KEV · NCSC advisories · VirusTotal · OTX |
| **Network Analysis** | Wireshark · tshark · tcpdump · Suricata IDS · DNS enumeration · Packet analysis · TLS inspection |
| **Identity** | Microsoft Entra ID — MFA, Conditional Access, role-based access control |
| **Offensive Tools** | Nmap · Burp Suite · apktool · jadx · ADB · OWASP Top 10 / Mobile Top 10 |
| **Infrastructure** | Kali Linux ARM64 · UTM · Docker · Vultr cloud servers |
| **Languages** | Python · Bash · SPL · KQL · Sigma (YAML) |

---

## Credentials

| Credential | Institution | Status |
|---|---|:---:|
| MSc Information Security | Royal Holloway, University of London — NCSC-recognised ACE-CSR | ✅ Completed 2025 |
| CompTIA Security+ SY0-701 | CompTIA | ✅ Certified Aug 2026 |
| Certified in Cybersecurity (CC) | ISC² | ✅ Active |
| Splunk Core Certified User | Splunk | 🎯 Planned Q4 2026 |

---

## Granger Security — YouTube

230+ videos and Shorts since 2022 — daily explainer series on AI security, SOC analysis and Python, plus longer CVE breakdowns and Security+ content. Built for aspiring SOC analysts and career changers.

[![YouTube](https://img.shields.io/badge/▶_Watch-Granger_Security-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Granger-Security)

Companion videos for the investigations here are in production — each case README will link its video once it's live.

---

## Roadmap

```
2025
 ├── ✅  MSc Information Security — Royal Holloway, University of London
 └── ✅  ISC² Certified in Cybersecurity (CC)

Q1–Q2 2026
 ├── ✅  SOC Lab Programme — Labs 001–010
 └── ✅  OZONE Shield — live AI scam checker

Q3 2026
 ├── ✅  CompTIA Security+ SY0-701 — passed first attempt
 ├── ✅  MYDFIR Wazuh SOC Analyst Challenge
 ├── 🔄  MYDFIR Elastic SOC Challenge
 └── 🔄  UK SOC Analyst applications              ← active

Q4 2026
 ├── 🎯  Splunk Core Certified User
 ├── 🎯  Splunk Power User
 ├── 🎯  BTL1 / eJPT
 └── 🎯  Open-source Sigma contributions

2027
 ├── 🎯  CompTIA CySA+
 ├── 🎯  Cloud security — AZ-500 / AWS Security Specialty
 └── 🎯  Detection engineering specialism
```

---

## Contact

**Looking for an L1 / L2 SOC Analyst role anywhere in the UK.**

| | |
|---|---|
| LinkedIn | [linkedin.com/in/bhargav-baranda](https://www.linkedin.com/in/bhargav-baranda) |
| YouTube | [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security) |
| GitHub | [github.com/Granger0007](https://github.com/Granger0007) |
| Email | bbaranda055@gmail.com |

---

<div align="center">

*Built in public. Every rule, investigation and write-up is free to use under the MIT License.*

![Labs](https://img.shields.io/badge/Labs_Complete-10-EE3124?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=for-the-badge)
![Commits](https://img.shields.io/badge/Commits-Building-brightgreen?style=for-the-badge)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:EE3124,50:1a1f2e,100:0d1117&height=100&section=footer"/>

</div>
