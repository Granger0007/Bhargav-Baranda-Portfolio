<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:EE3124&height=180&section=header&text=Information%20Security%20Portfolio&fontSize=40&fontColor=ffffff&fontAlignY=38&desc=Bhargav%20Baranda%20%C2%B7%20Operations%20%2B%20Governance%20%C2%B7%20Security%2B%20%C2%B7%20ISC%C2%B2%20CC%20%C2%B7%20MSc%20Information%20Security&descSize=15&descAlignY=58&descColor=EE3124" />

[![ISC²](https://img.shields.io/badge/ISC²-Certified_in_Cybersecurity-00599C?style=for-the-badge&logoColor=white)](https://www.isc2.org/certifications/cc)
[![Security+](https://img.shields.io/badge/CompTIA-Security+_Certified-EE3124?style=for-the-badge)](https://www.comptia.org/certifications/security)
[![Royal Holloway](https://img.shields.io/badge/Royal_Holloway-MSc_Information_Security-003087?style=for-the-badge)](https://www.royalholloway.ac.uk)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhargav--baranda-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/bhargav-baranda)
[![YouTube](https://img.shields.io/badge/YouTube-Granger_Security-FF0000?style=flat-square&logo=youtube)](https://youtube.com/@Granger-Security)
[![GitHub](https://img.shields.io/badge/GitHub-Granger0007-181717?style=flat-square&logo=github)](https://github.com/Granger0007)

![Labs](https://img.shields.io/badge/Labs_Complete-13-EE3124?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-v20.0_·_Sub--technique_Level-orange?style=flat-square)
![Detection Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)
![Frameworks](https://img.shields.io/badge/Frameworks-ISO_27001_%7C_NIST_CSF_2.0_%7C_CE_v3.3-6f42c1?style=flat-square)

</div>


## Start here

If you have sixty seconds, read these three:

- **[Wazuh SOC Lab](./projects/wazuh-soc-lab/)** — I built a SIEM on a bare cloud server, wrote my own detection rules, and set up an automatic response that blocked real attackers from the internet. Including what I got wrong on the way.
- **[Case 001 — Spearphishing, A Story in Seven Layers](./incidents/case-001/)** — one attack traced from the email to the C2 channel, mapped to ATT&CK at sub-technique level, with the same detection logic written three ways.
- **[OZONE Shield](https://github.com/Granger0007/ozone-shield)** — a free AI scam checker I built and run in production. Paste a suspicious message, get a verdict with reasons. Security thinking applied to a live product, not just a lab.



## What's in This Portfolio

I'm working toward my first information security role — the all-round kind that covers **both halves** of the job: monitoring and incidents, *and* risk, controls and compliance. Most portfolios show one. This one shows both, because that's the work I want and it's what my background actually fits.

- **Operations** — the thirteen labs and the SIEM build below. Hands-on, from my own ARM64 home lab and cloud servers.
- **Governance** — frameworks studied to working depth, and my own lab mapped against them. See [Governance, Risk and Compliance](#governance-risk-and-compliance).

The thirteen labs are a mix of three kinds of work:

- **🔵 Labs** — real captures, scans and logs from my own machines (Wireshark, tshark, Nmap, dig, syslog and Windows event logs), plus real phishing emails from a public honeypot collection.
- **🔴 Investigations** — an attack traced end to end, from first signal to containment.
- **🟡 Analysis** — a security topic examined properly and written up, without an incident attached.

What each write-up covers:

- **MITRE ATT&CK** mapping at sub-technique level — tactic → technique → sub-technique → what was actually observed
- **Detection rules** — in seven of the thirteen, the same logic written three ways: Sigma (SIEM-agnostic), Splunk SPL and KQL
- **Remediation** — containment, eradication and longer-term prevention, where the lab calls for it
- **Business impact** — systems affected and regulatory exposure (UK GDPR, Information Commission reporting) for the investigations
- **What went wrong** — the dead ends, the broken builds and the rules that fired on my own activity. Every portfolio shows things working. This one shows the diagnosis too, because that's the part of the job nobody can teach you from a course.

> **On scope and authorisation.** Every scan, capture and test in this repository was carried out against systems I own and built myself. Nothing here was run against a third party. Under the Computer Misuse Act 1990 that distinction is the whole thing, and I treat it as a hard line rather than a footnote.



## Home Lab

> Enterprise security tools assume x86_64. My machine is an Apple Silicon Mac (ARM64) with 8 GB of RAM.
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
        ├── Vuln Mgmt       →  Trivy 0.76.1 · CISA KEV · FIRST EPSS
        └── Offensive       →  Burp Suite · apktool · jadx · ADB

Vultr cloud servers — 2 vCPU / 8 GB / London, one per project
├── Wazuh 4.14          →  Wazuh challenge, Sept 2026: server + Ubuntu agent  (deleted after submission)
└── Elastic Stack       →  Elastic challenge: Elasticsearch · Kibana · Sysmon  (signed up, not yet started)
```

Setup guides: [Kali on UTM](./lab-setup/kali-utm/) · [Wazuh on a cloud server](./lab-setup/wazuh-setup/) · [Splunk on ARM64](./lab-setup/splunk-arm64/) · [Suricata](./lab-setup/suricata-ids/)



## Lab Index

| # | Type | Title | Key Skills | Status |
|:-:|:----:|-------|-----------|:------:|
| 001 | 🔴 Investigation | [Spearphishing Attack — A Story in Seven Layers](./incidents/case-001/) | T1566.001 · T1204.002 · T1059.005 · T1027 · T1071.001 · T1573.001 · Sigma + SPL + KQL | ✅ |
| 002 | 🔴 Investigation | [TCP Traffic Analysis — SSL Stripping & C2 Beacon Detection](./incidents/case-002/) | T1040 · T1071.001 · T1557 · Wireshark packet analysis · Sigma + SPL + KQL | ✅ |
| 003 | 🔴 Investigation | [Network Segmentation — Lateral Movement Detection](./incidents/case-003/) | T1021.002 · T1018 · T1210 · Subnet boundary analysis · Sigma + SPL + KQL | ✅ |
| 004 | 🔵 Lab | [DNS Enumeration — Interrogating the Internet](./lab-setup/dns-enumeration/) | T1590.002 · T1498.002 · dig · nslookup · DNS record analysis · Threat intelligence | ✅ |
| 005 | 🔴 Investigation | [HTTP vs HTTPS — I Watched a Password Travel Across the Internet](./incidents/case-005/) | T1040 · T1557.002 · T1595.001 · Wireshark · Credential interception · TLS analysis | ✅ |
| 006 | 🟡 Analysis | [Twenty Doors — Port Security Analysis](./incidents/case-006/) | T1046 · T1021.001 · T1021.002 · T1048.003 · T1190 · T1133 · 20 ports risk-tiered | ✅ |
| 007 | 🟡 Analysis | [Firewall Architecture — The Invisible Walls Inside Every Network](./incidents/case-007/) | T1190 · T1021.002 · T1041 · T1571 · T1599 · Three-zone architecture · Default deny | ✅ |
| 008 | 🔵 Lab | [Nmap Port Scanning — What Attackers See in 30 Seconds](./lab-setup/nmap-labs/lab-008/) | T1046 · Nmap 7.99 · Wireshark · Service version detection · OS fingerprinting · VMware CVE probe | ✅ |
| 009 | 🔵 Lab | [Wireshark Deep Dive — Forensic PCAP Analysis](./lab-setup/wireshark-labs/lab-009/) | T1040 · T1557 · T1071 · tshark · TCP flag analysis · HTTP NSE extraction · SSH banner forensics | ✅ |
| 010 | 🔵 Lab | [Log Analysis Fundamentals](./lab-setup/log-analysis/lab-010/) | T1078 · T1110 · syslog · auth.log · Windows Event Logs · Event IDs 4624/4625/4688 | ✅ |
| 011 | 🔵 Lab | [Phishing Email Triage — Four Domains, No Microsoft](./lab-setup/email-analysis/lab-011/) | T1598 · T1684.001 · T1589.002 · SPF/DKIM/DMARC · Header forensics · WHOIS & reputation · KQL + SPL | ✅ |
| 012 | 🔴 Investigation | [A Recruitment Scam That Targeted Me](./lab-setup/email-analysis/lab-012/) | T1598 · T1684.001 · T1583.001 · T1585.002 · T1593.001 · SPF vs DMARC alignment · Domain age (WHOIS) · AI-text fingerprint · KQL + SPL | ✅ |
| 013 | 🔵 Lab | [Vulnerability Management — 121 Findings, 14 That Matter](./lab-setup/vuln-management/lab-013/) | Trivy · Container image + SCA · CVSS vs EPSS vs CISA KEV · Risk-based prioritisation · Model regression test · Remediation tickets · ISO 27001 A.8.8 | ✅ |

**Key:** 🔴 Investigation &nbsp;·&nbsp; 🟡 Analysis &nbsp;·&nbsp; 🔵 Lab &nbsp;·&nbsp; ✅ Complete &nbsp;·&nbsp; 🔄 In Progress



## MITRE ATT&CK Coverage

Mapped against **ATT&CK v20.0 (released 13 October 2026)**.

> **Note on the matrix:** ATT&CK v19 (April 2026) restructured the Enterprise matrix from 14 tactics to 15, and v20 keeps that structure. The old *Defense Evasion* tactic was split into **Stealth (TA0005)** — hiding activity by appearing to be normal behaviour — and a new **Defense Impairment (TA0112)** — breaking the defender's tooling, pipelines and visibility. Most published material still shows the old 14-tactic matrix.

| Tactic | Techniques |
|---|---|
| Reconnaissance (TA0043) | T1590.002 · T1595.001 · T1598 · T1589.002 · T1593.001 |
| Resource Development (TA0042) | T1584.004 · T1583.001 · T1585.002 |
| Initial Access (TA0001) | T1566.001 · T1190 · T1133 · T1078 |
| Execution (TA0002) | T1204.002 · T1059.005 |
| Stealth (TA0005) | T1027 · T1036 · T1684.001 |
| Defense Impairment (TA0112) | T1599 |
| Credential Access (TA0006) | T1110 · T1040 · T1557.002 |
| Discovery (TA0007) | T1046 · T1018 · T1040 |
| Lateral Movement (TA0008) | T1021.001 · T1021.002 · T1210 |
| Command and Control (TA0011) | T1071.001 · T1071.004 · T1573.001 · T1571 |
| Exfiltration (TA0010) | T1041 · T1048.003 |
| Impact (TA0040) | T1498.002 |

Coverage grows with every lab. Each case README maps its techniques to what was actually observed.



## Governance, Risk and Compliance

Security operations tells you what happened. Governance decides whether it should have been possible, and proves the controls work. An information security analyst needs both, so I've studied the governance side to working depth rather than exam depth.

| Framework | Depth | Where it shows up |
|---|---|:---:|
| **ISO/IEC 27001:2022** | Clauses 4–10 and all 93 Annex A controls, by theme | Control mapping (below) |
| **NIST CSF 2.0** | All six functions including Govern, down to category level | Control mapping (below) |
| **Cyber Essentials v3.3** | All five technical controls and the v3.3 automatic-fail conditions | Control mapping (below) |
| **NCSC CAF v4.0** | Four objectives, fourteen principles | Public sector and essential services |
| **UK GDPR / DPA 2018** | Article 33 breach reporting, Article 35 DPIAs, the 72-hour clock | Business impact in every investigation |
| **NIST SP 800-61 Rev. 3** | The incident lifecycle, as recast against CSF 2.0 | Incident write-ups |

**🔄 In progress — Control Mapping:** every component of my Wazuh and Entra ID lab mapped to the ISO 27001 Annex A control, NIST CSF 2.0 function and Cyber Essentials control it satisfies, with the evidence that would prove it to an auditor and an honest list of the gaps it doesn't cover.

**🎯 Next — OZONE Shield DPIA:** a data-flow map and data protection impact assessment for my own live product. Written as a genuine DPIA for a real thing I run, not a template exercise.



## Projects

| | Project | Description | Stack | Status |
|:-:|---------|-------------|-------|:------:|
| 🔎 | [Wazuh SOC Lab — MYDFIR Wazuh Challenge](./projects/wazuh-soc-lab/) | Wazuh SIEM on a cloud server with Windows and Linux agents, file integrity monitoring, two custom detections and an automatic SSH block that caught real attackers | Wazuh 4.14 · Vultr · UTM · Windows 11 ARM64 · Ubuntu 24.04 | ✅ Completed |
| 🛡️ | [OZONE Shield](https://github.com/Granger0007/ozone-shield) | Free AI scam checker I built and run — paste a suspicious message, get a verdict with a confidence score, reasons and next steps | Claude API · Cloudflare Workers · Cloudflare AI Gateway | 🟢 Live |



## Technical Skills

> Everything below is **lab, project and study experience.** I haven't held a security job yet — that's the thing I'm looking for. I'd rather tell you that here than have you find out in the interview.

| Area | Skills |
|------|--------|
| **SIEM** | Wazuh (cloud deployment, custom rules) · Elastic / ELK (KQL queries; full stack build is next) · Splunk SPL — search, stats, eval, rex, timechart |
| **Detection Engineering** | Sigma · Splunk SPL · KQL · Wazuh custom rules · MITRE ATT&CK mapping · False-positive tuning |
| **Incident Response** | NIST SP 800-61r3 · Timeline reconstruction · Root cause analysis · UK GDPR Article 33 / 72-hour reporting |
| **Governance & Compliance** | ISO/IEC 27001:2022 · NIST CSF 2.0 · Cyber Essentials v3.3 · NCSC CAF v4.0 · UK GDPR · PCI DSS |
| **Threat Intelligence** | MITRE ATT&CK at sub-technique level · IOC extraction · CISA KEV · NCSC advisories · VirusTotal · OTX |
| **Network Analysis** | Wireshark · tshark · tcpdump · Suricata IDS · DNS enumeration · Packet analysis · TLS inspection |
| **Identity** | Microsoft Entra ID — MFA, Conditional Access, role-based access control |
| **Offensive Tools** | Nmap · Burp Suite · apktool · jadx · ADB · OWASP Top 10 / Mobile Top 10 |
| **Infrastructure** | Kali Linux ARM64 · UTM · Docker · Vultr cloud servers |
| **Languages** | Python · Bash · SPL · KQL · Sigma (YAML) |



## Credentials

| Credential | Institution | Status |
|---|---|:---:|
| MSc Information Security | Royal Holloway, University of London — NCSC-recognised ACE-CSR | ✅ Completed 2025 |
| CompTIA Security+ SY0-701 | CompTIA | ✅ Certified Aug 2026 |
| Certified in Cybersecurity (CC) | ISC² | ✅ Active |



## Granger Security — YouTube

230+ videos and Shorts since 2022 — daily explainer series on AI security, security analysis and Python, plus longer CVE breakdowns and Security+ content. Built for people changing career into security, which is the thing I wish had existed when I started.

[![YouTube](https://img.shields.io/badge/▶_Watch-Granger_Security-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Granger-Security)

Companion videos for the investigations here are in production — each case README will link its video once it's live.



## Roadmap

```
2025
 ├── ✅  MSc Information Security — Royal Holloway, University of London
 └── ✅  ISC² Certified in Cybersecurity (CC)

Q1–Q2 2026
 ├── ✅  Security Lab Programme — Labs 001–010
 └── ✅  OZONE Shield — live AI scam checker

Q3 2026
 ├── ✅  CompTIA Security+ SY0-701 — passed first attempt
 ├── ✅  MYDFIR Wazuh SOC Analyst Challenge
 └── 🔄  UK information security applications        ← active

Q4 2026
 ├── 🔄  Control mapping — my lab against ISO 27001, NIST CSF 2.0, Cyber Essentials
 ├── ✅  Lab 011 — Phishing email triage on real honeypot samples
 ├── ✅  Lab 012 — Live recruitment scam that targeted me, triaged and reported to the NCSC
 ├── ✅  Lab 013 — Vulnerability management: Trivy scans prioritised with CVSS, EPSS and CISA KEV
 ├── 🎯  OZONE Shield DPIA — data-flow map and impact assessment
 └── 🎯  Open-source Sigma contributions

2027 — once earning
 ├── 🎯  Microsoft SC-200 (studying the free Learn paths now)
 ├── 🎯  Splunk Core Certified User
 ├── 🎯  ISO/IEC 27001 Lead Implementer or Lead Auditor
 └── 🎯  Cloud security — AZ-500 / AWS Security Specialty
```



## Contact

**Looking for my first information security role in the UK** — Information Security Analyst, SOC Analyst (L1), or security GRC. Open to anywhere in the UK, and available immediately.

I have full right to work in the UK with no sponsorship needed to start.

| | |
|---|---|
| LinkedIn | [linkedin.com/in/bhargav-baranda](https://www.linkedin.com/in/bhargav-baranda) |
| YouTube | [youtube.com/@Granger-Security](https://youtube.com/@Granger-Security) |
| GitHub | [github.com/Granger0007](https://github.com/Granger0007) |




<div align="center">

*Built in public. Every rule, investigation and write-up is free to use under the MIT License.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:EE3124,50:1a1f2e,100:0d1117&height=100&section=footer"/>

</div>
