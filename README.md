<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:EE3124&height=180&section=header&text=Security%20Operations%20Portfolio&fontSize=40&fontColor=ffffff&fontAlignY=38&desc=Bhargav%20Baranda%20%7C%20SOC%20Analyst%20%7C%20Detection%20Engineer&descSize=16&descAlignY=58&descColor=EE3124" />

[![ISC² CC](https://img.shields.io/badge/ISC²-Certified_in_Cybersecurity-00599C?style=for-the-badge&logoColor=white)](https://www.isc2.org/certifications/cc)
[![Security+](https://img.shields.io/badge/CompTIA-Security+_In_Progress-EE3124?style=for-the-badge)](https://www.comptia.org/certifications/security)
[![Royal Holloway](https://img.shields.io/badge/Royal_Holloway-MSc_Information_Security-003087?style=for-the-badge)](https://www.royalholloway.ac.uk)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhargav--baranda-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/bhargav-baranda)
[![YouTube](https://img.shields.io/badge/YouTube-Granger_Security-FF0000?style=flat-square&logo=youtube)](https://youtube.com/@Granger-Security)
[![Profile](https://img.shields.io/badge/GitHub-Granger0007-181717?style=flat-square&logo=github)](https://github.com/Granger0007)

![Investigations](https://img.shields.io/badge/Investigations-3_of_30-EE3124?style=flat-square)
![Detection Rules](https://img.shields.io/badge/Detection_Rules-Sigma_%7C_SPL_%7C_KQL-blue?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Sub--technique_Level-orange?style=flat-square)

</div>

---

## 🎯 What This Portfolio Demonstrates

This is not a collection of course exercises. Every investigation was conducted in a purpose-built ARM64 home lab running enterprise-grade tooling. Every finding is MITRE ATT&CK mapped at sub-technique level. Every detection produces three rule formats — Sigma, SPL, and KQL — ready for deployment in a production SOC environment.

**The standard applied to every piece of work:**

- MITRE ATT&CK mapping — tactic → technique → sub-technique → observed procedure
- Detection triad — Sigma (SIEM-agnostic) + Splunk SPL + Microsoft Sentinel KQL
- Business impact assessment — systems affected, regulatory exposure, £ estimate
- Remediation playbook — 0–4hr containment, 24–72hr eradication, long-term prevention
- IOC package — IPs, domains, hashes with confidence ratings

---

## 🖥️ ARM64 Security Lab

```
MacBook Pro (Apple Silicon M-series)
└── VirtualBox
    └── Kali Linux ARM64
        ├── 🔍 SIEM          → Splunk (Docker/containerised) + ELK Stack 8.x
        ├── 🛡️  IDS/EDR       → Suricata 7.x + Wazuh 4.x
        ├── 🔎 Analysis       → Wireshark, tcpdump, Nmap, Volatility
        ├── ⚙️  Detection Eng  → Sigma, SPL, KQL
        └── 🐳 Infra          → Docker containers, £0 cloud spend
```

> **ARM64 challenge:** Most enterprise SOC tools ship x86_64 only. Every workaround is documented under [`/lab-setup/`](./lab-setup/) — reproducible by any analyst on Apple Silicon.

---

## 🔬 Incident Investigations

> Each investigation: executive summary → MITRE ATT&CK mapping → full technical analysis → IOC package → detection triad → business impact → remediation playbook → interview answer.

| Case | Title | MITRE Techniques | Severity | Status |
|:----:|-------|-----------------|:--------:|:------:|
| [001](./incidents/case-001/) | [Spearphishing Attack — A Story in Seven Layers](./incidents/case-001/) | T1566.001, T1204.002, T1059.005, T1027, T1071.001, T1573.001 + 3 more | 🔴 High | ✅ |
| [002](./incidents/case-002/) | [TCP Traffic Analysis — SSL Stripping & C2 Beacon Detection](./incidents/case-002/) | T1040, T1071.001, T1557 | 🟡 Medium | ✅ |
| [003](./incidents/case-003/) | [Network Segmentation — Lateral Movement Detection](./incidents/case-003/) | T1021.002, T1018, T1210 | 🟢 Low | ✅ |
| 004–030 | *Active build — committing weekly* | — | — | 🔄 |

**Running total:** 3 investigations complete · 9 MITRE techniques mapped across first case alone · Detection triad deployed for every case

---

## ⚙️ Detection Rules

> All rules pass five quality gates before publication: true positive walkthrough, false positive identification, tuning guidance, evasion gap analysis, and coverage assessment.

### Sigma Rules — SIEM Agnostic

| Rule | Technique | Description | Status |
|------|-----------|-------------|:------:|
| [t1566-001-office-child-process.yml](./detection-rules/sigma/) | T1566.001 | Office application spawning suspicious child process | ✅ |

### Splunk SPL Correlation Searches

| Search | Technique | Description | Status |
|--------|-----------|-------------|:------:|
| [t1566-001-office-child-process.spl](./detection-rules/splunk-spl/) | T1566.001 | Office macro child process with risk scoring | ✅ |

### Microsoft Sentinel KQL

| Query | Technique | Description | Status |
|-------|-----------|-------------|:------:|
| [t1566-001-office-child-process.kql](./detection-rules/sentinel-kql/) | T1566.001 | Office macro execution — Defender for Endpoint | ✅ |

---

## 🔍 Lab Documentation

| Lab | Title | Focus | Tools | Status |
|:---:|-------|-------|-------|:------:|
| [004](./lab-setup/dns-enumeration/) | [DNS Enumeration — Interrogating the Internet](./lab-setup/dns-enumeration/) | Threat intelligence, reconnaissance methodology | dig, nslookup | ✅ |
| — | [Splunk on ARM64 — Docker Workaround](./lab-setup/splunk-arm64/) | SIEM deployment on Apple Silicon | Docker, QEMU | ✅ |
| — | [Kali Linux ARM64 — VirtualBox Setup](./lab-setup/kali-virtualbox/) | Lab infrastructure | VirtualBox | ✅ |
| — | [Suricata IDS Configuration](./lab-setup/suricata-ids/) | Network intrusion detection | Suricata 7.x | ✅ |
| — | [Wazuh EDR Setup](./lab-setup/wazuh-setup/) | Host-based detection | Wazuh 4.x | ✅ |

---

## 🧠 Threat Intelligence

| Resource | Description | Status |
|----------|-------------|:------:|
| [APT Actor Profiles](./threat-intel/apt-profiles/) | APT29, Lazarus Group, FIN7, LockBit — TTPs, targets, detection | 🔄 |
| [Campaign Analysis](./threat-intel/campaign-analysis/) | CVE-linked campaign breakdowns with IOC packages | 🔄 |

---

## 💼 Technical Capabilities

<table>
<tr>
<td width="50%" valign="top">

**SIEM Operations**
- Splunk SPL — search, stats, eval, rex, timechart
- ELK Stack 8.x — alert triage, index management
- Correlation search development
- Dashboard creation for SOC operational visibility

</td>
<td width="50%" valign="top">

**Detection Engineering**
- Sigma rule authoring — SIEM-agnostic, open source
- Splunk SPL correlation searches with risk scoring
- Microsoft Sentinel KQL detection queries
- False positive tuning & evasion gap analysis

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Incident Response**
- Timeline reconstruction from multi-source logs
- Root cause analysis with full evidence chain
- GDPR Article 33 — ICO 72hr notification assessment
- Remediation playbooks — 0–4hr / 24–72hr / long-term

</td>
<td width="50%" valign="top">

**Threat Intelligence**
- MITRE ATT&CK at sub-technique level
- DNS enumeration — 7-step SOC analyst workflow
- IOC extraction — IPs, domains, hashes + confidence scoring
- CISA KEV, NCSC advisories, GreyNoise, OTX enrichment

</td>
</tr>
</table>

---

## 🎓 Credentials & Education

| Credential | Institution | Status | Date |
|---|---|:---:|---|
| MSc Information Security | Royal Holloway, University of London | ✅ Completed | 2024–2025 |
| Certified in Cybersecurity (CC) | ISC² | ✅ Active | Jan 2025 |
| CompTIA Security+ SY0-701 | CompTIA | 🔄 In Progress | 2026 |
| Splunk Core Certified User | Splunk | 🎯 Planned | Q2 2026 |

---

## 📺 Granger Security — YouTube

Security operations content built for aspiring SOC analysts and career changers. 89 videos covering CVE analysis, threat intelligence briefs, lab walkthroughs, and Security+ exam prep.

[![Watch on YouTube](https://img.shields.io/badge/▶_Watch-Granger_Security_(89_videos)-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Granger-Security)

Every significant investigation in this portfolio has a companion video. Links in individual case READMEs.

---

## 🎯 2026 Roadmap

```
Q1 2026 — Foundation
 ├── ✅ MSc Information Security — Royal Holloway
 ├── ✅ ISC² Certified in Cybersecurity (CC)
 ├── 🔄 CompTIA Security+ SY0-701
 ├── 🔄 30 incident investigations (3 complete)
 └── 🔄 Detection rules — Sigma / SPL / KQL

Q2 2026 — Acceleration
 ├── 🎯 Security+ exam passed
 ├── 🎯 30 investigations complete
 ├── 🎯 Splunk Core Certified User
 └── 🎯 SOC Analyst role secured — UK market

Q3 2026 — Growth
 ├── 🎯 Splunk Power User
 ├── 🎯 Open-source Sigma contributions
 └── 🎯 OZONE Security — AI threat detection MVP
```

---

## 📬 Contact

| Channel | Details |
|---|---|
| 💼 LinkedIn | [linkedin.com/in/bhargav-baranda](https://www.linkedin.com/in/bhargav-baranda) |
| 📧 Email | bbaranda055@gmail.com |
| 📺 YouTube | [@Granger-Security](https://youtube.com/@Granger-Security) |
| 💻 GitHub | [github.com/Granger0007](https://github.com/Granger0007) |

**Actively seeking SOC Analyst roles across the UK market.**

---

<div align="center">

*Every detection rule, investigation, and writeup is freely available under the MIT License.*
*Built in public. Documented for the community.*

![Progress](https://img.shields.io/badge/Investigations-3%20%2F%2030-EE3124?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection_Rules-3_Live-blue?style=for-the-badge)
![Commits](https://img.shields.io/badge/Commits-30_and_counting-brightgreen?style=for-the-badge)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:EE3124,50:1a1f2e,100:0d1117&height=100&section=footer"/>

</div>
