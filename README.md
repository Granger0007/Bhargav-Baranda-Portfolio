<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:EE3124&height=180&section=header&text=Security%20Operations%20Portfolio&fontSize=40&fontColor=ffffff&fontAlignY=38&desc=Bhargav%20Baranda%20%7C%20SOC%20Analyst%20%7C%20Detection%20Engineer&descSize=16&descAlignY=58&descColor=EE3124" />

[![ISC² CC](https://img.shields.io/badge/ISC²-Certified_in_Cybersecurity-00599C?style=for-the-badge&logoColor=white)](https://www.isc2.org/certifications/cc)
[![Security+](https://img.shields.io/badge/CompTIA-Security+_In_Progress-EE3124?style=for-the-badge)](https://www.comptia.org/certifications/security)
[![Royal Holloway](https://img.shields.io/badge/Royal_Holloway-MSc_Information_Security-003087?style=for-the-badge)](https://www.royalholloway.ac.uk)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-bhargav--baranda-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/bhargav-baranda)
[![YouTube](https://img.shields.io/badge/YouTube-Granger_Security-FF0000?style=flat-square&logo=youtube)](https://youtube.com/@Granger-Security)
[![Profile](https://img.shields.io/badge/GitHub-Granger0007-181717?style=flat-square&logo=github)](https://github.com/Granger0007)

</div>

---

## 🎯 What This Portfolio Demonstrates

This is not a collection of course exercises. Every investigation here was conducted in a purpose-built ARM64 home lab running enterprise-grade tooling. Every finding is MITRE ATT&CK mapped at sub-technique level. Every detection produces three rule formats — Sigma, SPL, and KQL — ready for deployment in a production SOC environment.

**The standard applied to every piece of work:**
- MITRE ATT&CK mapping — tactic → technique → sub-technique → observed procedure
- Detection triad — Sigma (SIEM-agnostic) + Splunk SPL + Microsoft Sentinel KQL
- Business impact assessment — systems affected, regulatory exposure, £ estimate
- Remediation playbook — 0–4hr containment, 24–72hr eradication, long-term prevention
- IOC package — IPs, domains, hashes with confidence ratings (Confirmed / Probable / Suspicious)

---

## 🖥️ ARM64 Security Lab

```
MacBook Pro (Apple Silicon M-series)
└── VirtualBox
    └── Kali Linux ARM64
        ├── 🔍 SIEM          → Splunk (Docker/containerised) + ELK Stack 8.x
        ├── 🛡️  IDS/EDR       → Suricata 7.x + Wazuh 4.x
        ├── 🔎 Analysis       → Wireshark, tcpdump, Nmap, Volatility
        ├── ⚙️  Detection Eng  → Sigma, SPL (Splunk), KQL (Microsoft Sentinel)
        └── 🐳 Infra          → Docker, £0 cloud spend
```

> **ARM64 challenge:** Most enterprise SOC tools ship x86_64 only. Every workaround in this lab is documented under [`/lab-setup/`](./lab-setup/) — reproducible by any analyst on Apple Silicon.

---

## 📂 Repository Structure

```
Bhargav-Baranda-Portfolio/
├── 📁 incidents/                  ← Documented SOC investigations
│   ├── template.md               ← Standard investigation template
│   └── [case-XXX]/               ← Individual cases
├── 📁 detection-rules/
│   ├── sigma/                    ← Sigma rules (SIEM-agnostic)
│   ├── splunk-spl/               ← SPL correlation searches
│   └── sentinel-kql/             ← KQL for Microsoft Sentinel
├── 📁 lab-setup/
│   ├── splunk-arm64/             ← Docker workaround documentation
│   ├── kali-virtualbox/          ← ARM64 setup guide
│   ├── suricata-ids/             ← IDS configuration
│   └── wazuh-setup/              ← SIEM/EDR integration
├── 📁 threat-intel/
│   ├── apt-profiles/             ← APT actor research writeups
│   └── campaign-analysis/        ← Specific campaign breakdowns
└── 📁 security-plus/
    ├── study-notes/              ← Domain-organised exam notes
    └── practice-scenarios/       ← Scenario-based Q&A
```

---

## 🔬 Incident Investigations

> Each investigation follows a standard template: executive summary → MITRE ATT&CK mapping → timeline → technical analysis → IOC package → detection rules → business impact → remediation playbook.

| Case | Title | MITRE Techniques | Severity | Status |
|:----:|-------|-----------------|:--------:|:------:|
| 001 | [Phishing → Initial Access Analysis](./incidents/001-phishing-initial-access/) | T1566.001, T1204.002 | 🟡 Medium | ✅ Complete |
| 002 | [TCP Traffic Anomaly Investigation](./incidents/002-tcp-traffic-analysis/) | T1071.001, T1095 | 🟡 Medium | ✅ Complete |
| 003 | [Network Segmentation Review](./incidents/003-network-segmentation/) | T1018, T1046 | 🟢 Low | ✅ Complete |
| 004–030 | *In progress — committing weekly* | — | — | 🔄 Building |

---

## ⚙️ Detection Rules

> All rules verified against MITRE ATT&CK. Each rule includes: true positive walkthrough, false positive identification, tuning guidance, and evasion gap analysis.

### Sigma Rules (SIEM-Agnostic)

| Rule | Technique | Status |
|------|-----------|:------:|
| [Suspicious PowerShell Execution](./detection-rules/sigma/) | T1059.001 | 🔄 In Progress |
| [LSASS Memory Access](./detection-rules/sigma/) | T1003.001 | 🔄 In Progress |
| [Lateral Movement via SMB](./detection-rules/sigma/) | T1021.002 | 🔄 In Progress |

### Splunk SPL Correlation Searches

| Search | Use Case | Status |
|--------|----------|:------:|
| [Brute Force Detection](./detection-rules/splunk-spl/) | T1110 | 🔄 In Progress |
| [Outbound DNS Tunnelling](./detection-rules/splunk-spl/) | T1071.004 | 🔄 In Progress |

### Microsoft Sentinel KQL

| Query | Use Case | Status |
|-------|----------|:------:|
| [Impossible Travel Detection](./detection-rules/sentinel-kql/) | T1078 | 🔄 In Progress |
| [Privileged Account Usage](./detection-rules/sentinel-kql/) | T1078.002 | 🔄 In Progress |

---

## 💼 Technical Capabilities

<table>
<tr>
<td width="50%" valign="top">

**SIEM Operations**
- Splunk SPL — search, stats, eval, rex, timechart
- ELK Stack 8.x — KQL queries, index management
- Alert triage and correlation search development
- Dashboard creation for SOC operational visibility

</td>
<td width="50%" valign="top">

**Detection Engineering**
- Sigma rule authoring (SIEM-agnostic, open source)
- Splunk SPL correlation searches
- Microsoft Sentinel KQL detection queries
- False positive tuning & evasion gap analysis

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Incident Response**
- Timeline reconstruction from multi-source logs
- Root cause analysis with evidence chain
- GDPR Article 33 — ICO 72hr notification assessment
- Remediation playbooks with time-bound phases

</td>
<td width="50%" valign="top">

**Threat Intelligence**
- MITRE ATT&CK mapping at sub-technique level
- IOC extraction: IPs, domains, hashes + confidence scoring
- APT actor profiling (APT29, Lazarus, FIN7)
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

Security operations content published for aspiring SOC analysts and career changers. 89 videos covering CVE analysis, threat intelligence, lab walkthroughs, and Security+ exam prep.

[![Watch on YouTube](https://img.shields.io/badge/▶_Watch-Granger_Security_(89_videos)-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Granger-Security)

Every significant lab investigation in this portfolio has a companion video. Links included in individual case READMEs.

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

*Every detection rule, investigation, and writeup in this portfolio is freely available under the MIT License.*
*Built in public. Documented for the community.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:EE3124,50:1a1f2e,100:0d1117&height=100&section=footer"/>

</div>
