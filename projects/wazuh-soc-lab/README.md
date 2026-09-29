<div align="center">

# 🛡️ Wazuh SOC Lab — MYDFIR Wazuh Challenge

**A working SIEM built from nothing in four days: two agents, a dashboard, file integrity monitoring, two custom detections and an automatic response — which blocked real attackers from the internet on its own.**

![Wazuh](https://img.shields.io/badge/Wazuh-4.14-005571?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed_16_Sept_2026-brightgreen?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1110_%7C_T1078.001-orange?style=flat-square)
![Cloud](https://img.shields.io/badge/Server-Vultr_London-007BFC?style=flat-square)

</div>

---

## 📋 Summary

| Field | Details |
|-------|---------|
| **Challenge** | MYDFIR Wazuh SOC Analyst Challenge (Steven Mah / MYDFIR) — seven videos, four deliverables |
| **Built** | 13–16 September 2026 · submitted before the deadline |
| **SIEM** | Wazuh 4.14 all-in-one (indexer, manager, dashboard) on Ubuntu 24.04 |
| **Agents** | Windows 11 Pro ARM64 (UTM on my Mac) · Ubuntu 24.04 (cloud) — agent v4.14.7 |
| **Detections** | Guest account enabled (rule 100200) · SSH brute force (rule 100101) + automatic firewall block |
| **Analyst** | Bhargav Baranda |

**What happened that I didn't plan:** once the SSH brute-force rule and its automatic response were live, the Linux agent, which sat on a public IP, started blocking **real attackers from the internet** by itself. The first one came within minutes. By the time I cleaned up, its firewall held three genuine external IPs alongside my own test IP.

---

## 🗺️ Architecture

```
MacBook Pro — Apple Silicon (ARM64, 8 GB RAM)
├── Chrome → Wazuh dashboard (HTTPS 443)
├── Terminal → SSH to both cloud servers
└── UTM
    └── Windows 11 Pro ARM64 (4 GB, 2 vCPU) ── Wazuh agent "Bhargav-Windows" ──┐
                                                                                │  1514 / 1515
Vultr, London                                                                   ▼
├── "wazuh"        2 vCPU / 8 GB / 120 GB NVMe · Ubuntu 24.04 · Wazuh 4.14 all-in-one
└── "ubuntu-agent" 1 vCPU / 2 GB                · Ubuntu 24.04 · Wazuh agent "Bhargav-Linux"
```

### Why it's built this way

The challenge videos run everything on one Windows PC in VMware. That wasn't possible here, for two hard reasons:

1. **Memory.** The video gives the Wazuh server 8 GB on its own. My Mac has 8 GB in total — and a Windows agent VM still has to run next to it.
2. **CPU architecture.** The video's Ubuntu ISO is x86. An Apple Silicon Mac virtualises ARM64, so that ISO won't even boot locally.

So the **server moved to the cloud**, running the exact x86 Ubuntu 24.04 and install commands from the video. The **Windows agent stayed local** in UTM as Windows 11 ARM64. The **Linux agent got its own small cloud server** too, because a second local VM would have gone past 8 GB again.

It ran on referral credit, and I deleted both servers the day after submitting, so they only cost money while they were in use.

---

## 🔧 Build

### 1. Server

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && bash ./wazuh-install.sh -a
```

The all-in-one install took about 2.5 minutes: indexer, manager, Filebeat and dashboard.

To search **every** event, not just ones that trigger alerts, the server has to archive everything. In 4.14 both settings were already on by default — I checked each one rather than assuming:

- `/var/ossec/etc/ossec.conf` → `<logall>yes</logall>` and `<logall_json>yes</logall_json>`
- `/etc/filebeat/filebeat.yml` → `archives: enabled: true`

Then an index pattern for `wazuh-archives-*` in Dashboard Management, with `timestamp` as the time field.

### 2. Two firewalls, not one

This caught me out, and it's a real-world lesson:

| Layer | What it needed |
|-------|----------------|
| **Vultr firewall group** | Inbound TCP **22** (SSH), **443** (dashboard), **1514** (agent events), **1515** (agent enrolment). Vultr drops everything not listed — leaving out 22 and 443 would have locked me out. |
| **UFW on Ubuntu** | Active by default and blocking everything except SSH. The Wazuh installer even warned about it. Fixed with `ufw allow 443/tcp`, `ufw allow 1514/tcp`, `ufw allow 1515/tcp`. |

**An open cloud firewall doesn't mean the operating system's firewall is open.** Both have to be checked.

### 3. Agents

Both agents were deployed with the dashboard's **Deploy new agent** wizard, which generates a ready-to-run install command with the server address and agent name built in.

One detail worth knowing: for this version the wizard's Windows start command was `NET START Wazuh`, while older generic docs say `WazuhSvc`. I trusted the command generated for my exact version, and it worked first time.

---

## 📊 Dashboard — "Basic SOC Activity Overview"

Three panels, built on the `wazuh-archives` index:

| Panel | Type | Query | Why it matters |
|-------|------|-------|----------------|
| **Failed Windows Logon** | Metric | `data.win.system.eventID:4625` | 4625 = failed logon. A sudden jump means password guessing. |
| **Windows Account Changes Over Time** | Line chart, split by event ID | `data.win.system.eventID: ("4720" OR "4722" OR "4723" OR "4724" OR "4725" OR "4726" OR "4732" OR "4733" OR "4738")` | Accounts created, enabled, reset, disabled, deleted or added to groups — the changes an attacker makes to stay in. |
| **Linux Failed SSH Authentication Activity** | Data table | `"Failed password"` on `Bhargav-Linux`, split by `data.srcuser`, `data.dstuser`, `data.srcip` | Who is trying to log in, as which user, from where. |

---

## 📁 File Integrity Monitoring

A monitored folder on each agent, watched in real time:

```xml
<!-- Windows agent: C:\Program Files (x86)\ossec-agent\ossec.conf -->
<directories realtime="yes">C:\Company Data</directories>

<!-- Linux agent: /var/ossec/etc/ossec.conf -->
<directories realtime="yes">/opt/company-data</directories>
```

**Tested both ways on both agents:** editing the test file raised *Integrity checksum changed*, and deleting it raised a delete event. On Linux, FIM had already recorded kernel and boot file changes from the system update — proof it was genuinely running before I touched it.

In a real estate this is how you'd spot tampering with sensitive files (ATT&CK **T1565.001** Stored Data Manipulation) or their deletion (**T1485** Data Destruction).

---

## 🚨 Detection 1 — Windows Guest Account Enabled (rule 100200)

The Guest account should stay disabled. If it gets switched on, someone may be opening a quiet way back in.

```xml
<group name="windows,windows_security,account_changed,adduser">
<rule id="100200" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4722$</field>
  <field name="win.eventdata.targetUserName">^Guest$</field>
  <description>MYDFIR-Bhargav Baranda Windows Guest account was enabled.</description>
  <mitre>
    <id>T1078</id>
  </mitre>
  <group>
    windows,
    windows_account_management,
    account_enabled,
    guest_account,
  </group>
</rule>
</group>
```

**What each part does:**

- `if_sid 60103` — builds on Wazuh's built-in Windows audit-success rule, so it only checks events Wazuh has already classified.
- `eventID ^4722$` — 4722 is "a user account was enabled". The anchors stop it matching 47220 or similar.
- `targetUserName ^Guest$` — only the Guest account, not every account being enabled.
- `level 12` — high severity, because this should never happen on a managed machine.
- **ATT&CK T1078** (Valid Accounts) — more precisely **T1078.001, Default Accounts**, since Guest is a built-in account.

**Tested:** enabled the Guest account in Computer Management. The rule **fired on the first attempt** — event 4722, target `Guest`, rule 100200 at level 12, with the MITRE tag attached.

> The challenge video's own build hit a field-name bug live. I used the corrected field names from the start, so there was nothing to debug.

---

## 🔒 Detection 2 + Response — SSH Brute Force, Blocked Automatically (rule 100101)

### The detection

```xml
<group name="local,syslog,sshd,authentication_failed,">
<rule id="100101" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>Multiple SSH login failures observed from the same source IP</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failed,ssh_bruteforce,credential_access,</group>
</rule>
</group>
```

- `if_matched_sid 5760` — builds on Wazuh's built-in "sshd: authentication failed" rule.
- `frequency="3" timeframe="120"` + `same_source_ip` — three failures from **one IP** inside **two minutes**. One mistyped password doesn't fire; a script does.
- **ATT&CK T1110** — Brute Force (Credential Access).

### The response

Wazuh's built-in `firewall-drop` command, tied to rule 100101 in the manager's `ossec.conf`. When the rule fires, the agent adds the attacker's IP to its own `iptables` block list. `agent_control -L` confirmed it was loaded: `firewall-drop0, command: firewall-drop`.

### The test

Before starting I kept Vultr's browser console open — a way back into the server if the rule blocked my own SSH session.

1. Continuous `ping` to the Linux agent in one terminal.
2. Three wrong SSH passwords from a second terminal.
3. **The ping stopped.** The agent had blocked my IP in real time.
4. The dashboard showed rule 100101 firing, tagged T1110, with my IP as the source.

### What it caught on its own

The Linux agent was on a public IP, so real attackers were already trying SSH passwords against it. With the rule live, **the active response blocked them without any input from me**. At clean-up, `iptables -L -n --line-numbers` showed four blocked IPs: my own test IP, and three genuine external attackers (for example `45.148.10.x`).

### Rolling back safely

1. Confirmed my own public IP with `curl ifconfig.me` **before** deleting anything, rather than guessing which rule was mine.
2. Removed my IP from the **INPUT** chain, then re-listed line numbers and removed it from **FORWARD** separately, because the chains number independently.
3. Left the three real attacker IPs blocked, deliberately.
4. The ping came back.

---

## 🧯 What Went Wrong — and What I Did

| Problem | Diagnosis | Outcome |
|---------|-----------|---------|
| **Three cloud providers fell through** before Vultr (trial credit too small, surprise prepayments, sign-up limits) | Checked each provider's real sign-up screens, not old guides | Vultr referral credit covered the whole build |
| **Vultr's defaults were traps** — IPv6-only networking, Ubuntu 26.04 preselected, a plan row with no storage attached, Block Storage as the boot default | Read the order summary before deploying | Enabled IPv4, picked 24.04 to match the install script, chose the plan with 120 GB local NVMe and Local Storage boot |
| **Dashboard wouldn't load in Safari** | `curl -kv` from the same Mac showed a clean TLS handshake and correct redirect — the server was fine, Safari's handling of the self-signed certificate wasn't | Used Chrome |
| **UFW blocking agent traffic** | Installer warning + checked `ufw status` | Opened 443, 1514, 1515 |
| **Sysmon: "This driver has been blocked from loading"** on Windows 11 ARM64 | Ruled out one cause at a time: virtualisation-based security wasn't running (checked with `Win32_DeviceGuard`), turned off the Vulnerable Driver Blocklist, turned off Smart App Control, rebuilt the VM clean — same block every time | **Unresolved.** Moved to Windows' native Event Log, which every deliverable could use. Kept a record of what not to retry. |
| **Stuck Sysmon service** (`sc.exe delete` → Access denied, even as admin) | The Service Control Manager caches its list until reboot | Deleted `HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64`, then rebooted |
| **Windows VM lost all network** mid-test | Adapter had a valid lease, but it couldn't even ping its own gateway `192.168.64.1` — the fault was in UTM's shared-network NAT, not Windows or Wazuh | Ran the brute-force test from two Mac terminals instead — same test, same result |

---

## 🔍 Findings

| Question | Answer |
|----------|--------|
| **Who** | External IPs brute-forcing SSH on `Bhargav-Linux`. The Guest account on `Bhargav-Windows` (enabled by me, as part of the exercise). |
| **What** | Repeated SSH authentication failures; Guest account enabled; monitored files changed and deleted (also part of the exercise). |
| **When** | 13–16 September 2026. The SSH attempts from the internet were ongoing for as long as the agent was online. |
| **Where** | SSH on the Linux agent · `C:\Company Data` on Windows · `/opt/company-data` on Linux |
| **Why** | The SSH activity matches automated password guessing against any public IP — opportunistic, not targeted. The Guest account and file changes were deliberate lab tests. |
| **How** | Password guessing over SSH · account change through Computer Management · direct file edits |

**Recommendations:** SSH key-only authentication (no passwords) · keep the automatic block, with a timeout so shared IPs don't stay blocked forever · disable the Guest account by Group Policy · restrict who can change `Company Data` · resolve the Sysmon driver block so process-level telemetry is available.

---

## 🧭 What I'd Do Next

- **Get Sysmon running** — try the Group Policy / Code Integrity policy route I didn't reach, so detections can see process creation and not just log-ons.
- **Tune rule 100101** — add a whitelist for known admin IPs so a tired engineer can't lock themselves out.
- **Alert on the attackers too** — the auto-blocked IPs are threat intelligence; enrich them (AbuseIPDB, VirusTotal) as part of the response.

---

## 🎤 Interview Answer

> *"Tell me about a detection you've built."*

"In the MYDFIR Wazuh challenge I built a SIEM from scratch — the server on a cloud VM because my Mac only has 8 GB of RAM, a Windows agent in UTM and a Linux agent in the cloud. I set up a Wazuh rule that fires when three SSH logins fail from the same IP within two minutes, tied it to Wazuh's firewall-drop active response, and tested it with a continuous ping from my Mac — when I failed three passwords, the ping stopped. The part I didn't expect was that the Linux agent was on a public IP, so within minutes it was blocking real attackers from the internet on its own. When I cleaned up, I confirmed my own IP first, removed only that from both iptables chains, and left the three real attackers blocked. The honest gap is Sysmon — the driver was blocked on Windows 11 ARM, and I worked through the documented causes before moving to the native event log so the deadline didn't slip."

---


<div align="center">

*Built for the MYDFIR Wazuh SOC Analyst Challenge — adapted for Apple Silicon.*

</div>
