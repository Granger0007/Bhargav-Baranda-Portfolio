# Lab 010 — Log Analysis Fundamentals
## SSH Brute Force Detection via journalctl

**Date:** 30 April 2026
**Author:** Bhargav (Granger) Baranda
**Environment:** Kali Linux ARM64 · UTM · MacBook Pro Apple Silicon
**Tools:** journalctl · grep · systemd · PAM
**MITRE ATT&CK:** T1110 — Brute Force · T1078 — Valid Accounts
**Security+ Objectives:** SY0-701 2.2 · 4.1 · 4.3
**Tier:** Tier 1 — Foundations (Final Lab)
**Status:** ✅ Complete

---

## Executive Summary

Log analysis is the most fundamental skill a SOC analyst possesses. Every alert triaged, every incident investigated, every threat hunted — it all starts with reading logs. This lab built that foundation through deliberate generation of a brute force attack pattern followed by forensic investigation of the resulting log evidence across three independent log layers.

SSH was started on Kali Linux ARM64, six failed login attempts were generated across two sessions (simulating T1110 Brute Force), followed by a successful login (T1078 Valid Accounts). The complete attack timeline was reconstructed using journalctl and grep, demonstrating exactly how a SIEM ingests and correlates multiple log sources simultaneously.

**Key findings:**
- 6 failed SSH login attempts confirmed in journald logs
- Successful login captured immediately after brute force — T1110 → T1078 chain confirmed
- Three independent log layers (SSH, PAM, systemd) all recorded the same events
- Every sudo command logged with exact username, command, and working directory
- CRON job proximity to successful login identified as a persistence investigation trigger

---

## Legal and Ethical Framework

All activity was performed on a personal Kali Linux machine. No external systems were targeted. All commands were run with explicit understanding of their scope and reversibility.

---

## Environment

```
OS:       Kali Linux ARM64 (kernel 6.19.11+kali-arm64)
Host:     MacBook Pro Apple Silicon (M-series)
VM:       UTM Virtualisation
Log:      systemd-journald (no /var/log/auth.log on this build)
SSH:      OpenSSH 10.2p1 Debian 6
```

**Note on ARM64 Kali:** Traditional `/var/log/auth.log` does not exist on this build. Authentication events are stored in systemd-journald and accessed via `journalctl`. All commands in this lab use journalctl — the output is identical to auth.log content.

---

## The Three Log Sources

### 1. journald / auth.log (Linux Authentication)

Records every authentication event: SSH logins, PAM results, sudo commands, su attempts. The first place a SOC analyst looks when investigating suspicious access on a Linux machine.

```
Normal:    Accepted password for granger from 192.168.64.1 port 22
Attack:    Failed password for root from 45.33.32.156 port 22
           Failed password for root from 45.33.32.156 port 22
           [× 10,000]
```

### 2. syslog (General System Events)

Records everything beyond authentication — service starts/stops, kernel messages, cron execution, application errors. Cross-referencing with auth events builds the complete incident picture.

### 3. Windows Event Viewer (Reference)

The Windows equivalent. Every login, process creation, scheduled task, and account change recorded with a specific Event ID.

| Event ID | Meaning |
|---|---|
| 4624 | Successful login |
| 4625 | Failed login — brute force indicator |
| 4648 | Login with explicit credentials — lateral movement |
| 4688 | New process created — malware execution |
| 4698 | Scheduled task created — persistence |
| 4720 | New user account created — backdoor account |

---

## Lab Steps

### Step 1 — Confirm Log Source

```bash
ls /var/log/
```

No `/var/log/auth.log` present. Confirmed journald is the log source.

```bash
sudo journalctl _SYSTEMD_UNIT=ssh.service --no-pager | tail -20
```

**Output revealed Lab 008 historical data:**
- SSH service start (21:04:36 22 Apr)
- Nmap NSE protocol negotiation failures
- SSH service stop via SIGTERM (21:36:34 22 Apr)

This established the baseline before generating new events.

---

### Step 2 — Generate the Attack Pattern

```bash
sudo systemctl start ssh

# Generate failed attempts (brute force simulation)
ssh wronguser@localhost   # 3 attempts, wrong password — session 1
ssh wronguser@localhost   # 3 attempts, wrong password — session 2

# Generate successful login (compromise simulation)
ssh granger@localhost     # correct password

exit
sudo systemctl stop ssh
```

---

### Step 3 — Extract the Evidence

**Targeted SSH log query:**
```bash
sudo journalctl _SYSTEMD_UNIT=ssh.service --no-pager | \
  grep -i "wronguser\|granger\|failed\|accepted\|invalid" | tail -30
```

**Full syslog cross-reference:**
```bash
sudo journalctl --no-pager | grep "Apr 30 11:2" | \
  grep -E "Failed|Accepted|Invalid|session opened|session closed" | \
  grep -v "CRON\|sudo"
```

**Programmatic count:**
```bash
sudo journalctl --no-pager | grep "Apr 30" | grep -c "Failed password"
# Result: 6
```

---

## Log Evidence — Full Analysis

### The Raw Evidence

```
Apr 30 11:22:04  Invalid user wronguser from ::1 port 59674
Apr 30 11:22:12  Failed password for invalid user wronguser from ::1 port 59674 ssh2
Apr 30 11:22:20  Failed password for invalid user wronguser from ::1 port 59674 ssh2
Apr 30 11:22:28  Failed password for invalid user wronguser from ::1 port 59674 ssh2
Apr 30 11:22:30  Connection closed by invalid user wronguser ::1 port 59674 [preauth]
Apr 30 11:23:25  Invalid user wronguser from ::1 port 48442
Apr 30 11:23:31  Failed password for invalid user wronguser from ::1 port 48442 ssh2
Apr 30 11:23:38  Failed password for invalid user wronguser from ::1 port 48442 ssh2
Apr 30 11:23:46  Failed password for invalid user wronguser from ::1 port 48442 ssh2
Apr 30 11:23:46  Connection closed by invalid user wronguser ::1 port 48442 [preauth]
Apr 30 11:24:33  Accepted password for granger from ::1 port 58580 ssh2
Apr 30 11:24:33  pam_unix(sshd:session): session opened for user granger(uid=1000)
```

### Line-by-Line Decoding

**`Invalid user wronguser from ::1 port 59674`**

The username `wronguser` does not exist in the system's user database. SSH identifies this before checking the password. This is the **username enumeration phase** — the attacker is probing which usernames exist on the system.

**`Failed password for invalid user wronguser`**

Despite the username not existing, the attacker submitted a password. SSH deliberately delays rejection until after the password prompt — this prevents timing-based username enumeration. All rejections take the same time regardless of whether the username is valid.

**`Connection closed by invalid user wronguser [preauth]`**

`[preauth]` is a critical forensic marker:

```
[preauth] present:  Connection closed BEFORE authentication succeeded.
                    Attacker did not get in on this attempt.

[preauth] absent:   Connection progressed past authentication.
                    Something happened after login — investigate immediately.
```

In a brute force investigation: hundreds of `[preauth]` entries = attack in progress. A single entry WITHOUT `[preauth]` following the failures = the attack succeeded.

**`Accepted password for granger from ::1 port 58580 ssh2`**

The attack succeeded. Valid username + correct password. This is the **T1078 Valid Accounts** event. One minute elapsed between last failed attempt (11:23:46) and success (11:24:33). The attacker switched from `wronguser` to `granger` — either they had credentials already (credential stuffing) or identified `granger` through prior enumeration.

**`pam_unix(sshd:session): session opened for user granger(uid=1000)`**

PAM confirmed the session at the OS level. uid=1000 = standard user account. This is the **second independent confirmation** of the successful login from a completely separate subsystem.

---

## The Three-Layer Correlation

One successful login recorded by four independent systems simultaneously:

| Layer | Log Entry |
|---|---|
| SSH | `Accepted password for granger from ::1 port 58580 ssh2` |
| PAM | `pam_unix(sshd:session): session opened for user granger(uid=1000)` |
| systemd-logind | `New session '8' of user 'granger' with class 'user'` |
| systemd kernel | `Started session-8.scope - Session 8 of User granger` |

A sophisticated attacker who deletes the SSH log still leaves traces in PAM, systemd-logind, and the kernel audit layer. Destroying all four simultaneously — without trace — is extremely difficult.

---

## CRON Proximity — Persistence Indicator

```
11:25:01  CRON: pam_unix(cron:session): session opened for user root
11:25:01  CRON: pam_unix(cron:session): session closed for user root
```

A root cron job ran exactly one minute after the successful login. In this lab it was a legitimate system task. In a real investigation, this proximity triggers an immediate persistence check:

```bash
cat /etc/crontab
ls -la /etc/cron.d/
sudo crontab -l
crontab -l -u granger
ls -la /var/spool/cron/crontabs/
```

MITRE T1053.003 — Cron is one of the most common persistence mechanisms after initial SSH access.

---

## The Analyst Audit Trail

```
11:26:50  sudo: granger : TTY=pts/1 ; PWD=/home/granger ;
          USER=root ; COMMAND=/usr/bin/journalctl
```

Every sudo command logged with: who (granger), from which terminal (pts/1), in which directory, as which user (root), and the exact command. This creates an immutable analyst audit trail — proof of investigation actions for compliance and legal purposes.

---

## Complete Incident Timeline

| Timestamp | Event |
|---|---|
| 11:22:04 | SSH service listening |
| 11:22:04 | First brute force session — Invalid user wronguser |
| 11:22:12 | Failed password attempt 1 [preauth] |
| 11:22:20 | Failed password attempt 2 [preauth] |
| 11:22:28 | Failed password attempt 3 [preauth] |
| 11:22:30 | Connection closed [preauth] |
| 11:23:25 | Second brute force session — Invalid user wronguser |
| 11:23:31 | Failed password attempt 4 [preauth] |
| 11:23:38 | Failed password attempt 5 [preauth] |
| 11:23:46 | Failed password attempt 6 [preauth] |
| 11:23:46 | Connection closed [preauth] |
| **11:24:33** | **⚠️ COMPROMISE — Accepted password for granger** |
| 11:24:33 | PAM session opened uid=1000 |
| 11:24:33 | systemd-logind: New session 8 |
| 11:24:33 | systemd: session-8.scope started |
| 11:25:01 | CRON job ran as root — check for persistence |
| 11:26:50 | Analyst sudo journalctl — investigation begins |
| 11:46:10 | SSH service stopped |

**Total attack duration: 2 minutes 29 seconds from first probe to successful compromise.**

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Credential Access · Initial Access |
| T1110 | Brute Force — 6 failed attempts across 2 sessions |
| T1078 | Valid Accounts — successful login after brute force |
| Sub-technique | T1110.001 — Password Guessing |
| Evidence | journald: Failed password, Invalid user, Accepted password |
| Detection | Count of Failed password > 5 from same source within 10 min |
| Follow-on | T1053.003 — Cron persistence (proximity of CRON entry) |

---

## Detection Engineering

### Sigma Rule

```yaml
title: SSH Brute Force Attack Detected
id: d2e3f4a5-b6c7-8d9e-0f1a-2b3c4d5e6f7a
status: production
description: Detects SSH brute force followed by successful
             authentication — T1110 leading to T1078
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://attack.mitre.org/techniques/T1078/
author: Granger Baranda
date: 2026-04-30
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1078
logsource:
  product: linux
  service: auth
detection:
  brute_force:
    keywords:
      - 'Failed password'
      - 'Invalid user'
  timeframe: 10m
  condition: brute_force | count() > 5
falsepositives:
  - Legitimate users mistyping passwords repeatedly
  - Automated systems with misconfigured credentials
level: high
```

### Splunk SPL

```spl
index=linux_logs sourcetype=journald
| where message like "%Failed password%"
  OR message like "%Invalid user%"
| rex field=message "from (?<src_ip>\S+) port"
| bin _time span=10m
| stats count as failures by _time src_ip
| where failures > 5
| join src_ip
  [search index=linux_logs "Accepted password"
   | rex field=message "for (?<user>\S+) from (?<src_ip>\S+)"
   | table src_ip user]
| eval alert="Brute force succeeded — T1110 to T1078"
| table _time src_ip user failures alert
```

### Microsoft Sentinel KQL

```kql
Syslog
| where SyslogMessage has_any ("Failed password", "Invalid user")
| parse SyslogMessage with * "from " src_ip " port" *
| summarize
    FailureCount = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt  = max(TimeGenerated)
    by src_ip, bin(TimeGenerated, 10m)
| where FailureCount > 5
| join kind=inner (
    Syslog
    | where SyslogMessage has "Accepted password"
    | parse SyslogMessage with * "for " username " from " src_ip " port" *
    | project src_ip, username, SuccessTime = TimeGenerated
  ) on src_ip
| where SuccessTime > LastAttempt
| project FirstAttempt, src_ip, username, FailureCount, SuccessTime
| order by SuccessTime desc
```

---

## Critical Log Entry Reference

| Log Entry | Meaning |
|---|---|
| `Invalid user [x] from [IP]` | Username does not exist. Enumeration phase. |
| `Failed password for invalid user [x]` | Attempt against non-existent user. T1110 in progress. |
| `Failed password for [x] from [IP]` | Attempt against VALID username. Escalated risk. |
| `Connection closed [preauth]` | Attacker did not get in on this attempt. |
| `Accepted password for [x] from [IP]` | Successful login. T1078. Investigate immediately. |
| `pam_unix: session opened uid=1000` | PAM confirmed session. Second independent log layer. |
| `systemd-logind: New session` | OS session created. Third confirmation layer. |
| `sudo: [user] COMMAND=[cmd]` | Privileged command. Exact command recorded. |
| `CRON: session opened for root` | Scheduled task. Check proximity to login for persistence. |

---

## SOC Analyst Response Workflow

```
Step 1 — IDENTIFY
grep for "Failed password" and "Accepted password"
Count failures per source IP per time window
Locate the compromise point

Step 2 — TIMELINE
Extract all events from suspect IP
Reconstruct: probe → brute force → success → session

Step 3 — ASSESS IMPACT
Check: new cron jobs, new files, sudo commands,
       outbound connections, new user accounts

Step 4 — CONTAIN
Kill active session, block source IP,
disable compromised account, change credentials

Step 5 — ERADICATE
Remove attacker persistence, patch vulnerability

Step 6 — DOCUMENT
Full timeline, MITRE mapping, incident report
```

---

## Security+ Connection

| Objective | Coverage |
|---|---|
| SY0-701 4.3 | Log analysis, timeline reconstruction, evidence extraction |
| SY0-701 2.2 | Brute force as credential attack vector |
| SY0-701 4.1 | journalctl and grep as log analysis tools |
| SY0-701 4.4 | Incident response — containment and eradication |

---

## Lab Connections

| Lab | Connection |
|---|---|
| Lab 002 | Each 'Failed password' maps to a TCP conversation — SYN, SYN-ACK, RST |
| Lab 008 | Historical Lab 008 SSH session visible in journald months later |
| Lab 009 | TCP flag distribution from Lab 009 maps to [preauth] closures here |

---

## Files in This Lab

```
lab-setup/log-analysis/lab-010/
└── README.md    ← This file
```

---

## Commit Message

```
Add Lab-010: Log analysis fundamentals — SSH brute force
detection via journalctl, PAM and systemd log correlation,
T1110 Brute Force + T1078 Valid Accounts — 30 April 2026
```

---

## Tier 1 Complete

| Lab | Topic | Status |
|:-:|---|:---:|
| 001 | OSI Model & Phishing Analysis | ✅ |
| 002 | Wireshark TCP Handshake | ✅ |
| 003 | Subnetting | ✅ |
| 004 | DNS Enumeration | ✅ |
| 005 | HTTP/HTTPS & TLS | ✅ |
| 006 | Ports & Protocols | ✅ |
| 007 | Firewalls & DMZ | ✅ |
| 008 | Nmap Port Scanning | ✅ |
| 009 | Wireshark Deep Dive | ✅ |
| 010 | Log Analysis Fundamentals | ✅ |

**Tier 2 — Detection Engineering begins next.**

---

*Lab 010 complete — 30 April 2026*
*Granger Baranda | MSc Information Security — Royal Holloway, University of London*
*[github.com/Granger0007](https://github.com/Granger0007) | [Granger Security (YouTube)](https://youtube.com/@Granger-Security)*
