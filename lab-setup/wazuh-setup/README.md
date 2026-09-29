# Wazuh 4.14 — Server Setup on a Cloud VM

**Platform:** Vultr cloud server (x86, Ubuntu 24.04 LTS) · agents on a Windows 11 ARM64 VM in UTM and a second Ubuntu server
**Why cloud:** an all-in-one Wazuh server wants about 8 GB of RAM — all the memory my Mac has — so the server can't run locally.

The full build, detections and results are in the project write-up: **[Wazuh SOC Lab — MYDFIR Wazuh Challenge](../../projects/wazuh-soc-lab/)**. This page is just the setup, as a checklist.

---

## 1. Create the server

| Setting | Value |
|---------|-------|
| Plan | 2 vCPU / 8 GB RAM / 120 GB local NVMe |
| Location | London |
| Image | **Ubuntu 24.04 LTS x64** — change it if a newer version is preselected, to match the install script |
| Boot | **Local Storage** (the plan's own disk) |
| Networking | Enable **public IPv4** as well as IPv6 |

---

## 2. Open the firewalls — both of them

**Cloud firewall group** — inbound TCP only:

| Port | Purpose |
|------|---------|
| 22 | SSH |
| 443 | Wazuh dashboard |
| 1514 | Agent events |
| 1515 | Agent enrolment |

Anything not listed is dropped, so leaving out 22 or 443 locks you out.

**UFW on Ubuntu** — on by default, and separate from the cloud firewall:

```bash
ufw allow 443/tcp
ufw allow 1514/tcp
ufw allow 1515/tcp
```

---

## 3. Install Wazuh

```bash
apt-get update && apt-get upgrade -y
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && bash ./wazuh-install.sh -a
```

About 2.5 minutes. The installer prints the `admin` password at the end — save it straight into a password manager.

Dashboard: `https://<server-ip>` — accept the self-signed certificate. **Use Chrome**: Safari failed to load it in this setup.

---

## 4. Archive every event, not just alerts

Check (in 4.14 these were already set, but confirm):

- `/var/ossec/etc/ossec.conf` → `<logall>yes</logall>` and `<logall_json>yes</logall_json>`
- `/etc/filebeat/filebeat.yml` → under `archives`, `enabled: true`

```bash
systemctl restart wazuh-manager
systemctl restart filebeat
```

Then in the dashboard: **Dashboard Management → Index Patterns → Create** → `wazuh-archives-*`, time field `timestamp`.

---

## 5. Add agents

Dashboard → **Agents → Deploy new agent**. Pick the OS, enter the server address and an agent name, and run the command it generates.

| Agent | Start command generated for 4.14.7 |
|-------|-------------------------------------|
| Windows (admin PowerShell) | `NET START Wazuh` |
| Ubuntu | `systemctl daemon-reload && systemctl enable wazuh-agent && systemctl start wazuh-agent` |

Use the wizard's command for your exact version — older docs name the Windows service `WazuhSvc`.

After editing an **agent's** `ossec.conf`, restart the **agent**, not the manager.

---

## 6. Clean up

Delete the servers when the project is finished — they cost money for as long as they exist, even when idle.
