# Wazuh 4.x — SIEM/EDR Setup

**Version:** Wazuh 4.x
**Platform:** Docker on Kali Linux ARM64

---

## Deployment — Docker Compose
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
docker-compose up -d
```

## Access
```
Wazuh Dashboard: https://localhost:443
Username: admin
Password: [set during setup]
```

## Integrations

- Suricata logs → Wazuh agent → forwarded to Splunk
- Windows event logs (if Windows VM added to lab)
- File integrity monitoring on Kali host

---

*Integration documentation expanded as lab exercises are completed.*
