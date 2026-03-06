# Suricata IDS — Configuration & Lab Setup

**Version:** Suricata 7.x
**Platform:** Kali Linux ARM64

---

## Installation
```bash
sudo apt update
sudo apt install -y suricata
sudo suricata-update
```

## Basic Configuration

Edit `/etc/suricata/suricata.yaml`:
```yaml
# Set your network interface
af-packet:
  - interface: eth0

# Home network definition
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

## Start Suricata
```bash
sudo systemctl enable suricata
sudo systemctl start suricata

# Verify alerts are flowing
sudo tail -f /var/log/suricata/fast.log
```

## Forwarding to Splunk

See [`/lab-setup/splunk-arm64/`](../splunk-arm64/) for forwarder configuration.

---

*Configuration details expanded as lab exercises are completed.*
