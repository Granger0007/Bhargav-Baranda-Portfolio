# Kali Linux ARM64 on VirtualBox — Setup Guide

**Platform:** MacBook Pro Apple Silicon → VirtualBox → Kali Linux ARM64

---

## Download

Always use the official ARM64 image:
[https://www.kali.org/get-kali/#kali-virtual-machines](https://www.kali.org/get-kali/#kali-virtual-machines)

Select: **Kali Linux ARM64 VirtualBox image**

---

## VirtualBox Configuration

| Setting | Value |
|---------|-------|
| Memory | 4096 MB minimum (8192 MB recommended) |
| CPU | 2 cores minimum |
| Display | 128 MB video memory |
| Network | Bridged Adapter (for lab traffic analysis) |
| Storage | 80 GB dynamically allocated |

---

## Post-Install Essentials
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y \
  wireshark \
  tcpdump \
  nmap \
  git \
  docker.io \
  python3-pip \
  suricata
```

---

## Notes

- VirtualBox Guest Additions for ARM64 may have display issues — use CLI where possible
- Bridged networking required for Suricata to capture live traffic
- Snapshot after clean install before adding tools

---

*More detail added as lab evolves.*
