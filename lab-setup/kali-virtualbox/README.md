# Kali Linux ARM64 on UTM — Setup Guide

**Platform:** MacBook Pro Apple Silicon (M-series, 8 GB RAM) → UTM → Kali Linux ARM64

---

## Why UTM

UTM runs ARM64 guests in **Virtualize** mode, using Apple's own hypervisor, so Kali ARM64 runs at close to native speed on Apple Silicon. Tools that only ship for x86_64 need emulation on top of that — see the [Splunk guide](../splunk-arm64/) for how that's handled.

---

## Download

Use the official Kali **installer** image for Apple Silicon:
[https://www.kali.org/get-kali/#kali-installer-images](https://www.kali.org/get-kali/#kali-installer-images) → **Apple Silicon (ARM64)**

Check the SHA256 checksum against the one published on kali.org before installing.

---

## Create the VM

1. In UTM: **Create a New Virtual Machine → Virtualize → Linux**
2. **Boot ISO image:** select the Kali ARM64 installer
3. Set memory, CPU and storage (table below)
4. Leave the shared directory empty
5. Run the Kali installer as normal
6. When it finishes, shut the VM down and clear the **CD/DVD** drive in the VM's settings — otherwise it boots back into the installer

| Setting | Value on an 8 GB Mac |
|---------|-------|
| Memory | 4 GB — leaves 4 GB for macOS |
| CPU cores | 2–4 |
| Storage | 64 GB or more |
| Network | Shared Network (default) |

---

## Post-Install Essentials

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y \
  spice-vdagent \
  wireshark \
  tcpdump \
  nmap \
  git \
  docker.io \
  python3-pip \
  suricata
```

`spice-vdagent` enables copy and paste between macOS and the VM.

---

## Networking

- **Shared Network** (default) puts the VM behind NAT on the `192.168.64.0/24` range — that's why the case-002 capture shows the VM at `192.168.64.3`. Wireshark and Suricata see the VM's own traffic, which is all the labs here need.
- **Bridged (Advanced)** puts the VM directly on the local network. Only needed when other devices have to reach it.

---

## Notes

- **8 GB is the real limit.** A full Wazuh or Elastic deployment wants about 8 GB on its own, so those run on a separate cloud server — not in this VM.
- **Restore point:** after a clean install, shut the VM down and clone it in UTM before adding tools.
- Prefer the command line for heavy tools — it keeps memory free for the capture itself.
