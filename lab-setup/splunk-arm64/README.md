# Splunk on ARM64 — Docker Workaround

**Platform:** MacBook Pro Apple Silicon (M-series) → VirtualBox → Kali Linux ARM64
**Problem:** Splunk Enterprise ships x86_64 only. No native ARM64 installer.
**Solution:** Docker with QEMU emulation layer.

---

## The Problem

Splunk's official installer is x86_64 only. Running it directly on ARM64 fails:
```bash
$ ./splunk start
bash: ./splunk: cannot execute binary file: Exec format error
```

---

## The Solution — Docker with QEMU

The official `splunk/splunk` Docker image runs on ARM64 via QEMU emulation.
Performance is reduced compared to native, but fully functional for lab use.

---

## Step-by-Step Setup

### 1. Install Docker on Kali Linux ARM64
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

### 2. Enable QEMU Multi-Architecture Support
```bash
docker run --privileged --rm tonistiigi/binfmt --install all
```

### 3. Pull and Run Splunk Container
```bash
docker run -d \
  --name splunk \
  --platform linux/amd64 \
  -p 8000:8000 \
  -p 8088:8088 \
  -p 9997:9997 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='YourPasswordHere' \
  -v splunk-data:/opt/splunk/var \
  splunk/splunk:latest
```

### 4. Access Splunk Web
```
http://localhost:8000
Username: admin
Password: [password you set above]
```

### 5. Verify Container Health
```bash
docker ps
docker logs splunk --follow
```

Wait for: `Ansible playbook complete, will begin streaming Splunk output`

---

## Connecting Log Sources

### Forward Suricata Logs to Splunk
```bash
docker run -d \
  --name splunkforwarder \
  --platform linux/amd64 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='YourPasswordHere' \
  -e SPLUNK_FORWARD_SERVER='splunk:9997' \
  -v /var/log/suricata:/var/log/suricata:ro \
  splunk/universalforwarder:latest
```

---

## Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| QEMU emulation overhead | ~20–30% slower search performance | Acceptable for lab use |
| Some Splunk apps may fail | ARM64 incompatibility | Use Splunk Cloud trial for app testing |
| Memory usage higher | QEMU overhead | Allocate 4GB+ RAM to Docker |

---

## Performance Tips

- Limit search time windows — never run open-ended searches
- Use `index=` and `sourcetype=` scoping on every search
- Restart container if performance degrades: `docker restart splunk`

---

## References

- [Splunk Docker Hub](https://hub.docker.com/r/splunk/splunk)
- [QEMU Multi-arch Docker](https://github.com/tonistiigi/binfmt)
- Related investigation: [`/incidents/case-001/`](../../incidents/case-001/)
