# Incident Investigation: [Case ID] — [Attack Type]

**Date:** [YYYY-MM-DD]
**Severity:** [Critical/High/Medium/Low] — [Justify in one sentence]
**Status:** [Active/Contained/Closed]
**Analyst:** Bhargav Baranda

---

## Executive Summary
[2–3 sentences. Business language. No jargon. Lead with risk and regulatory exposure.]

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Observed Procedure |
|--------|-----------|--------------|-------------------|
| | | | |

---

## Timeline of Events

| Timestamp | Event | Source | Evidence |
|-----------|-------|--------|----------|
| | | | |

---

## Technical Analysis

### Log Evidence
[Raw log excerpts with source and timestamp]

### Attack Path
[Step-by-step reconstruction of attacker actions]

### Indicators of Compromise (IOCs)

| Type | Value | Confidence | Source |
|------|-------|:----------:|--------|
| IP | | Confirmed / Probable / Suspicious | |
| Domain | | | |
| Hash (MD5) | | | |
| Hash (SHA256) | | | |

---

## Detection Rules

### Sigma
```yaml
# Sigma rule — [technique]
# Link: /detection-rules/sigma/[filename].yml
```

### Splunk SPL
```spl
# SPL correlation search — [technique]
# Link: /detection-rules/splunk-spl/[filename].spl
```

### Microsoft Sentinel KQL
```kql
# KQL detection query — [technique]
# Link: /detection-rules/sentinel-kql/[filename].kql
```

---

## Business Impact Assessment

- **Systems affected:** [X]
- **Data at risk:** [Y records / data types]
- **Regulatory exposure:** [GDPR Article 33 — ICO 72hr notification required if personal data involved]
- **Estimated remediation cost:** £[range]
- **Potential fine:** Up to 4% global annual turnover (GDPR Article 83)

---

## Remediation Playbook

**Immediate (0–4hr)**
- [ ] Isolate affected systems
- [ ] Block IOCs at perimeter (firewall, DNS sinkhole)
- [ ] Revoke compromised credentials
- [ ] Preserve forensic evidence (memory dump, log export)

**Short-term (24–72hr)**
- [ ] Eradicate persistence mechanisms
- [ ] Patch exploited vulnerability
- [ ] Reset scope — confirm no lateral movement missed
- [ ] Notify stakeholders per ICO/GDPR requirements if applicable

**Long-term (weeks/months)**
- [ ] Systemic prevention — policy, architecture, detection improvement
- [ ] Update detection rules based on lessons learned
- [ ] Tabletop exercise to test updated playbook
- [ ] Document in post-incident review

---

## Lessons Learned

[What would you do differently? What detection gap did this expose?]

---

## Security+ Connection

[Which SY0-701 objective does this investigation reinforce? State the domain and objective number.]

---

## YouTube Companion

[Link to Granger Security video covering this investigation — if published]
