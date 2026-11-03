# Lab 011 — Phishing Email Triage
## Four Domains, No Microsoft: Triaging a Reply-Chain Phish

**Date:** 3 November 2026
**Author:** Bhargav (Granger) Baranda
**Environment:** Kali Linux ARM64 · UTM · MacBook Pro Apple Silicon
**Tools:** curl · sha256sum · grep · Python 3 (`email` standard library) · whois · AbuseIPDB
**Sample:** `sample-2.eml` from [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) (real phishing captured by honeypots, CC BY-NC 4.0)
**MITRE ATT&CK (v20):** T1598 Phishing for Information · T1684.001 Impersonation · T1589.002 Email Addresses
**Security+ Objectives:** SY0-701 2.2 · 4.5 · 4.9
**Tier:** Tier 2 — Analyst Workflows
**Status:** ✅ Complete (walkthrough sample) · 🔄 Four comparison samples next



## Executive Summary

User-reported phishing is one of the most common things a Tier 1 analyst handles. The job is the same every time: decide quickly whether the email is malicious, prove it with evidence from the email itself, and hand over indicators that someone can act on.

This lab triaged a real phishing email captured by a honeypot. It claims to be a Microsoft account security alert about a sign-in from Moscow. It isn't from Microsoft. Four unrelated domains are involved, not one of them Microsoft's. Nothing authenticates it, and there is **no malicious link and no attachment**. Every button is a `mailto:` link to a free Gmail address, and a hidden 1×1 tracking pixel reports back when the email is opened. That design is why link scanners miss this kind of phish.

**Verdict: Malicious — High confidence.**

**Key findings:**
- Display name "Microsoft account team" sent from `access-accsecurity.com`, a non-Microsoft domain
- `Reply-To` is a free Gmail address, and `Return-Path` is a third unrelated domain
- SPF `none`, DKIM `none`, DMARC `permerror`: nothing authenticates the email
- Empty `Message-ID`
- All three `mailto:` buttons go to the attacker's Gmail, including "Unsubscribe me"
- A hidden 1×1 tracking pixel on a fourth domain confirms live addresses
- All three attacker domains are now de-registered: disposable infrastructure
- The sending IP sits on a Polish hosting provider, not on Microsoft infrastructure



## Legal and Ethical Framework

The samples are published, anonymised phishing emails released for defensive research. Every lookup in this lab was **passive**: public WHOIS registries and the AbuseIPDB reputation database. I didn't connect to, probe or scan any attacker infrastructure. Under the Computer Misuse Act 1990, that line between looking something up and touching the system is the whole thing.

Handling rules for live phishing samples:
- emails read only as text in a terminal, never opened in an email client or browser
- no URL visited, fetched or clicked
- no attachment decoded or opened
- all sample handling stayed inside the Kali VM



## Environment

```
OS:        Kali Linux ARM64 (UTM guest)
Host:      MacBook Pro Apple Silicon (M-series)
Folder:    ~/labs/lab-011-phishing-triage/{samples,scripts,notes}
Sample:    sample-2.eml — 25,597 bytes
SHA256:    4fbf4c3d80aba156c59004c12c83ff53dd64c9cf7b7a6029e98fe1da0760783a
```

**Note on dataset size:** the full `phishing_pot` repository is about 2.5 GB with 12,864 emails, too large for an 8 GB lab VM. I downloaded individual samples with `curl` instead of cloning the repository.



## Triage Workflow

### 1. Evidence first: acquire and hash

```bash
curl -fsSL -o sample-2.eml https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-2.eml
sha256sum sample-2.eml
```

The hash goes in the ticket before any analysis starts. It proves exactly which file was examined, and it's searchable in threat intelligence platforms.

### 2. Key headers

```bash
grep -iE "^(From|To|Subject|Date|Reply-To|Return-Path|Message-ID|X-Sender-IP):" sample-2.eml
```

```
From: Microsoft account team ,_<no-reply@access-accsecurity.com>
Subject: Microsoft account unusual signin activity
To: phishing@pot
Date: Fri, 8 Sep 2023 05:47:04 +0000
Reply-To: sotrecognizd@gmail.com
Message-ID:
Return-Path: bounce@thcultarfdes.co.uk
X-Sender-IP: 89.144.44.2
```

Three addresses, three different domains, and none of them Microsoft. The display name does the impersonating, which works because most phone mail apps show only the name. The `Message-ID` header is present but **empty**. Legitimate mail servers always create one. (`phishing@pot` is the dataset's anonymised recipient.)

### 3. Authentication: SPF, DKIM, DMARC

```bash
grep -i -A4 "^Authentication-Results" sample-2.eml
```

```
Authentication-Results: spf=none (sender IP is 89.144.44.2)
 smtp.mailfrom=thcultarfdes.co.uk; dkim=none (message not signed)
 header.d=none;dmarc=permerror action=none header.from=access-accsecurity.com;
Received-SPF: None (protection.outlook.com: thcultarfdes.co.uk does not
 designate permitted sender hosts)
```

| Check | Result | Meaning |
|---|---|---|
| SPF | `none` | The envelope domain publishes no SPF record, so nothing authorises this IP |
| DKIM | `none` | The message isn't signed |
| DMARC | `permerror` | The From domain's DMARC record is broken or invalid |

A real Microsoft security email would pass all three for Microsoft's own domains. The detail worth remembering is that **SPF checks the envelope sender (`Return-Path`), not the From address the user sees.** DMARC is what ties the visible From domain back to SPF or DKIM.

### 4. Origin: the Received chain, read bottom-up

```bash
grep -i -A2 "^Received: from" sample-2.eml
```

```
4. thcultarfdes.co.uk (89.144.44.2)            ← the sender
        ▼  05:47:04
3. DB8EUR06FT032 …protection.outlook.com       ← Microsoft's mail filter (the victim's provider)
        ▼
2. DB8P191CA0014 …outlook.com                  ← internal hop
        ▼
1. SJ0PR19MB6679 → MN0PR19MB6312 …outlook.com  ← the victim's mailbox
           05:47:06
```

The only hop that tells you who sent it is the **bottom** one. Everything above it is the receiving side, Outlook here because the honeypot mailbox is hosted there. Seeing "outlook.com" in the headers says nothing about the sender being Microsoft. The bottom hop's IP matches `X-Sender-IP`. Delivery took two seconds, despite failing authentication.

### 5. Links and calls to action

```bash
grep -oiE "https?://[^\"' <>)]+" sample-2.eml | sort -u
grep -oiE "mailto:[^\"' >]+" sample-2.eml | sort -u
```

```
http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176

mailto:sotrecognizd@gmail.com?&amp;cc=sotrecognizd@gmail.com&amp;Subject=Report+The+User
mailto:sotrecognizd@gmail.com?&amp;cc=sotrecognizd@gmail.com&amp;Subject=Unsubscribe+me
mailto:sotrecognizd@gmail.com?&amp;cc=sotrecognizd@gmail.com&amp;subject=unusual
```

Every `mailto:` button pre-fills an email to the same Gmail address as `Reply-To`, in both To and CC. Even "Unsubscribe me" goes to the attacker. There's no way to respond to this email without contacting them.

### 6. The tracking pixel

```bash
grep -oiE "<img[^>]*thebandalisty[^>]*>" sample-2.eml
```

```html
<img alt="" src="http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176" width="1px" height="1px" style="visibility:hidden">
```

The only web link is a 1×1, hidden image with a per-recipient ID in the path. When the mail client loads images, the attacker learns that this exact address is live and read. The victim doesn't have to click anything.

### 7. The body, read safely

I wrote a short script that parses the email with Python's standard `email` library, lists the MIME parts **by name only**, and strips HTML to plain text. It never renders the HTML, so the tracking pixel can't fire, and it never decodes attachments. It runs in isolated mode (`python3 -I`), so nothing planted in the working folder can be imported.

```python
"""Safely print the readable text and list the parts of an .eml file.
Reads only: never renders HTML, never decodes or saves attachments."""
import sys, re, html, email
from email import policy

with open(sys.argv[1], errors="replace") as f:
    msg = email.message_from_file(f, policy=policy.default)

print("=== MIME parts ===")
for part in msg.walk():
    print(f"- {part.get_content_type():<28} attachment: {part.get_filename()}")

body = msg.get_body(preferencelist=("plain", "html"))
text = body.get_content() if body else ""
text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
text = html.unescape(re.sub(r"<[^>]+>", " ", text))
print("\n=== Readable body text ===")
print(re.sub(r"\s+", " ", text).strip()[:3000])
```

```
=== MIME parts ===
- text/html                    attachment: None

=== Readable body text ===
Microsoft account Unusual sign.in activity We detected something unusual about a recent
sign-in to the Microsoft account phishing@pot . Sign-in details Country/region: Russia/Moscow
IP address: 103.225.77.255 Date: Fri, 08 Sep 2023 05:46:57 +0000 ... If this wasn't you,
please report the user. If this was you, we'll trust similar activity in the future.
Report The User ...
```

**The social engineering:** a fake login from Moscow, timestamped seven seconds before the email was sent, creates fear and urgency. The wording "If this was you, we'll trust similar activity in the future" is copied from Microsoft's genuine alerts. The typo "sign.in" gives it away. "Report The User" opens an email to the attacker, and the reply starts a conversation in which "Microsoft support" asks for credentials or codes.

### 8. Passive infrastructure checks

```bash
whois access-accsecurity.com | grep -iE "creation date|registrar:|no match|not found" | head -5
whois thcultarfdes.co.uk     | grep -iE "registered on|registrar:|no match|not found|expiry" | head -5
whois thebandalisty.com      | grep -iE "creation date|registrar:|no match|not found" | head -5
whois 89.144.44.2            | grep -iE "^(netname|descr|country|org-name|abuse-mailbox):" | head -8
```

| Indicator | Result (checked 3 Nov 2026) |
|---|---|
| `access-accsecurity.com` | `No match`: de-registered |
| `thcultarfdes.co.uk` | `No match` (Nominet): de-registered |
| `thebandalisty.com` | `No match`: de-registered |
| `89.144.44.2` | RIPE: netname `MSCODE`, org MSCode (`MSCode.pl`), country PL |

All three domains are gone: disposable infrastructure, registered for a campaign and abandoned. The original registration dates went with them. Historical WHOIS would recover them, but I didn't have access to it.

**AbuseIPDB, `89.144.44.2`:** 0% confidence score, one report (September 2026, port scan / DDoS, not phishing). Usage type: **Data Center / Web Hosting / Transit**, Warsaw.

A 0% score doesn't clear the IP. The email is from September 2023, and IP reputation decays. The useful fact is the usage type: Microsoft doesn't send account-security mail from a rented server at a third-party hosting provider. The server's location also says nothing about where the attacker is.



## Triage Table

| Indicator | Finding | Suspicious? |
|---|---|:---:|
| Display name vs domain | "Microsoft account team" from `access-accsecurity.com` | ✅ |
| Reply-To vs From | Replies go to `sotrecognizd@gmail.com` (free webmail) | ✅ |
| Return-Path | `thcultarfdes.co.uk`, a third unrelated domain | ✅ |
| SPF / DKIM / DMARC | none / none / permerror | ✅ |
| Message-ID | Present but empty | ✅ |
| Sending IP | `89.144.44.2`, hosting provider (MSCode.pl, PL); currently 0% on AbuseIPDB | ✅ |
| Links | 3 × `mailto:` to the attacker's Gmail; 1 × hidden tracking pixel | ✅ |
| Attachments | None | — |
| Social engineering | Fake Moscow sign-in → fear and urgency → victim emails the attacker | ✅ |
| Domain status | All 3 domains de-registered | ✅ |
| **Verdict** | **Malicious** | |
| **Confidence** | **High**: multiple independent indicators, no legitimate explanation | |



## Escalation Note

```text
Ticket:   PHISH-011-002          Analyst: Bhargav Baranda        Date: 2026-11-03
Summary:  User-reported email impersonating Microsoft account security.
          Verdict: MALICIOUS — High confidence.

Evidence:
- Display name "Microsoft account team" from access-accsecurity.com (not Microsoft)
- Reply-To is free webmail (sotrecognizd@gmail.com); Return-Path is a third domain
- SPF none, DKIM none, DMARC permerror — no authentication
- Empty Message-ID
- All mailto buttons ("Report The User", "Unsubscribe me") go to the Reply-To Gmail
- Hidden 1x1 tracking pixel on thebandalisty.com
- No attachments; no credential-harvesting link — reply-chain phishing

IOCs:
  IP       89.144.44.2
  Domains  access-accsecurity.com · thcultarfdes.co.uk · thebandalisty.com
  Email    sotrecognizd@gmail.com
  SHA256   4fbf4c3d80aba156c59004c12c83ff53dd64c9cf7b7a6029e98fe1da0760783a

Recommended actions:
1. Block the sender domains and the Reply-To address at the mail gateway
2. Search all mailboxes for the sender, Reply-To and subject; purge matches
3. Check whether any user replied to or emailed sotrecognizd@gmail.com — if so,
   review that user's sign-in logs, revoke sessions and reset credentials
4. Block thebandalisty.com at the web proxy
5. Thank the reporting user and confirm it was phishing
```



## MITRE ATT&CK Mapping (v20)

| Tactic | Technique | Observed |
|---|---|---|
| Reconnaissance (TA0043) | **T1598 — Phishing for Information** | Victim pushed to email the attacker, harvesting replies and details through conversation |
| Reconnaissance (TA0043) | **T1589.002 — Gather Victim Identity Information: Email Addresses** | Hidden tracking pixel confirms which addresses are live and read |
| Stealth (TA0005) | **T1684.001 — Social Engineering: Impersonation** | Display name and copied Microsoft alert wording |

Technique IDs and tactics were checked against MITRE's ATT&CK v20.0 STIX data (`mitre-attack/attack-stix-data`).



## Detection Engineering

> **Status: drafts, not tested.** I don't have a Microsoft 365 tenant or an email log source in the lab, so neither query has been run against live data. They're written against the documented schemas and will need tuning before use.

**KQL — Microsoft Defender `EmailEvents`:** inbound mail where the visible From domain differs from the envelope domain and neither SPF nor DKIM passes.

```kql
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromDomain != SenderMailFromDomain
| extend Auth = parse_json(AuthenticationDetails)
| where tostring(Auth.SPF) != "pass" and tostring(Auth.DKIM) != "pass"
| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, Auth
```

**Splunk SPL — email gateway logs:** the same logic. Field names depend on how the gateway logs are parsed. These assume `from_domain`, `return_path_domain`, `spf` and `dkim` fields.

```spl
index=email direction=inbound
| where from_domain!=return_path_domain AND spf!="pass" AND dkim!="pass"
| stats count values(recipient) as recipients values(subject) as subjects by from_domain, return_path_domain, src_ip
| sort - count
```

**Why there's no Sigma rule this time:** Sigma has no standard, widely supported log source for email message events, so a Sigma rule here would only be a stand-in for one specific product's schema. I've kept to the two platforms where the fields are documented.

**Expected false positives:** newsletters and marketing platforms legitimately send with a different envelope domain. Tune with an allow-list of known bulk senders, and keep the authentication condition.

**Why this rule alone wouldn't stop this email:** the domains are disposable. Domain blocklists age in hours, so the durable signals are the *pattern*: display-name/domain mismatch, a free-webmail Reply-To, and failed authentication.



## What Went Wrong

- **I first mapped the impersonation to T1656.** Checking against the v20 STIX data showed T1656 is **revoked** and replaced by **T1684.001** (Social Engineering: Impersonation) under Stealth. Mapping from memory, or from older blog posts, gets IDs wrong after a matrix change. Check the current data.
- **I mixed up two indicators' roles.** At first I said the victim would email `thebandalisty.com`. That domain is only the tracking pixel; replies go to the Gmail address. Getting each indicator's role right matters, because the gateway block and the proxy block are different actions.
- **I retyped an IOC and misspelt it** (`sotrecongnizd` for `sotrecognizd`). A misspelt IOC in a block rule or mailbox search silently misses the real thing. Copy and paste IOCs, never retype them.
- **The AbuseIPDB score was tempting.** 0% and "Low Risk" looks like a clean bill of health. It isn't, for a three-year-old email on an IP that has had time to change hands.
- **WHOIS came back empty three times.** That's a finding (disposable infrastructure), but it also means the registration dates can't be recovered without historical WHOIS.
- **Practical:** the Kali browser wasn't usable, so I ran the AbuseIPDB lookups from the Mac's browser. That's safe for a reputation-site search. No sample file ever left the VM.



## Business Impact

| Area | Impact if a user replied |
|---|---|
| Accounts | Credential or MFA-code theft through a fake "Microsoft support" conversation → mailbox and Microsoft 365 compromise |
| Data | Access to email and OneDrive/SharePoint content; possible personal data exposure |
| Regulatory | A confirmed compromise involving personal data may need assessment under UK GDPR Article 33 (72 hours to report to the Information Commission where there is a risk to individuals) |
| Follow-on | The tracking pixel marks the address as live, raising its value for further targeting |



## Next

- [ ] `sample-1.eml`: SPF and DMARC `temperror` (a different failure type)
- [ ] `sample-5.eml`: SPF fail but DKIM pass. Whose domain signed it?
- [ ] `sample-10.eml`: DKIM fail
- [ ] `sample-4.eml`: SPF, DKIM and DMARC all pass, with a PDF attachment (listed, never opened). Authentication proves who sent it, not that it's safe.
- [ ] Companion video on the Granger Security YouTube channel



*Samples: [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot), licensed CC BY-NC 4.0. Used here for non-commercial, educational analysis.*
