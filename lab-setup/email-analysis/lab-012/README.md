# Lab 012 — A Recruitment Scam That Targeted Me
## Head of Threat Detection, Two Days Old: Triaging a Live Recruiter Phish

**Date:** 4 November 2026
**Author:** Bhargav (Granger) Baranda
**Environment:** Gmail header view · Kali Linux ARM64 · UTM · MacBook Pro Apple Silicon
**Tools:** Gmail "Show original" · whois
**MITRE ATT&CK (v20):** T1598 Phishing for Information · T1684.001 Impersonation · T1583.001 Domains · T1585.002 Email Accounts · T1593.001 Social Media
**Security+ Objectives:** SY0-701 2.2 · 4.5 · 4.9
**Tier:** Tier 2  Analyst Workflows
**Status:** ✅ Complete · Reported to the NCSC and Google



## Executive Summary

The day after I finished a phishing triage lab on honeypot samples, a phish arrived in my own inbox. It was aimed at exactly what I'm doing right now: looking for my first security job.

The email offered a "confidential, retained search" for a **Head of Threat Detection**, an executive role, and said my background "stood out during our shortlist review of senior executives". I'm applying for junior analyst roles. That mismatch is the hook: flattery big enough to get a reply.

The headers settled it in a few minutes. The email came from a **personal Gmail account** using a company address as a costume. **SPF passed, but only for Gmail. DMARC failed** for the domain shown in From. The sending domain was **registered two days before the email arrived**, and the "company website" in the signature was **22 days old**. The HTML formatting suggests the text was pasted from an AI chatbot.

**Verdict: Malicious recruitment fraud  High confidence.** Not replied to. Reported to the NCSC's Suspicious Email Reporting Service and to Google.

**Key findings:**
- Real sender: a free Gmail account, visible only in `Return-Path`
- Visible From: `apexcareerconnectteams.com`, a lookalike domain created **2 November 2026**
- Signature website: `apexcareerconnect.com`, created **13 October 2026**
- SPF `pass` (for gmail.com only) · DMARC `FAIL` · no DKIM signature for the From domain
- An executive role offered to an entry-level candidate, with no company, salary or location named
- AI-generated text, pasted in from a chatbot interface (high likelihood, see below)



## Legal and Ethical Framework

This was an email sent to me, so analysing it is my own business. Every external check was **passive**: public WHOIS registries only. I didn't reply, click the link, visit either domain or contact any server the sender controls. Visiting the domains would tell the sender the address is live and paying attention, and probing their infrastructure would cross into Computer Misuse Act 1990 territory. Neither was needed.

**A note on names.** Scam emails routinely use invented or stolen identities. The display name and the Gmail account below are recorded as indicators only. This write-up makes no claim about any real person with that name.

My own address is redacted below.



## The Email

```
From:    Muhammad <muhammad.nazir@apexcareerconnectteams.com> via gmail.com
To:      [my inbox]
Date:    Wed, 4 Nov 2026, 14:24 GMT
Subject: Leadership - Opportunity - Head of Threat Detection
```

> I'm reaching out regarding a confidential, retained search for an executive leader (**Head of Threat Detection**) with a real, actively operating company in the global cybersecurity and financial services space. Your background in [details from my public profile] stood out during our shortlist review of senior executives.
>
> If you're open to a confidential conversation, I'll share the full executive brief.

No company name, no salary, no location, no attachment. Its only job is to get a reply.



## Triage Workflow

### 1. The first look: Gmail's sender details

```
from:       Muhammad <muhammad.nazir@apexcareerconnectteams.com> via gmail.com
mailed-by:  gmail.com
signed-by:  (none)
security:   Standard encryption (TLS)
```

Two things stood out before opening the raw headers. **"via gmail.com" and "mailed-by: gmail.com"** mean the email wasn't sent by the company's own mail system. And there's **no "signed-by" line** for the company domain. A real firm on Microsoft 365 or Google Workspace would show its own domain there.

"Standard encryption (TLS)" is the line people trust and shouldn't. It only means the connection between mail servers was encrypted. It says nothing about who sent the email.

### 2. Authentication results: Show original

```
SPF:    PASS with IP 209.85.220.65
DMARC:  FAIL
```

```
Return-Path: <muhammadnazirsuleimanfhg@gmail.com>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of
 muhammadnazirsuleimanfhg@gmail.com designates 209.85.220.65 as permitted sender)
 smtp.mailfrom=muhammadnazirsuleimanfhg@gmail.com
```

**This is the part worth slowing down on.** SPF passed, and a tired analyst could stop there. But SPF checks the envelope sender, the `Return-Path`, and that was a personal Gmail account. So the pass only proves that **Gmail's server sent an email for a Gmail user**. It says nothing about `apexcareerconnectteams.com`.

DMARC is the check that ties the visible From domain back to SPF or DKIM, and it **failed**. Nothing authenticates the domain the recipient actually sees.

There's also **no DKIM signature for the From domain**. The only signature is Google's internal `X-Google-DKIM-Signature` with `d=1e100.net`.

| Check | Result | What it actually proves |
|---|---|---|
| SPF | `pass` | Gmail sent it for a Gmail account. Irrelevant to the company claim |
| DKIM | none for the From domain | The company domain didn't sign it |
| DMARC | `FAIL` | The visible From domain isn't backed by anything |

### 3. Where it was written

```
Message-ID: <CAGzwCZu3QSaRZs7K0cZjEMBUBcWZK2m3oVQSgOiqteSg=wL+og@mail.gmail.com>
Date: Wed, 4 Nov 2026 15:24:46 +0100
```

The `@mail.gmail.com` Message-ID shows it was composed in the ordinary Gmail web interface. The `+0100` offset means the sender's device clock was set to UTC+1. Many countries use that offset, so it identifies no one. I've recorded it as a fact, not a conclusion.

### 4. The body: an AI fingerprint

The HTML part carries styling that doesn't come from Gmail:

```html
<p class="gmail-ds-markdown-paragraph" style="... font-family:quote-cjk-patch,Inter,system-ui,...">
```

When you copy text from a web page and paste it into Gmail, Gmail keeps the source page's class names and prefixes them with `gmail-`. `ds-markdown` is the class name DeepSeek's chat interface uses for its responses, and the `quote-cjk-patch` font stack comes with it. So the email text was very likely **generated in an AI chatbot and pasted in**. I'm confident about the copy-and-paste. The specific tool is a strong inference from the class name, not a certainty.

It matters because AI writing removes the old tell of poor grammar. This email is fluent. The evidence is in the headers, not the prose.

### 5. Links and attachments

One link, in the signature: `https://apexcareerconnect.com/`. **Not visited.** It's a different domain from the From address. No attachments.

### 6. Passive infrastructure checks (Kali)

```bash
whois apexcareerconnectteams.com | grep -iE "creation date|registrar:|no match" | head -4
```
```
Creation Date: 2026-11-02T14:02:28Z
Registrar: Tucows Domains Inc.
```

```bash
whois apexcareerconnect.com | grep -iE "creation date|registrar:|no match" | head -4
```
```
getaddrinfo(https://who-is.whogohost.com): Name or service not known
Creation Date: 2026-10-13T12:45:19Z
Registrar: GO54 Limited
```

| Domain | Role | Created | Age at contact |
|---|---|---|---|
| `apexcareerconnect.com` | "Company website" in the signature | 13 Oct 2026 | **22 days** |
| `apexcareerconnectteams.com` | Visible From address | 2 Nov 2026 | **2 days** |

The order tells the story: a website domain first, to look established, then a lookalike sending domain registered two days before the campaign. The `getaddrinfo` line is the registrar's own WHOIS referral server failing to resolve. The creation dates come from the `.com` registry itself, so they're reliable. I didn't get registrant details, and the registrar's location says nothing about who's behind it.



## Triage Table

| Indicator | Finding | Suspicious? |
|---|---|:---:|
| Role vs recipient | Executive search offered to an entry-level candidate | ✅ |
| Real sender (Return-Path) | Free personal Gmail account | ✅ |
| Visible From domain | Lookalike, created 2 days before contact | ✅ |
| Signature website | A different domain, 22 days old | ✅ |
| SPF | `pass`, for gmail.com only | ⚠️ misleading |
| DKIM | No signature for the From domain | ✅ |
| DMARC | `FAIL` | ✅ |
| Content | No company, salary or location; "real, actively operating company" | ✅ |
| Text origin | Pasted from an AI chatbot interface (high likelihood) | ✅ |
| Call to action | Reply to receive an "executive brief" | ✅ |
| **Verdict** | **Malicious — recruitment fraud** | |
| **Confidence** | **High** | |



## IOCs

```
Sender account   muhammadnazirsuleimanfhg@gmail.com
From address     muhammad.nazir@apexcareerconnectteams.com
Domains          apexcareerconnectteams.com   (created 2026-11-02, Tucows)
                 apexcareerconnect.com        (created 2026-10-13, GO54 Limited)
Sending IP       209.85.220.65 — Google mail infrastructure, NOT attacker-owned
Message-ID       CAGzwCZu3QSaRZs7K0cZjEMBUBcWZK2m3oVQSgOiqteSg=wL+og@mail.gmail.com
```

**Don't block the IP.** It belongs to Google and carries legitimate Gmail traffic. In an escalation note, that's worth saying explicitly so nobody blocks it by mistake. The useful blocks are the two domains and the sender account.



## What Happens If You Reply

I didn't reply, so this part is the common pattern for this kind of campaign, not something I observed here. The "executive brief" is the second stage. Typical next steps are a fee for "background checks" or "onboarding", a request for passport and bank details for "pre-employment screening", a document that carries malware, or a move to WhatsApp or Telegram where there are no headers to read. Fake recruiting is also a known way to reach people inside a target company: a candidate is given an "assignment" repository that runs malicious code.



## Actions Taken

1. Didn't reply, click or visit anything
2. Forwarded the email to **report@phishing.gov.uk**, the NCSC's Suspicious Email Reporting Service
3. Reported it as phishing in Gmail, which flags the sending account to Google



## MITRE ATT&CK Mapping (v20)

| Tactic | Technique | Observed |
|---|---|---|
| Reconnaissance (TA0043) | **T1593.001 — Search Open Websites/Domains: Social Media** | The email quoted details consistent with my public profile |
| Resource Development (TA0042) | **T1583.001 — Acquire Infrastructure: Domains** | Two lookalike domains registered 22 days and 2 days before contact |
| Resource Development (TA0042) | **T1585.002 — Establish Accounts: Email Accounts** | A free Gmail account used as the real sender. Created or compromised can't be told from the headers, so this is the likelier reading |
| Reconnaissance (TA0043) | **T1598 — Phishing for Information** | A reply-bait email designed to start a conversation and extract information |
| Stealth (TA0005) | **T1684.001 — Social Engineering: Impersonation** | A fake executive recruiter persona and a lookalike company domain |

Technique IDs and tactics checked against MITRE's ATT&CK v20.0 STIX data (`mitre-attack/attack-stix-data`).



## Detection Engineering

> **Status: drafts, not tested.** No Microsoft 365 tenant or email log source in the lab. Written against the documented schemas; they need tuning before use.

**KQL — Microsoft Defender `EmailEvents`:** inbound mail where the visible From domain differs from the envelope domain, the envelope is a free webmail provider, and DMARC didn't pass.

```kql
let FreeMail = dynamic(["gmail.com","outlook.com","hotmail.com","yahoo.com","proton.me","icloud.com"]);
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromDomain != SenderMailFromDomain
| where SenderMailFromDomain in~ (FreeMail)
| extend Auth = parse_json(AuthenticationDetails)
| where tostring(Auth.DMARC) != "pass"
| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, Auth
```

**Splunk SPL — email gateway logs:** the same logic. Field names depend on how the gateway logs are parsed.

```spl
index=email direction=inbound
| eval free_envelope=if(match(lower(return_path_domain), "^(gmail|outlook|hotmail|yahoo|icloud)\.com$|^proton\.me$"), 1, 0)
| where from_domain!=return_path_domain AND free_envelope=1 AND dmarc!="pass"
| stats count values(recipient) as recipients values(subject) as subjects by from_domain, return_path_domain
```

**The signal neither query has: domain age.** The strongest indicator here was a two-day-old domain, and email logs don't carry registration dates. In production, that comes from threat intelligence enrichment, or a gateway policy that flags newly registered domains. Many organisations treat anything under 30 days old as suspicious.

**Expected false positives:** small businesses that genuinely send from a personal Gmail account while showing a company address. Not common for a firm claiming "retained executive search".



## What Went Wrong / What I Learned

- **The SPF pass nearly looked reassuring.** It's the most misleading line in the whole header. SPF answers "was this server allowed to send for the envelope domain?", not "is the From address real?". Reading DMARC alongside it is what makes the difference.
- **The prose was fine.** No spelling mistakes, no broken English. AI has removed the tell people were taught to look for. The headers and the domain dates did the work.
- **The bait was matched to my situation.** It arrived while I'm actively job-hunting and named skills that are on my public profile. Targeting job seekers works because the hope is real. I'll be more careful about which specific figures I make public.
- **WHOIS beat reputation.** Neither domain had any reputation history yet: they were too new for anyone to have reported them. Creation dates were the signal. A clean reputation result on a new domain proves nothing.
- **Lab 011 helped directly.** I'd triaged four-domain Microsoft impersonation the day before. Seeing the same disguise, with a free webmail sender behind a borrowed domain, took minutes rather than an hour.



## Business Impact (if a user in an organisation had replied)

| Area | Impact |
|---|---|
| Identity | Passport, address and bank details handed over for fake "screening" → identity fraud |
| Money | Upfront "processing" or "onboarding" fees |
| Endpoint | Malware delivered as an "executive brief" or a technical "assignment" |
| Organisation | If the target works in security or finance, a foothold for social engineering against their employer |
| Regulatory | If the target's employer data were exposed, possible UK GDPR breach assessment under Article 33 |
