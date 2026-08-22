# 🎣 Phishing Email Analyzer

> A Python tool that automatically analyzes `.eml` email files for phishing indicators — detecting header spoofing, brand impersonation, malicious URLs, and IOCs — with optional **VirusTotal API** integration for real-time URL reputation checks.

Built as a SOC analyst portfolio project by **Sai Sura** — Master's student in Intelligent Interactive Systems, Universität Bielefeld.

---

## 📸 Dashboard Preview

```
╔══════════════════════════════════════════════════════════╗
║  🎣  Phishing Email Analyzer                            ║
║  ─────────────────────────────────────────────────────  ║
║  Threat Score: 100/100   Severity: 🔴 HIGH              ║
║  Indicators: 9           URLs Found: 3                  ║
║  ─────────────────────────────────────────────────────  ║
║                                                          ║
║  🔴 PHISHING LIKELY — Threat score 100/100              ║
║                                                          ║
║  📧 Email Header Summary                                ║
║  From:    security@paypa1-support.xyz                   ║
║  Subject: URGENT: Your PayPal account has been...       ║
║  Date:    Sat, 27 Jun 2026 02:14:33 +0000               ║
║                                                          ║
║  🚨 Phishing Indicators                                 ║
║  [+30] Brand Impersonation (PayPal)                     ║
║  [+30] IP-Based URL detected                            ║
║  [+25] Reply-To Mismatch                                ║
║  [+25] SPF Authentication Failure                       ║
║  [+20] Suspicious TLD (.xyz)                            ║
║  [+20] DKIM Failure                                     ║
║  [+20] Phishing Keywords (7 found)                      ║
║  [+15] URL Shortener Detected                           ║
║  [+15] Urgency Language in Subject                      ║
║                                                          ║
║  [ 📥 Download Phishing Report (JSON) ]                 ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🎯 Problem This Solves

Phishing emails are the **#1 initial attack vector** in corporate breaches. A Level 1 SOC analyst spends a significant part of their day manually triaging suspicious emails forwarded by employees — checking headers, inspecting links, looking up domains.

This tool **automates that triage**. Drop in a `.eml` file, get back a 0–100 threat score with every indicator explained and all IOCs extracted. What takes an analyst 10–15 minutes manually takes this tool under 3 seconds.

---

## 🔍 What It Detects

| Check | What It Looks For | Max Score |
|-------|-------------------|-----------|
| **Header Spoofing** | Reply-To / Return-Path mismatch with From domain | +45 pts |
| **Brand Impersonation** | PayPal/Apple/Microsoft mentioned but wrong sender domain | +30 pts |
| **IP-Based URL** | Links using raw IP addresses instead of domains | +30 pts |
| **Suspicious TLD** | Domains ending in .xyz, .click, .top, .tk etc. | +20 pts |
| **URL Shortener** | bit.ly, tinyurl hiding the real destination | +15 pts |
| **Subdomain Abuse** | paypal.evil-site.xyz pretending to be PayPal | +35 pts |
| **Urgency Language** | "Urgent", "Act now", "Account suspended" in subject | +15 pts |
| **Phishing Keywords** | Known phishing phrases in body | +20 pts |
| **SPF Failure** | Sending server not authorized for that domain | +25 pts |
| **DKIM Failure** | Email signature missing or invalid | +20 pts |
| **Dangerous Attachments** | .exe, .bat, .ps1, double-extension files | +40 pts |
| **VirusTotal (optional)** | URL checked against 70+ AV engines via API | +40 pts |

### Threat Score → Severity
| Score | Severity | Meaning |
|-------|----------|---------|
| 60–100 | 🔴 HIGH | Block sender, report to security team immediately |
| 30–59 | 🟠 MEDIUM | Do not click links, verify sender through official channels |
| 1–29 | 🟡 LOW | Probably fine, double-check if unexpected |
| 0 | 🟢 CLEAN | No indicators found |

---

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │   .eml File     │
                    │  (email file)   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Email Parser   │  ← Extracts: From, Reply-To,
                    │  (analyzer.py)  │    Subject, Body, URLs,
                    └────────┬────────┘    Attachments, Auth headers
                             │
        ┌────────────────────┼─────────────────────┐
        ▼                    ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│   Header     │    │     URL      │    │    Content       │
│  Spoofing    │    │  Analysis    │    │    Signals       │
│  Check       │    │  Check       │    │  (keywords +     │
└──────┬───────┘    └──────┬───────┘    │   urgency)       │
       │                   │            └──────┬───────────┘
       │            ┌──────┴───────┐           │
       │            │  VirusTotal  │           │
       │            │  API Check   │           │
       │            └──────┬───────┘           │
       └────────────────── ┼ ──────────────────┘
                           ▼
                  ┌─────────────────┐
                  │ Threat Score    │  ← 0–100 score
                  │ Calculator      │    + severity label
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐
                  │ Report Generator│  ← JSON with IOCs,
                  │                 │    indicators, actions
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐
                  │   Streamlit     │  ← Web dashboard
                  │   Dashboard     │
                  └─────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/surasai060/phishing-email-analyzer.git
cd phishing-email-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate sample emails
```bash
python generate_sample_emails.py
```
Creates two test files:
- `sample_emails/phishing_sample.eml` — realistic PayPal phishing email
- `sample_emails/legitimate_sample.eml` — clean GitHub newsletter

### 4a. Run CLI analysis
```bash
# Without VirusTotal
python analyzer.py sample_emails/phishing_sample.eml

# With VirusTotal API key
python analyzer.py sample_emails/phishing_sample.eml YOUR_VT_API_KEY report.json
```

### 4b. Launch the Streamlit dashboard
```bash
streamlit run dashboard.py
```
Then open **http://localhost:8501** in your browser.

---

## 📊 Sample Output (CLI)

```
[*] Analyzing: sample_emails/phishing_sample.eml
[*] Running detection checks...
[*] Checking 3 URLs against VirusTotal...

=======================================================
  THREAT SCORE : 100/100
  SEVERITY     : HIGH
  INDICATORS   : 9
=======================================================

  VERDICT: PHISHING LIKELY — Threat score 100/100. 9 indicators detected.

  [ 30 pts] Brand Impersonation (Paypal)
             Email mentions 'paypal' but sender is 'paypa1-support.xyz'

  [ 30 pts] IP-Based URL
             URL uses raw IP: http://185.220.101.47/paypal/verify?token=abc123

  [ 25 pts] Reply-To Mismatch
             From 'paypa1-support.xyz' differs from Reply-To 'collect-paypal.click'

  [ 25 pts] SPF Failure
             fail (domain does not designate IP as permitted sender)

  [ 20 pts] Suspicious TLD (.xyz)
             https://secure-paypal-login.xyz/confirm

  [ 20 pts] DKIM Failure
             DKIM signature missing or invalid

  [ 20 pts] Phishing Keywords Detected
             7 phrases found: "verify your account", "unusual activity"...

  [ 15 pts] URL Shortener Detected
             https://bit.ly/3xPaypalVerify hides true destination

  [ 15 pts] Urgency Language in Subject
             Triggers: urgent, suspended
```

---

## 🌐 VirusTotal Integration

Get a **free API key** at [virustotal.com](https://www.virustotal.com) (takes 2 minutes).

The free tier allows 4 lookups/minute and 500/day — enough for testing and demos. The tool automatically limits to 5 URL checks per analysis to stay within the free tier.

**How to use:**
```bash
# CLI
python analyzer.py email.eml YOUR_API_KEY report.json

# Dashboard
# Paste your key into the sidebar field — it's masked for security
```

> ⚠️ Never hardcode your API key in the code or push it to GitHub. Always pass it at runtime.

---

## 📄 Sample IOC Report (JSON)

```json
{
  "report_metadata": {
    "tool": "Phishing Email Analyzer",
    "generated_at": "2026-06-27 14:32:01",
    "threat_score": 100,
    "severity": "HIGH",
    "total_indicators": 9
  },
  "email_summary": {
    "from": "security@paypa1-support.xyz",
    "subject": "URGENT: Your PayPal account has been suspended",
    "reply_to": "no-reply@collect-paypal.click"
  },
  "iocs": {
    "sending_domain": "paypa1-support.xyz",
    "reply_to_domain": "collect-paypal.click",
    "urls": [
      "http://185.220.101.47/paypal/verify?token=abc123",
      "https://secure-paypal-login.xyz/confirm",
      "https://bit.ly/3xPaypalVerify"
    ],
    "originating_ips": ["185.220.101.47"]
  }
}
```

---

## 📁 Project Structure

```
phishing-email-analyzer/
│
├── analyzer.py                 # Core detection engine
│   ├── Email Parser            #   Parses .eml headers + body
│   ├── Header Spoofing Check   #   Reply-To / Return-Path mismatch
│   ├── Brand Impersonation     #   PayPal, Apple, Microsoft etc.
│   ├── URL Analysis            #   IP URLs, bad TLDs, shorteners
│   ├── Content Signals         #   Keywords + urgency language
│   ├── SPF / DKIM Check        #   Email authentication results
│   ├── Attachment Check        #   Dangerous file extensions
│   ├── VirusTotal Integration  #   Live URL reputation API
│   └── Report Generator        #   JSON IOC report
│
├── dashboard.py                # Streamlit web dashboard
├── generate_sample_emails.py   # Sample .eml file generator
├── requirements.txt            # streamlit
└── sample_emails/
    ├── phishing_sample.eml     # Realistic phishing test email
    └── legitimate_sample.eml  # Clean comparison email
```

---

## 🔗 How This Relates to Real SOC Work

| This Project | Real SOC Task |
|---|---|
| Header spoofing check | Manual header analysis in email client |
| Brand impersonation detection | "Does this look like it's pretending to be PayPal?" |
| URL extraction + TLD check | Copy link → paste into URLScan.io |
| VirusTotal API lookup | Manually submitting URLs to VirusTotal |
| SPF/DKIM check | Checking email authentication headers |
| JSON IOC report | Writing up indicators for the SIEM ticket |

---

## 🛠️ Tech Stack

- **Python 3.x** — email parsing, detection logic, IOC extraction
- **Streamlit** — interactive web dashboard
- **VirusTotal API** — URL/domain reputation (optional, free tier)
- **JSON** — structured incident report output
- **Python `email` library** — RFC-compliant .eml parsing

---

## 👤 Author

**Sai Sura**  
Master's in Intelligent Interactive Systems — Universität Bielefeld  
1 year SOC experience — Tech Mahindra (IBM QRadar, HP ArcSight)  
📧 surasai060@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/sai-sura-945032284)

---

## 📜 License

MIT License — free to use, modify, and distribute.
