# Phishing Email Analyzer

A Python-based tool that analyzes`.eml` email files for phishing indicators including header spoofing,brand impersonation,malicious URLs,IOC extraction,and optional VirusTotal reputation checks.

# What It Detects

| Check | Description | Max Score |
|-------|-------------|-----------|
| Header Spoofing | Reply-To / Return-Path mismatch with From domain | +45 pts |
| Brand Impersonation | Email mentions PayPal, Apple etc. but wrong sender domain | +30 pts |
| Suspicious URLs | IP-based URLs, malicious TLDs, URL shorteners, subdomain abuse | +35 pts |
| Urgency Language | "Urgent", "Act now", "Account suspended" in subject/body | +15 pts |
| Phishing Keywords | Known phishing phrases in email body | +20 pts |
| SPF / DKIM Failure | Email authentication checks failed | +45 pts |
| Dangerous Attachments | .exe, .bat, .ps1, double-extension files | +40 pts |
| VirusTotal (optional) | URL reputation check via API | +40 pts |

# Threat Score → Severity
| Score | Severity |
|-------|----------|
| 60–100 | 🔴 HIGH |
| 30–59 | 🟠 MEDIUM |
| 1–29 | 🟡 LOW |
| 0 | 🟢 CLEAN |

# 1.Install dependencies
pip install -r requirements.txt

# 2.Generate sample emails
python generate_sample_emails.py
# 3.Run CLI analysis
python analyzer.py sample_emails/phishing_sample.eml
# 4.With VirusTotal API key
python analyzer.py sample_emails/phishing_sample.eml my api key report.json

# 5.Launch Streamlit dashboard
streamlit run dashboard.py
# Dashboard
- Upload any `.eml` file or use built-in phishing/legitimate samples
- View threat score,severity,and all phishing indicators
- Browse extracted IOCs (domains, IPs, URLs)
- See VirusTotal results
- Download a structured JSON incident report

# VirusTotal Integration

Get a free API key at [virustotal.com](https://www.virustotal.com).  
The free tier allows 4 lookups/minute — the tool automatically limits to 5 URLs per analysis.

# Sample Output

[*] Analyzing: sample_emails/phishing_sample.eml
[*] Running detection checks...
[*] Skipping VirusTotal (no API key provided)

  THREAT SCORE : 95/100
  SEVERITY     : HIGH
  INDICATORS   : 7
  VERDICT: PHISHING LIKELY — Threat score 95/100. 7 indicators detected.

  [ 35 pts] Subdomain Brand Abuse
             Domain mimics 'paypal' via subdomain: secure-paypal-login.xyz
  [ 30 pts] Brand Impersonation (Paypal)
             Email mentions 'paypal' but sender domain is 'paypa1-support.xyz'
  [ 30 pts] IP-Based URL
             URL uses raw IP instead of domain: http://185.220.101.47/paypal/verify
  [ 25 pts] Reply-To Mismatch
             From domain 'paypa1-support.xyz' differs from Reply-To 'collect-paypal.click'
  [ 25 pts] SPF Failure
             SPF check failed: fail (domain does not designate IP as permitted)
  [ 20 pts] DKIM Failure
             DKIM signature missing or invalid
  [ 15 pts] Urgency Language in Subject
             Subject contains urgency triggers: urgent, suspended