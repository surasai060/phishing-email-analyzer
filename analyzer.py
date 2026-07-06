import re
import json
import email
import email.policy
import urllib.parse
from datetime import datetime
SUSPICIOUS_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your payment',
    'account suspended', 'unusual activity', 'click here immediately',
    'your account will be closed', 'won a prize', 'congratulations you have',
    'limited time offer', 'act now', 'urgent action required',
    'password expired', 'reset your password', 'login attempt',
    'invoice attached', 'payment failed', 'refund available',
    'irs refund', 'tax return', 'dear customer', 'dear user',
    'verify now', 'confirm now', 'validate your',
]
SUSPICIOUS_TLD = [
    '.xyz', '.top', '.click', '.link', '.online', '.site',
    '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw',
    '.download', '.zip', '.review', '.country', '.kim',
]
URGENT_WORDS = [
    'urgent', 'immediately', 'action required', 'important notice',
    'final warning', 'last chance', 'expires today', 'within 24 hours',
    'account will be terminated', 'suspended', 'verify now',
]
FREE_EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'protonmail.com', 'mail.com', 'aol.com', 'icloud.com',
]
KNOWN_BRAND_DOMAINS = {
    'paypal': 'paypal.com',
    'amazon': 'amazon.com',
    'apple': 'apple.com',
    'microsoft': 'microsoft.com',
    'google': 'google.com',
    'facebook': 'facebook.com',
    'netflix': 'netflix.com',
    'ebay': 'ebay.com',
    'dhl': 'dhl.com',
    'fedex': 'fedex.com',
    'irs': 'irs.gov',
    'bank': None,
}
URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>]+',
    re.IGNORECASE
)
IP_URL_PATTERN = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}'
)
def parse_email(filepath):
    """Parse .eml file into structured fields."""
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    body_text = ''
    body_html = ''
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get('Content-Disposition', ''))
            if 'attachment' in disp:
                attachments.append({
                    'filename': part.get_filename('unknown'),
                    'content_type': ct,
                })
            elif ct == 'text/plain':
                body_text += part.get_content() or ''
            elif ct == 'text/html':
                body_html += part.get_content() or ''
    else:
        ct = msg.get_content_type()
        if ct == 'text/plain':
            body_text = msg.get_content() or ''
        elif ct == 'text/html':
            body_html = msg.get_content() or ''
    return {
        'from': msg.get('From', ''),
        'reply_to': msg.get('Reply-To', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'return_path': msg.get('Return-Path', ''),
        'received': msg.get_all('Received', []),
        'x_mailer': msg.get('X-Mailer', ''),
        'x_originating_ip': msg.get('X-Originating-IP', ''),
        'spf': msg.get('Received-SPF', ''),
        'dkim': msg.get('Authentication-Results', ''),
        'body_text': body_text,
        'body_html': body_html,
        'attachments': attachments,
        'raw_headers': dict(msg.items()),
    }
def extract_domain(email_addr):
    """Pull domain from an email address string."""
    match = re.search(r'@([\w.\-]+)', email_addr)
    return match.group(1).lower() if match else None
def extract_urls(text):
    """Extract all URLs from text/HTML body."""
    urls = URL_PATTERN.findall(text)
    return list(set(u.rstrip('.,;)>"\']') for u in urls))
def extract_ip_from_received(received_headers):
    """Pull originating IPs from Received headers."""
    ips = []
    ip_pattern = re.compile(r'\[(\d{1,3}\.){3}\d{1,3}\]')
    for header in received_headers:
        matches = ip_pattern.findall(header)
        ips.extend(matches)
    return list(set(ips))
def check_header_spoofing(parsed):
    """Detect mismatches between From, Reply-To, and Return-Path."""
    findings = []
    from_domain = extract_domain(parsed['from'])
    reply_domain = extract_domain(parsed['reply_to']) if parsed['reply_to'] else None
    return_domain = extract_domain(parsed['return_path']) if parsed['return_path'] else None
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({
            'indicator': 'Reply-To Mismatch',
            'detail': f"From domain '{from_domain}' differs from Reply-To '{reply_domain}'",
            'weight': 25,
        })
    if return_domain and from_domain and return_domain != from_domain:
        findings.append({
            'indicator': 'Return-Path Mismatch',
            'detail': f"From domain '{from_domain}' differs from Return-Path '{return_domain}'",
            'weight': 20,
        })
    return findings
def check_brand_impersonation(parsed):
    """Check if email claims to be from a known brand but uses wrong domain."""
    findings = []
    subject = parsed['subject'].lower()
    body = (parsed['body_text'] + parsed['body_html']).lower()
    from_domain = extract_domain(parsed['from']) or ''
    for brand, legit_domain in KNOWN_BRAND_DOMAINS.items():
        if brand in subject or brand in body:
            if legit_domain and legit_domain not in from_domain:
                findings.append({
                    'indicator': f'Brand Impersonation ({brand.title()})',
                    'detail': f"Email mentions '{brand}' but sender domain is '{from_domain}' (expected '{legit_domain}')",
                    'weight': 30,
                })
            elif from_domain in FREE_EMAIL_DOMAINS:
                findings.append({
                    'indicator': f'Brand via Free Email ({brand.title()})',
                    'detail': f"'{brand}' mentioned but sent from free email provider '{from_domain}'",
                    'weight': 20,
                })

    return findings
def check_suspicious_urls(parsed):
    """Analyze URLs in the email body."""
    findings = []
    all_text = parsed['body_text'] + parsed['body_html']
    urls = extract_urls(all_text)
    for url in urls:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        if IP_URL_PATTERN.match(url):
            findings.append({
                'indicator': 'IP-Based URL',
                'detail': f"URL uses raw IP instead of domain: {url[:80]}",
                'weight': 30,
                'url': url,
            })
        for tld in SUSPICIOUS_TLD:
            if domain.endswith(tld):
                findings.append({
                    'indicator': f'Suspicious TLD ({tld})',
                    'detail': f"URL uses high-risk TLD: {url[:80]}",
                    'weight': 20,
                    'url': url,
                })
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'rb.gy']
        if any(s in domain for s in shorteners):
            findings.append({
                'indicator': 'URL Shortener Detected',
                'detail': f"Shortened URL hides true destination: {url[:80]}",
                'weight': 15,
                'url': url,
            })
        parts = domain.split('.')
        if len(parts) > 3:
            for brand in KNOWN_BRAND_DOMAINS:
                if brand in domain and not domain.endswith(f"{brand}.com"):
                    findings.append({
                        'indicator': 'Subdomain Brand Abuse',
                        'detail': f"Domain mimics '{brand}' via subdomain: {domain}",
                        'weight': 35,
                        'url': url,
                    })
    return findings, urls
def check_content_signals(parsed):
    """Check subject and body for phishing language and urgency."""
    findings = []
    subject = parsed['subject'].lower()
    body = (parsed['body_text'] + parsed['body_html']).lower()
    combined = subject + ' ' + body
    urgency_hits = [w for w in URGENT_WORDS if w in subject]
    if urgency_hits:
        findings.append({
            'indicator': 'Urgency Language in Subject',
            'detail': f"Subject contains urgency triggers: {', '.join(urgency_hits[:3])}",
            'weight': 15,
        })
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined]
    if len(kw_hits) >= 2:
        findings.append({
            'indicator': 'Phishing Keywords Detected',
            'detail': f"{len(kw_hits)} phishing phrases found: \"{kw_hits[0]}\", \"{kw_hits[1]}\"...",
            'weight': 20,
        })
    elif len(kw_hits) == 1:
        findings.append({
            'indicator': 'Phishing Keyword Detected',
            'detail': f"Phishing phrase found: \"{kw_hits[0]}\"",
            'weight': 10,
        })
    return findings
def check_auth_results(parsed):
    """Check SPF/DKIM authentication results."""
    findings = []
    spf = parsed['spf'].lower()
    dkim = parsed['dkim'].lower()
    if 'fail' in spf or 'softfail' in spf:
        findings.append({
            'indicator': 'SPF Failure',
            'detail': f"SPF check failed: {parsed['spf'][:100]}",
            'weight': 25,
        })
    if 'dkim=fail' in dkim or 'dkim=none' in dkim:
        findings.append({
            'indicator': 'DKIM Failure',
            'detail': "DKIM signature missing or invalid",
            'weight': 20,
        })
    return findings
def check_attachments(parsed):
    """Flag dangerous attachment types."""
    findings = []
    dangerous_ext = ['.exe', '.bat', '.vbs', '.js', '.ps1', '.scr', '.msi', '.cmd', '.jar']
    for att in parsed['attachments']:
        fname = att['filename'].lower()
        for ext in dangerous_ext:
            if fname.endswith(ext):
                findings.append({
                    'indicator': f'Dangerous Attachment ({ext})',
                    'detail': f"Executable attachment detected: {att['filename']}",
                    'weight': 40,
                })
        if fname.count('.') >= 2:
            findings.append({
                'indicator': 'Double Extension Attachment',
                'detail': f"Possible double-extension trick: {att['filename']}",
                'weight': 35,
            })
    return findings
def check_virustotal(urls, api_key):
    """Check URLs against VirusTotal API. Returns dict of url -> result."""
    import urllib.request
    results = {}
    if not api_key or api_key == 'YOUR_VT_API_KEY':
        return results 
    for url in urls[:5]:
        try:
            url_id = urllib.parse.quote(url, safe='')
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                results[url] = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                }
        except Exception as e:
            results[url] = {'error': str(e)}

    return results
def calculate_threat_score(all_findings, vt_results):
    """Sum weights from all findings + VirusTotal hits."""
    score = sum(f['weight'] for f in all_findings)
    for url, result in vt_results.items():
        mal = result.get('malicious', 0)
        if mal >= 5:
            score += 40
        elif mal >= 1:
            score += 20
    return min(score, 100)
def score_to_severity(score):
    if score >= 60:
        return 'HIGH'
    elif score >= 30:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    return 'CLEAN'
def generate_report(parsed_email, all_findings, urls, vt_results, source_file):
    score = calculate_threat_score(all_findings, vt_results)
    severity = score_to_severity(score)
    iocs = {
        'urls': urls[:20],
        'sending_domain': extract_domain(parsed_email['from']),
        'reply_to_domain': extract_domain(parsed_email['reply_to']) if parsed_email['reply_to'] else None,
        'originating_ips': extract_ip_from_received(parsed_email['received']),
        'attachments': [a['filename'] for a in parsed_email['attachments']],
    }
    return {
        'report_metadata': {
            'tool': 'Phishing Email Analyzer',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_file': source_file,
            'threat_score': score,
            'severity': severity,
            'total_indicators': len(all_findings),
        },
        'email_summary': {
            'from': parsed_email['from'],
            'subject': parsed_email['subject'],
            'date': parsed_email['date'],
            'reply_to': parsed_email['reply_to'],
        },
        'verdict': (
            f"PHISHING LIKELY — Threat score {score}/100. {len(all_findings)} indicators detected."
            if score >= 30 else
            f"LOW RISK — Threat score {score}/100. Email appears legitimate."
        ),
        'indicators': all_findings,
        'iocs': iocs,
        'virustotal_results': vt_results,
        'recommended_actions': _recommendations(severity),
    }
def _recommendations(severity):
    base = ['Do not click any links in the email', 'Do not open attachments']
    if severity == 'HIGH':
        return base + [
            'Block sender domain at email gateway',
            'Report to security team immediately',
            'Submit URLs to VirusTotal for full scan',
            'Alert other users who may have received this email',
        ]
    elif severity == 'MEDIUM':
        return base + [
            'Verify sender through official channels before responding',
            'Submit suspicious URLs for further analysis',
        ]
    return ['Verify sender identity if unexpected', 'Report if suspicious']
def analyze(eml_filepath, vt_api_key='', output_json=None):
    print(f"\n[*] Analyzing: {eml_filepath}")
    parsed = parse_email(eml_filepath)
    print("[*] Running detection checks...")
    findings = []
    findings += check_header_spoofing(parsed)
    findings += check_brand_impersonation(parsed)
    url_findings, urls = check_suspicious_urls(parsed)
    findings += url_findings
    findings += check_content_signals(parsed)
    findings += check_auth_results(parsed)
    findings += check_attachments(parsed)
    vt_results = {}
    if vt_api_key and vt_api_key != 'YOUR_VT_API_KEY':
        print(f"[*] Checking {min(len(urls),5)} URLs against VirusTotal...")
        vt_results = check_virustotal(urls, vt_api_key)
    else:
        print("[*] Skipping VirusTotal (no API key provided)")
    report = generate_report(parsed, findings, urls, vt_results, eml_filepath)
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to: {output_json}")
    return report
if __name__ == '__main__':
    import sys
    eml_file = sys.argv[1] if len(sys.argv) > 1 else 'sample_emails/phishing_sample.eml'
    vt_key = sys.argv[2] if len(sys.argv) > 2 else ''
    out_file = sys.argv[3] if len(sys.argv) > 3 else 'phishing_report.json'
    report = analyze(eml_file, vt_key, out_file)
    meta = report['report_metadata']
    print(f"\n{'='*55}")
    print(f"  THREAT SCORE : {meta['threat_score']}/100")
    print(f"  SEVERITY     : {meta['severity']}")
    print(f"  INDICATORS   : {meta['total_indicators']}")
    print(f"{'='*55}")
    print(f"\n  VERDICT: {report['verdict']}\n")
    for ind in report['indicators']:
        print(f"  [{ind['weight']:>3} pts] {ind['indicator']}")
        print(f"           {ind['detail']}")
