import re
import json
import time
import email
import email.policy
import base64
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

# Exact shortener domains (matched as full domain, not substring:
# a substring check for "t.co" would wrongly match "microsoft.com").
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'rb.gy', 'is.gd', 'cutt.ly', 'buff.ly',
]

DANGEROUS_EXT = ['.exe', '.bat', '.vbs', '.js', '.ps1', '.scr', '.msi', '.cmd', '.jar', '.hta', '.iso']
DOCUMENT_EXT = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.jpg', '.jpeg', '.png', '.zip']

URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
IP_URL_PATTERN = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}')
# Non-capturing inner group so findall() returns the FULL IP, not only the last octet.
RECEIVED_IP_PATTERN = re.compile(r'\[((?:\d{1,3}\.){3}\d{1,3})\]')

VT_MAX_URLS = 4            # VirusTotal free tier: 4 requests per minute

MITRE_PHISHING = 'T1566 - Phishing'
MITRE_LINK = 'T1566.002 - Spearphishing Link'
MITRE_ATTACHMENT = 'T1566.001 - Spearphishing Attachment'


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
            if 'attachment' in disp or part.get_filename():
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
        'from': str(msg.get('From', '')),
        'reply_to': str(msg.get('Reply-To', '')),
        'to': str(msg.get('To', '')),
        'subject': str(msg.get('Subject', '')),
        'date': str(msg.get('Date', '')),
        'return_path': str(msg.get('Return-Path', '')),
        'received': [str(h) for h in msg.get_all('Received', [])],
        'x_mailer': str(msg.get('X-Mailer', '')),
        'x_originating_ip': str(msg.get('X-Originating-IP', '')),
        'spf': str(msg.get('Received-SPF', '')),
        'dkim': str(msg.get('Authentication-Results', '')),
        'body_text': body_text,
        'body_html': body_html,
        'attachments': attachments,
        'raw_headers': {k: str(v) for k, v in msg.items()},
    }


def extract_domain(email_addr):
    """Pull domain from an email address string."""
    match = re.search(r'@([\w.\-]+)', email_addr or '')
    return match.group(1).lower() if match else None


def extract_email_address(header_value):
    """Pull the plain address out of 'Name <user@domain>'."""
    match = re.search(r'[\w.+\-]+@[\w.\-]+', header_value or '')
    return match.group(0).lower() if match else None


def domain_matches(domain, legit_domain):
    """True only if domain IS legit_domain or a real subdomain of it.
    'paypal.com' and 'mail.paypal.com' -> True
    'paypal.com.evil.xyz' and 'paypa1.com' -> False"""
    if not domain or not legit_domain:
        return False
    return domain == legit_domain or domain.endswith('.' + legit_domain)


def mentions_word(word, text):
    """Whole-word match, so 'irs' does not match 'first' and 'apple' not 'pineapple'."""
    return re.search(r'\b' + re.escape(word) + r'\b', text) is not None


def extract_urls(text):
    """Extract all unique URLs from text/HTML body (order kept)."""
    urls = URL_PATTERN.findall(text)
    cleaned = [u.rstrip('.,;)>"\']') for u in urls]
    return list(dict.fromkeys(cleaned))


def extract_ip_from_received(received_headers, x_originating_ip=''):
    """Pull originating IPs from Received headers and X-Originating-IP."""
    ips = []
    for header in received_headers:
        ips.extend(RECEIVED_IP_PATTERN.findall(header))
    if x_originating_ip:
        ips.extend(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', x_originating_ip))
    return list(dict.fromkeys(ips))


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
    """Check if the email CLAIMS to be from a known brand (sender name or subject)
    but is sent from a domain that does not belong to that brand.
    Only mentioning a brand in the body (e.g. a link to paypal.com) is not impersonation."""
    findings = []
    display_name = parsed['from'].split('<')[0].lower()
    claim_text = display_name + ' ' + parsed['subject'].lower()
    from_domain = extract_domain(parsed['from']) or ''

    for brand, legit_domain in KNOWN_BRAND_DOMAINS.items():
        if not mentions_word(brand, claim_text):
            continue
        if legit_domain and not domain_matches(from_domain, legit_domain):
            findings.append({
                'indicator': f'Brand Impersonation ({brand.title()})',
                'detail': f"Sender name/subject claims '{brand}' but sender domain is '{from_domain}' (expected '{legit_domain}')",
                'weight': 30,
            })
        elif from_domain in FREE_EMAIL_DOMAINS:
            findings.append({
                'indicator': f'Brand via Free Email ({brand.title()})',
                'detail': f"'{brand}' claimed but sent from free email provider '{from_domain}'",
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
        domain = (parsed_url.hostname or '').lower()

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
                break

        if any(domain_matches(domain, s) for s in URL_SHORTENERS):
            findings.append({
                'indicator': 'URL Shortener Detected',
                'detail': f"Shortened URL hides true destination: {url[:80]}",
                'weight': 15,
                'url': url,
            })

        # Brand name inside a domain that is NOT the brand's real domain,
        # e.g. paypal.evil-site.xyz or secure-paypal-login.xyz
        tokens = re.split(r'[.\-]', domain)
        for brand, legit_domain in KNOWN_BRAND_DOMAINS.items():
            if legit_domain and brand in tokens and not domain_matches(domain, legit_domain):
                findings.append({
                    'indicator': 'Brand Lookalike Domain',
                    'detail': f"Domain uses the name '{brand}' but is not {legit_domain}: {domain}",
                    'weight': 35,
                    'url': url,
                })
                break

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
    """Check SPF, DKIM and DMARC authentication results."""
    findings = []
    spf = parsed['spf'].lower()
    auth = parsed['dkim'].lower()          # Authentication-Results header

    if spf.startswith(('fail', 'softfail')) or 'spf=fail' in auth or 'spf=softfail' in auth:
        findings.append({
            'indicator': 'SPF Failure',
            'detail': f"SPF check failed: {(parsed['spf'] or 'see Authentication-Results')[:100]}",
            'weight': 25,
        })
    if 'dkim=fail' in auth or 'dkim=none' in auth:
        findings.append({
            'indicator': 'DKIM Failure',
            'detail': "DKIM signature missing or invalid",
            'weight': 20,
        })
    if 'dmarc=fail' in auth:
        findings.append({
            'indicator': 'DMARC Failure',
            'detail': "DMARC policy check failed for the sender domain",
            'weight': 20,
        })
    return findings


def check_attachments(parsed):
    """Flag dangerous attachment types (checked once per attachment)."""
    findings = []
    for att in parsed['attachments']:
        fname = (att['filename'] or '').lower()
        ext = '.' + fname.rsplit('.', 1)[-1] if '.' in fname else ''
        if ext in DANGEROUS_EXT:
            findings.append({
                'indicator': f'Dangerous Attachment ({ext})',
                'detail': f"Executable/script attachment detected: {att['filename']}",
                'weight': 40,
            })
            # double extension like invoice.pdf.exe
            parts = fname.rsplit('.', 2)
            if len(parts) == 3 and '.' + parts[1] in DOCUMENT_EXT:
                findings.append({
                    'indicator': 'Double Extension Attachment',
                    'detail': f"Document disguised as executable: {att['filename']}",
                    'weight': 35,
                })
    return findings


def vt_url_id(url):
    """VirusTotal API v3 URL identifier = base64url(url) without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def check_virustotal(urls, api_key):
    """Check URLs against VirusTotal API v3. Returns dict of url -> result."""
    import urllib.request
    import urllib.error
    results = {}
    if not api_key or api_key == 'YOUR_VT_API_KEY':
        return results

    for i, url in enumerate(urls[:VT_MAX_URLS]):
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/urls/{vt_url_id(url)}",
                headers={"x-apikey": api_key},
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
        except urllib.error.HTTPError as e:
            if e.code == 404:
                results[url] = {'status': 'not_in_virustotal',
                                'note': 'URL has never been scanned by VirusTotal'}
            elif e.code == 429:
                results[url] = {'status': 'rate_limited',
                                'note': 'VirusTotal free-tier limit reached; try again in 1 minute'}
            elif e.code == 401:
                results[url] = {'status': 'invalid_api_key'}
            else:
                results[url] = {'error': f'HTTP {e.code}'}
        except Exception as e:
            results[url] = {'error': str(e)}
        if i < min(len(urls), VT_MAX_URLS) - 1:
            time.sleep(0.5)
    return results


def calculate_threat_score(all_findings, vt_results):
    """Sum weights from all findings + VirusTotal hits, capped at 100."""
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


def map_mitre(parsed_email, urls, severity):
    """Map the email to MITRE ATT&CK phishing techniques."""
    if severity in ('CLEAN', 'LOW'):
        return []
    techniques = [MITRE_PHISHING]
    if urls:
        techniques.append(MITRE_LINK)
    if parsed_email['attachments']:
        techniques.append(MITRE_ATTACHMENT)
    return techniques


def generate_report(parsed_email, all_findings, urls, vt_results, source_file):
    score = calculate_threat_score(all_findings, vt_results)
    severity = score_to_severity(score)
    url_domains = list(dict.fromkeys(
        (urllib.parse.urlparse(u).hostname or '').lower() for u in urls
    ))
    iocs = {
        'sender_address': extract_email_address(parsed_email['from']),
        'sending_domain': extract_domain(parsed_email['from']),
        'reply_to_domain': extract_domain(parsed_email['reply_to']) if parsed_email['reply_to'] else None,
        'urls': urls[:20],
        'url_domains': url_domains[:20],
        'originating_ips': extract_ip_from_received(parsed_email['received'],
                                                    parsed_email['x_originating_ip']),
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
        'mitre_attack': map_mitre(parsed_email, urls, severity),
        'iocs': iocs,
        'virustotal_results': vt_results,
        'recommended_actions': _recommendations(severity),
    }


def _recommendations(severity):
    base = ['Do not click any links in the email', 'Do not open attachments']
    if severity == 'HIGH':
        return base + [
            'Block sender domain and URLs at email gateway and proxy',
            'Report to security team immediately',
            'Search mailboxes for other recipients and purge the email',
            'Reset credentials of any user who clicked and entered a password',
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
        print(f"[*] Checking {min(len(urls), VT_MAX_URLS)} URLs against VirusTotal...")
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
    print(f"  MITRE ATT&CK : {', '.join(report['mitre_attack']) or '-'}")
    print(f"{'='*55}")
    print(f"\n  VERDICT: {report['verdict']}\n")
    for ind in report['indicators']:
        print(f"  [{ind['weight']:>3} pts] {ind['indicator']}")
        print(f"             {ind['detail']}")
