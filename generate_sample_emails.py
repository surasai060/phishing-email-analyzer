import os

PHISHING_EML = """\
From: security@paypa1-support.xyz
To: victim@example.com
Subject: URGENT: Your PayPal account has been suspended
Date: Sat, 27 Jun 2026 02:14:33 +0000
Reply-To: no-reply@collect-paypal.click
Return-Path: <bounce@paypa1-support.xyz>
X-Mailer: PHPMailer 5.2.0
Received-SPF: fail (domain of paypa1-support.xyz does not designate 185.220.101.47 as permitted sender)
Authentication-Results: mx.example.com; dkim=fail header.d=paypa1-support.xyz
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear Customer,</p>
<p>We have detected <b>unusual activity</b> on your PayPal account. 
Your account has been <b>suspended</b> due to suspicious login attempts.</p>

<p><b>Urgent action required</b> — you must verify your identity within 24 hours 
or your account will be permanently closed.</p>

<p>Please click the link below to verify your account immediately:</p>

<a href="http://185.220.101.47/paypal/verify?token=abc123">
    http://185.220.101.47/paypal/verify?token=abc123
</a>

<p>Alternatively visit: https://secure-paypal-login.xyz/confirm</p>
<p>Or use our short link: https://bit.ly/3xPaypalVerify</p>

<p>If you do not verify now, your account will be closed permanently.</p>

<p>Thank you,<br>
PayPal Security Team</p>
</body>
</html>
"""
LEGIT_EML = """\
From: newsletter@github.com
To: surasai060@gmail.com
Subject: Your monthly GitHub activity summary
Date: Sat, 27 Jun 2026 09:00:00 +0000
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Received-SPF: pass (github.com designates 192.30.252.1 as permitted sender)
Authentication-Results: mx.example.com; dkim=pass header.d=github.com
Content-Type: text/plain; charset="UTF-8"

Hi Sai,

Here's your GitHub activity summary for June 2026.

You made 23 commits this month across 4 repositories.
Your top repository was siem-log-anomaly-detector with 15 commits.

Keep up the great work!

The GitHub Team
https://github.com
"""
def generate(output_dir='sample_emails'):
    os.makedirs(output_dir, exist_ok=True)

    phishing_path = os.path.join(output_dir, 'phishing_sample.eml')
    legit_path = os.path.join(output_dir, 'legitimate_sample.eml')

    with open(phishing_path, 'w') as f:
        f.write(PHISHING_EML)

    with open(legit_path, 'w') as f:
        f.write(LEGIT_EML)

    print(f"[*] Generated: {phishing_path}")
    print(f"[*] Generated: {legit_path}")
    return phishing_path, legit_path


if __name__ == '__main__':
    generate()
