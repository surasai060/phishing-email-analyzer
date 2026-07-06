import streamlit as st
import json
import os
import tempfile
from analyzer import analyze
st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="🎣",
    layout="wide"
)
st.markdown("""
<style>
.high   { background:#ff4b4b22; border-left:4px solid #ff4b4b; padding:12px; border-radius:4px; margin:6px 0; }
.medium { background:#ffa50022; border-left:4px solid #ffa500; padding:12px; border-radius:4px; margin:6px 0; }
.low    { background:#ffd70022; border-left:4px solid #ffd700; padding:12px; border-radius:4px; margin:6px 0; }
.clean  { background:#00c80022; border-left:4px solid #00c800; padding:12px; border-radius:4px; margin:6px 0; }
.ioc-box { background:#1e2130; padding:10px 14px; border-radius:6px; font-family:monospace; font-size:13px; margin:4px 0; }
</style>
""", unsafe_allow_html=True)

st.title("Phishing Email Analyzer")
st.caption("Upload a .eml file to analyze for phishing indicators, header spoofing, malicious URLs, and IOCs.")
with st.sidebar:
    st.header("Settings")
    vt_api_key = st.text_input(
        "VirusTotal API Key (optional)",
        type="password",
        help="Get a free key at virustotal.com. Without it, URL reputation checks are skipped."
    )
    st.markdown("---")
    st.markdown("**What This Checks**")
    st.markdown("""
- 📧 Header spoofing (Reply-To / Return-Path mismatch)
- 🏢 Brand impersonation detection
- 🔗 Suspicious / IP-based URLs
- ⚡ Urgency language & phishing keywords
- 🔐 SPF / DKIM authentication results
- 📎 Dangerous attachment types
- 🌐 VirusTotal URL reputation (with API key)
""")
    st.markdown("---")
    st.markdown("**Threat Score**")
    st.markdown("🔴 HIGH: 60–100  \n🟠 MEDIUM: 30–59  \n🟡 LOW: 1–29  \n🟢 CLEAN: 0")
col1, col2 = st.columns([2, 1])

with col1:
    uploaded = st.file_uploader("Upload .eml file", type=['eml', 'txt'])
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    use_phishing = st.button("🎣 Load Phishing Sample", use_container_width=True)
    use_legit = st.button("✅ Load Legit Sample", use_container_width=True)
    if use_phishing or use_legit:
        from generate_sample_emails import generate
        generate()
        st.session_state['sample_type'] = 'phishing' if use_phishing else 'legit'
report = None
if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name
    with st.spinner("Analyzing email..."):
        report = analyze(tmp_path, vt_api_key or '')
    os.unlink(tmp_path)
elif st.session_state.get('sample_type'):
    sample_file = (
        'sample_emails/phishing_sample.eml'
        if st.session_state['sample_type'] == 'phishing'
        else 'sample_emails/legitimate_sample.eml'
    )
    if os.path.exists(sample_file):
        with st.spinner("Analyzing sample email..."):
            report = analyze(sample_file, vt_api_key or '')

if report:
    meta = report['report_metadata']
    severity = meta['severity']
    score = meta['threat_score']
    indicators = report['indicators']
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threat Score", f"{score}/100")
    m2.metric("Severity", severity)
    m3.metric("Indicators Found", meta['total_indicators'])
    m4.metric("URLs Extracted", len(report['iocs']['urls']))
    color = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'CLEAN': 'clean'}[severity]
    icon = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡', 'CLEAN': '🟢'}[severity]
    st.markdown(f'<div class="{color}"><strong>{icon} {report["verdict"]}</strong></div>', unsafe_allow_html=True)
    st.markdown("### 📧 Email Header Summary")
    es = report['email_summary']
    h1, h2 = st.columns(2)
    with h1:
        st.write(f"**From:** `{es['from']}`")
        st.write(f"**Subject:** {es['subject']}")
    with h2:
        st.write(f"**Date:** {es['date']}")
        if es['reply_to']:
            st.write(f"**Reply-To:** `{es['reply_to']}`")
    if indicators:
        st.markdown("### 🚨 Phishing Indicators")
        for ind in sorted(indicators, key=lambda x: -x['weight']):
            pts = ind['weight']
            css = 'high' if pts >= 30 else 'medium' if pts >= 15 else 'low'
            st.markdown(
                f'<div class="{css}"><strong>{ind["indicator"]}</strong> '
                f'<span style="float:right;opacity:0.7">+{pts} pts</span><br>'
                f'<small>{ind["detail"]}</small></div>',
                unsafe_allow_html=True
            )
    else:
        st.success("✅ No phishing indicators detected.")
    st.markdown("### 🔍 Indicators of Compromise (IOCs)")
    iocs = report['iocs']
    i1, i2 = st.columns(2)
    with i1:
        st.write("**Sending Domain:**")
        st.markdown(f'<div class="ioc-box">{iocs["sending_domain"] or "unknown"}</div>', unsafe_allow_html=True)
        if iocs['reply_to_domain']:
            st.write("**Reply-To Domain:**")
            st.markdown(f'<div class="ioc-box">{iocs["reply_to_domain"]}</div>', unsafe_allow_html=True)
        if iocs['originating_ips']:
            st.write("**Originating IPs:**")
            for ip in iocs['originating_ips']:
                st.markdown(f'<div class="ioc-box">{ip}</div>', unsafe_allow_html=True)
    with i2:
        if iocs['urls']:
            st.write(f"**Extracted URLs ({len(iocs['urls'])}):**")
            for url in iocs['urls'][:8]:
                st.markdown(f'<div class="ioc-box">{url[:70]}{"..." if len(url)>70 else ""}</div>', unsafe_allow_html=True)
    if report['virustotal_results']:
        st.markdown("### 🌐 VirusTotal Results")
        for url, result in report['virustotal_results'].items():
            if 'error' not in result:
                mal = result.get('malicious', 0)
                color = 'high' if mal >= 5 else 'medium' if mal >= 1 else 'clean'
                st.markdown(
                    f'<div class="{color}"><code>{url[:60]}...</code><br>'
                    f'Malicious: {mal} | Suspicious: {result.get("suspicious",0)} | Harmless: {result.get("harmless",0)}</div>',
                    unsafe_allow_html=True
                )
    st.markdown("### 📋 Recommended Actions")
    for rec in report['recommended_actions']:
        st.markdown(f"- {rec}")
    st.markdown("---")
    st.download_button(
        label="📥 Download Phishing Report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"phishing_report_{meta['generated_at'].replace(' ','_').replace(':','-')}.json",
        mime="application/json"
    )
else:
    st.info("👆 Upload a .eml file or click a sample button to run the analyzer.")
