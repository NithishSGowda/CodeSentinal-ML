"""
test_welcome_email.py - Direct test of welcome email sending
Run: python test_welcome_email.py
"""
import sys
import traceback
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST     = 'smtp.gmail.com'
SMTP_PORT     = 587
SMTP_EMAIL    = 'techtonic202005@gmail.com'
SMTP_PASSWORD = 'xdmwuhtflvfnxxok'

def send_welcome(to_email, name):
    greeting = name.strip() if name else 'Operator'
    first    = greeting.split()[0]

    plain = (
        "SENTINEL AI v1.0 - Operator Enrollment Complete\n"
        "================================================\n\n"
        "Welcome aboard, " + greeting + ".\n\n"
        "Identity confirmed. Your secure operator profile for CodeSentinel ML\n"
        "is now active and ready for operations.\n\n"
        "SOC terminal: http://localhost:3000\n\n"
        "Capabilities unlocked:\n"
        "  - Static vulnerability scanning (50+ patterns)\n"
        "  - Attack surface & chain correlation\n"
        "  - ML-powered TF-IDF risk classification\n"
        "  - AI-assisted secure code patching (Gemini)\n"
        "  - PDF / CSV / JSON report exfiltration\n\n"
        "Stay sharp, Operator.\n"
        "-- SENTINEL AI . CodeSentinel ML Security Operations\n"
    )

    html_parts = []
    html_parts.append('<!DOCTYPE html><html>')
    html_parts.append('<head><meta charset="UTF-8"></head>')
    html_parts.append('<body style="margin:0;padding:0;background:#020308;font-family:\'Courier New\',monospace;">')
    html_parts.append('<table width="100%" cellpadding="0" cellspacing="0" style="background:#020308;min-height:100vh;">')
    html_parts.append('<tr><td align="center" style="padding:40px 20px;">')
    html_parts.append('<table width="560" cellpadding="0" cellspacing="0" style="background:rgba(3,6,17,0.97);border:1px solid rgba(0,240,255,0.18);border-radius:20px;overflow:hidden;">')
    # Top laser border
    html_parts.append('<tr><td style="padding:0;height:3px;background:linear-gradient(90deg,transparent,#00f0ff 30%,#8b5cf6 70%,transparent);"></td></tr>')
    # Logo
    html_parts.append('<tr><td style="padding:36px 44px 20px;text-align:center;background:rgba(0,240,255,0.02);">')
    html_parts.append('<div style="font-size:14px;font-weight:900;letter-spacing:5px;color:#e2e8f0;text-transform:uppercase;">&#128737; CodeSentinel ML</div>')
    html_parts.append('<div style="font-size:9px;letter-spacing:5px;color:#00f0ff;text-transform:uppercase;font-weight:700;margin-top:6px;">SENTINEL AI v1.0 &middot; Operator Enrollment</div>')
    html_parts.append('</td></tr>')
    # Divider
    html_parts.append('<tr><td style="padding:0 44px;"><div style="height:1px;background:rgba(0,240,255,0.08);"></div></td></tr>')
    # Green status badge
    html_parts.append('<tr><td style="padding:24px 44px 0;text-align:center;">')
    html_parts.append('<div style="display:inline-flex;align-items:center;gap:8px;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.25);border-radius:20px;padding:7px 18px;">')
    html_parts.append('<span style="width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px #22c55e;display:inline-block;"></span>')
    html_parts.append('<span style="font-size:9px;font-weight:900;letter-spacing:4px;color:#22c55e;text-transform:uppercase;">Identity Confirmed &middot; Profile Active</span>')
    html_parts.append('</div></td></tr>')
    # Main body
    html_parts.append('<tr><td style="padding:32px 44px;">')
    html_parts.append('<p style="margin:0 0 6px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:rgba(0,240,255,0.55);font-weight:700;">INCOMING TRANSMISSION</p>')
    html_parts.append('<p style="margin:0 0 20px;font-size:17px;color:#e2e8f0;font-weight:700;">Welcome aboard, <span style="color:#00f0ff;">' + first + '</span>.</p>')
    html_parts.append('<p style="margin:0 0 24px;font-size:13px;color:#94a3b8;line-height:1.8;">Your secure operator profile for <strong style="color:#e2e8f0;">CodeSentinel ML</strong> is now fully initialized. Telemetry systems are online. Your SOC command terminal is ready.</p>')
    # Operator dossier
    html_parts.append('<div style="background:rgba(0,0,0,0.4);border:1px solid rgba(0,240,255,0.15);border-radius:14px;padding:22px 26px;margin:0 0 24px;">')
    html_parts.append('<div style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:rgba(0,240,255,0.5);font-weight:700;margin-bottom:16px;">OPERATOR DOSSIER</div>')
    html_parts.append('<table width="100%" cellpadding="0" cellspacing="0">')
    html_parts.append('<tr>')
    html_parts.append('<td style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);">')
    html_parts.append('<span style="font-size:9px;color:rgba(148,163,184,0.5);font-weight:700;letter-spacing:2px;text-transform:uppercase;">NAME</span><br>')
    html_parts.append('<span style="font-size:13px;color:#e2e8f0;font-weight:700;">' + greeting + '</span>')
    html_parts.append('</td>')
    html_parts.append('<td style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);text-align:right;">')
    html_parts.append('<span style="font-size:9px;color:rgba(148,163,184,0.5);font-weight:700;letter-spacing:2px;text-transform:uppercase;">CLEARANCE</span><br>')
    html_parts.append('<span style="font-size:13px;color:#a855f7;font-weight:700;">OPERATOR</span>')
    html_parts.append('</td></tr>')
    html_parts.append('<tr>')
    html_parts.append('<td style="padding:10px 0 0;">')
    html_parts.append('<span style="font-size:9px;color:rgba(148,163,184,0.5);font-weight:700;letter-spacing:2px;text-transform:uppercase;">STATUS</span><br>')
    html_parts.append('<span style="font-size:13px;color:#22c55e;font-weight:700;">ACTIVE</span>')
    html_parts.append('</td>')
    html_parts.append('<td style="padding:10px 0 0;text-align:right;">')
    html_parts.append('<span style="font-size:9px;color:rgba(148,163,184,0.5);font-weight:700;letter-spacing:2px;text-transform:uppercase;">SESSION</span><br>')
    html_parts.append('<span style="font-size:13px;color:#00f0ff;font-weight:700;">INITIALIZED</span>')
    html_parts.append('</td></tr>')
    html_parts.append('</table></div>')
    # Capabilities
    html_parts.append('<div style="margin:0 0 24px;">')
    html_parts.append('<div style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:rgba(139,92,246,0.7);font-weight:700;margin-bottom:12px;">CAPABILITIES UNLOCKED</div>')
    caps = [
        'Static vulnerability scanning &mdash; 50+ attack patterns',
        'Attack surface mapping &amp; chain correlation',
        'ML-powered TF-IDF risk classification',
        'AI-assisted secure code patching (Google Gemini)',
        'PDF / CSV / JSON report exfiltration',
    ]
    for i, cap in enumerate(caps):
        border = 'border-bottom:1px solid rgba(255,255,255,0.03);' if i < len(caps) - 1 else ''
        html_parts.append(
            '<div style="display:flex;align-items:center;gap:10px;padding:7px 0;' + border + '">'
            '<span style="color:#00f0ff;font-size:12px;">&#8594;</span>'
            '<span style="font-size:12px;color:#94a3b8;">' + cap + '</span>'
            '</div>'
        )
    html_parts.append('</div>')
    # CTA
    html_parts.append('<div style="text-align:center;margin:28px 0 8px;">')
    html_parts.append('<a href="http://localhost:3000" style="display:inline-block;background:transparent;border:1px solid rgba(0,240,255,0.4);color:#fff;font-size:11px;font-weight:900;letter-spacing:3px;text-transform:uppercase;text-decoration:none;padding:14px 36px;border-radius:50px;">ENTER THE SYSTEM &#8250;</a>')
    html_parts.append('</div>')
    html_parts.append('</td></tr>')
    # Footer
    html_parts.append('<tr><td style="padding:20px 44px 28px;text-align:center;border-top:1px solid rgba(255,255,255,0.04);">')
    html_parts.append('<p style="margin:0;font-size:9px;letter-spacing:3px;text-transform:uppercase;color:rgba(148,163,184,0.25);font-weight:700;">CODESENTINEL ML &middot; SECURITY OPERATIONS CENTER &middot; LOCAL TELEMETRY</p>')
    html_parts.append('</td></tr>')
    html_parts.append('</table></td></tr></table></body></html>')

    html = ''.join(html_parts)

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[SENTINEL AI] Welcome aboard, ' + first + '. Your operator profile is active.'
        msg['From']    = 'CodeSentinel ML <' + SMTP_EMAIL + '>'
        msg['To']      = to_email
        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print('[OK] Welcome email sent to ' + to_email)
        return True
    except Exception as exc:
        print('[ERROR] ' + str(exc))
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print('Sending welcome email test...')
    ok = send_welcome(SMTP_EMAIL, 'Nithish Kumar')
    print('Result:', 'SUCCESS' if ok else 'FAILED')
    sys.exit(0 if ok else 1)
