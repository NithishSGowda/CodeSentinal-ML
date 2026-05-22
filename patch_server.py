"""
patch_server.py - Replaces the broken _send_welcome_email in server.py
with the proven list-append version. Run: python patch_server.py
"""

NEW_FUNC = '''def _send_welcome_email(to_email: str, name: str) -> bool:
    """Send cyberpunk themed welcome email after successful registration."""
    greeting = name.strip() if name else 'Operator'
    first    = greeting.split()[0]

    plain = (
        'SENTINEL AI v1.0 - Operator Enrollment Complete\\n'
        '================================================\\n\\n'
        'Welcome aboard, ' + greeting + '.\\n\\n'
        'Identity confirmed. Your secure operator profile is now active.\\n'
        'SOC terminal: http://localhost:3000\\n\\n'
        'Capabilities:\\n'
        '  - Static vulnerability scanning (50+ patterns)\\n'
        '  - Attack surface & chain correlation\\n'
        '  - ML-powered TF-IDF risk classification\\n'
        '  - AI-assisted secure code patching (Gemini)\\n'
        '  - PDF / CSV / JSON report exfiltration\\n\\n'
        'Stay sharp, Operator.\\n'
    )

    h = []
    h.append('<!DOCTYPE html><html><head><meta charset="UTF-8"></head>')
    h.append('<body style="margin:0;padding:0;background:#020308;font-family:monospace;">')
    h.append('<table width="100%" cellpadding="0" cellspacing="0" style="background:#020308;">')
    h.append('<tr><td align="center" style="padding:40px 20px;">')
    h.append('<table width="560" cellpadding="0" cellspacing="0" style="background:rgba(3,6,17,0.97);border:1px solid rgba(0,240,255,0.18);border-radius:20px;overflow:hidden;">')
    h.append('<tr><td style="padding:0;height:3px;background:linear-gradient(90deg,transparent,#00f0ff 30%,#8b5cf6 70%,transparent);"></td></tr>')
    h.append('<tr><td style="padding:36px 44px 20px;text-align:center;">')
    h.append('<div style="font-size:14px;font-weight:900;letter-spacing:5px;color:#e2e8f0;text-transform:uppercase;">&#128737; CodeSentinel ML</div>')
    h.append('<div style="font-size:9px;letter-spacing:5px;color:#00f0ff;text-transform:uppercase;font-weight:700;margin-top:6px;">SENTINEL AI v1.0 &middot; Operator Enrollment</div>')
    h.append('</td></tr>')
    h.append('<tr><td style="padding:0 44px;"><div style="height:1px;background:rgba(0,240,255,0.08);"></div></td></tr>')
    h.append('<tr><td style="padding:24px 44px 0;text-align:center;">')
    h.append('<div style="display:inline-flex;align-items:center;gap:8px;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.25);border-radius:20px;padding:7px 18px;">')
    h.append('<span style="width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;"></span>')
    h.append('<span style="font-size:9px;font-weight:900;letter-spacing:4px;color:#22c55e;text-transform:uppercase;">Identity Confirmed &middot; Profile Active</span>')
    h.append('</div></td></tr>')
    h.append('<tr><td style="padding:32px 44px;">')
    h.append('<p style="margin:0 0 6px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:rgba(0,240,255,0.55);font-weight:700;">INCOMING TRANSMISSION</p>')
    h.append('<p style="margin:0 0 16px;font-size:17px;color:#e2e8f0;font-weight:700;">Welcome aboard, <span style="color:#00f0ff;">' + first + '</span>.</p>')
    h.append('<p style="margin:0 0 20px;font-size:13px;color:#94a3b8;line-height:1.8;">Your secure operator profile for <strong style="color:#e2e8f0;">CodeSentinel ML</strong> is now fully initialized. Telemetry systems are online.</p>')
    h.append('<div style="background:rgba(0,0,0,0.4);border:1px solid rgba(0,240,255,0.15);border-radius:14px;padding:20px 24px;margin:0 0 20px;">')
    h.append('<div style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:rgba(0,240,255,0.5);font-weight:700;margin-bottom:12px;">OPERATOR DOSSIER</div>')
    h.append('<table width="100%"><tr>')
    h.append('<td><span style="font-size:9px;color:rgba(148,163,184,0.5);">NAME</span><br><span style="font-size:13px;color:#e2e8f0;font-weight:700;">' + greeting + '</span></td>')
    h.append('<td style="text-align:right;"><span style="font-size:9px;color:rgba(148,163,184,0.5);">CLEARANCE</span><br><span style="font-size:13px;color:#a855f7;font-weight:700;">OPERATOR</span></td>')
    h.append('</tr><tr>')
    h.append('<td style="padding-top:8px;"><span style="font-size:9px;color:rgba(148,163,184,0.5);">STATUS</span><br><span style="font-size:13px;color:#22c55e;font-weight:700;">ACTIVE</span></td>')
    h.append('<td style="padding-top:8px;text-align:right;"><span style="font-size:9px;color:rgba(148,163,184,0.5);">SESSION</span><br><span style="font-size:13px;color:#00f0ff;font-weight:700;">INITIALIZED</span></td>')
    h.append('</tr></table></div>')
    caps = [
        'Static vulnerability scanning (50+ patterns)',
        'Attack surface mapping & chain correlation',
        'ML-powered TF-IDF risk classification',
        'AI-assisted secure code patching (Google Gemini)',
        'PDF / CSV / JSON report exfiltration',
    ]
    h.append('<div style="margin:0 0 20px;">')
    h.append('<div style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:rgba(139,92,246,0.7);font-weight:700;margin-bottom:10px;">CAPABILITIES UNLOCKED</div>')
    for cap in caps:
        h.append('<div style="padding:5px 0;font-size:12px;color:#94a3b8;">&#8594; ' + cap + '</div>')
    h.append('</div>')
    h.append('<div style="text-align:center;margin:24px 0 8px;">')
    h.append('<a href="http://localhost:3000" style="display:inline-block;border:1px solid rgba(0,240,255,0.4);color:#fff;font-size:11px;font-weight:900;letter-spacing:3px;text-transform:uppercase;text-decoration:none;padding:14px 36px;border-radius:50px;">ENTER THE SYSTEM &#8250;</a>')
    h.append('</div></td></tr>')
    h.append('<tr><td style="padding:16px 44px 24px;text-align:center;border-top:1px solid rgba(255,255,255,0.04);">')
    h.append('<p style="margin:0;font-size:9px;letter-spacing:3px;text-transform:uppercase;color:rgba(148,163,184,0.25);">CODESENTINEL ML &middot; SECURITY OPERATIONS CENTER</p>')
    h.append('</td></tr></table></td></tr></table></body></html>')
    html = ''.join(h)

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[SENTINEL AI] Welcome aboard, ' + first + '. Your operator profile is active.'
        msg['From']    = 'CodeSentinel ML <' + SMTP_EMAIL + '>'
        msg['To']      = to_email
        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html,  'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print('[AUTH] Welcome email dispatched to ' + to_email)
        return True
    except Exception as exc:
        print('[AUTH] Welcome email SMTP error: ' + str(exc))
        return False

'''

if __name__ == '__main__':
    with open('server.py', 'r', encoding='utf-8') as f:
        content = f.read()

    start_marker = 'def _send_welcome_email(to_email: str, name: str) -> bool:'
    end_marker   = '\n\n\n@app.route(\'/api/auth/verify-otp\''

    start_idx = content.find(start_marker)
    end_idx   = content.find(end_marker, start_idx)

    if start_idx == -1 or end_idx == -1:
        print(f'ERROR: markers not found. start={start_idx}, end={end_idx}')
        exit(1)

    print(f'Replacing lines {start_idx}..{end_idx}')
    new_content = content[:start_idx] + NEW_FUNC + content[end_idx:]

    with open('server.py', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print('Patch applied. Verifying syntax...')
    import py_compile
    try:
        py_compile.compile('server.py', doraise=True)
        print('server.py syntax OK!')
    except py_compile.PyCompileError as e:
        print(f'SYNTAX ERROR: {e}')
        exit(1)
