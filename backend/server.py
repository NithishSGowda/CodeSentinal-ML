"""
server.py
---------
Flask-based web server for CodeSentinel ML
Replaces Streamlit for full HTML/CSS/JS animation control.
Provides JSON endpoint for React/Next.js dashboard.
"""

import os
import sys
import json
import zipfile
import tempfile
import shutil
import requests
import random
import string
import smtplib
import socket
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# ── Force IPv4 for all outbound connections ───────────────────────────────────
# Render's free tier has no IPv6 route — this prevents "Network is unreachable"
_orig_getaddrinfo = socket.getaddrinfo
def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _patched_getaddrinfo

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.model import train_model, predict_risk
from scanner.detector import (
    scan_vulnerabilities, analyze_code_statistics,
    extract_metadata, generate_security_summary,
    compute_vibe_risk, compute_security_maturity
)
from scanner.entry_detector import scan_entry_points, generate_attack_surface_summary
from scanner.attack_chain import detect_attack_chains
from scanner.explanations import get_explanation
from scanner.recommendations import get_recommendation
from scanner.prioritizer import prioritize_findings
from scanner.intelligence import (
    compute_security_grade,
    compute_repository_fingerprint,
    generate_intelligence_summary,
    rank_files_by_risk,
    generate_terminal_logs,
    generate_ml_explanation,
)

from scanner.patcher import generate_code_fix

FILE_CACHE = {}

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app, origins=[
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    r'https://.*\.netlify\.app',
    r'https://.*\.onrender\.com',
], supports_credentials=True)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.php', '.java', '.c', '.cpp', '.cs',
                      '.rb', '.go', '.rs', '.html', '.txt', '.sh', '.env', '.yml', '.yaml'}

# Ensure ML model is trained on startup
train_model(force=False)

# ── Auth / OTP Configuration ─────────────────────────────────────────────────
# Set SMTP_EMAIL and SMTP_PASSWORD as environment variables before starting the server.
# Example: Gmail with App Password (not your regular Gmail password).
# Generate an App Password at: https://myaccount.google.com/apppasswords
SMTP_HOST     = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT     = int(os.environ.get('SMTP_PORT', '465'))
SMTP_EMAIL    = os.environ.get('SMTP_EMAIL', '')       # e.g. yourname@gmail.com
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')    # Gmail App Password
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')    # Brevo HTTP API key (preferred for cloud hosting)

OTP_STORE = {}   # { email: { otp, expires_at, name } }  — always in-memory (short TTL)
USER_STORE = {}  # fallback in-memory store when MongoDB is unavailable

OTP_TTL_SECONDS = 300   # 5 minutes

# ── MongoDB Atlas Connection ──────────────────────────────────────────────────
MONGO_URI = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://techtonic202005_db_user:Nitz%402005@cluster0.ivlbfop.mongodb.net/codesentinel?appName=Cluster0'
)
_mongo_client = None
_users_col     = None   # MongoDB collection handle (None = use fallback)

def _init_mongo():
    """Connect to MongoDB Atlas. Falls back to in-memory USER_STORE on failure."""
    global _mongo_client, _users_col
    if not MONGO_URI:
        print('[DB] No MONGO_URI set — using in-memory USER_STORE.')
        return
    try:
        import pymongo, certifi
        _mongo_client = pymongo.MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=6000,
            tls=True
        )
        _mongo_client.admin.command('ping')
        db = _mongo_client['codesentinel']
        _users_col = db['users']
        _users_col.create_index('email', unique=True)
        print('[DB] MongoDB Atlas connected — users are now persistent!')
    except Exception as exc:
        print(f'[DB] MongoDB unavailable ({exc}) — falling back to in-memory store.')
        _mongo_client = None
        _users_col = None

_init_mongo()

# ── Thin DB helpers (works whether MongoDB is live or not) ────────────────────
def _db_get_user(email: str) -> dict | None:
    if _users_col is not None:
        doc = _users_col.find_one({'email': email}, {'_id': 0})
        return dict(doc) if doc else None
    return USER_STORE.get(email)

def _db_set_user(email: str, data: dict):
    if _users_col is not None:
        _users_col.update_one({'email': email}, {'$set': data}, upsert=True)
    else:
        USER_STORE[email] = data

def _db_update_user(email: str, fields: dict):
    if _users_col is not None:
        _users_col.update_one({'email': email}, {'$set': fields})
    else:
        if email in USER_STORE:
            USER_STORE[email].update(fields)

def _db_delete_user(email: str):
    if _users_col is not None:
        _users_col.delete_one({'email': email})
    else:
        USER_STORE.pop(email, None)

def _generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def _send_email(to_email: str, subject: str, html_body: str, plain_body: str) -> bool:
    """Send email via Brevo API (preferred) or SMTP fallback."""
    # ── Brevo HTTP API (works on all hosting platforms, port 443) ────────────
    if BREVO_API_KEY:
        try:
            resp = requests.post(
                'https://api.brevo.com/v3/smtp/email',
                headers={
                    'api-key': BREVO_API_KEY,
                    'Content-Type': 'application/json',
                },
                json={
                    'sender':      {'name': 'CodeSentinel ML', 'email': SMTP_EMAIL or 'noreply@codesentinel.ml'},
                    'to':          [{'email': to_email}],
                    'subject':     subject,
                    'htmlContent': html_body,
                    'textContent': plain_body,
                },
                timeout=15,
            )
            if resp.status_code in (200, 201):
                print(f'[EMAIL] Sent via Brevo to {to_email}')
                return True
            print(f'[EMAIL] Brevo error {resp.status_code}: {resp.text}')
            return False
        except Exception as exc:
            print(f'[EMAIL] Brevo exception: {exc}')
            return False

    # ── SMTP fallback (for local dev) ─────────────────────────────────────────
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print('[EMAIL] No email credentials configured.')
        return False
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=15) as server:
            server.ehlo()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            from email.mime.multipart import MIMEMultipart as _MM
            from email.mime.text import MIMEText as _MT
            msg = _MM('alternative')
            msg['Subject'] = subject
            msg['From']    = f'CodeSentinel ML <{SMTP_EMAIL}>'
            msg['To']      = to_email
            msg.attach(_MT(plain_body, 'plain'))
            msg.attach(_MT(html_body, 'html'))
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        return True
    except Exception as exc:
        print(f'[EMAIL] SMTP error: {exc}')
        return False


def _send_otp_email(to_email: str, otp: str, name: str = '') -> bool:
    """Send OTP access code email via Brevo API or SMTP fallback."""
    greeting   = f"Operator {name}" if name else "Operator"
    plain_body = (
        f"SENTINEL AI v1.0 — Secure Access System\n"
        f"========================================\n\n"
        f"{greeting}, your one-time access code is:\n\n"
        f"  {otp}\n\n"
        f"This code expires in 5 minutes.\n"
        f"Do not share this code with anyone.\n\n"
        f"If you did not request this, ignore this message.\n\n"
        f"— CodeSentinel ML Security Operations"
    )
    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#020308;font-family:'Courier New',monospace;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#020308;min-height:100vh;">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="520" cellpadding="0" cellspacing="0" style="background:rgba(3,6,17,0.95);border:1px solid rgba(0,240,255,0.18);border-radius:20px;overflow:hidden;">
        <tr><td style="padding:0;height:2px;"><div style="height:2px;background:linear-gradient(90deg,transparent,#00f0ff,#8b5cf6,transparent);"></div></td></tr>
        <tr><td style="padding:36px 40px 24px;text-align:center;">
          <span style="font-size:13px;font-weight:900;letter-spacing:4px;color:#e2e8f0;text-transform:uppercase;">CodeSentinel ML</span><br>
          <div style="font-size:9px;letter-spacing:5px;color:#00f0ff;text-transform:uppercase;font-weight:700;margin-top:4px;">SENTINEL AI v1.0 &middot; Secure Access</div>
        </td></tr>
        <tr><td style="padding:0 40px;"><div style="height:1px;background:rgba(0,240,255,0.08);"></div></td></tr>
        <tr><td style="padding:32px 40px;">
          <p style="margin:0 0 6px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:rgba(0,240,255,0.6);font-weight:700;">INCOMING TRANSMISSION</p>
          <p style="margin:0 0 24px;font-size:15px;color:#e2e8f0;font-weight:600;">{greeting},</p>
          <p style="margin:0 0 24px;font-size:13px;color:#94a3b8;line-height:1.7;">Your secure one-time access code for <strong style="color:#e2e8f0;">CodeSentinel ML</strong> has been generated.</p>
          <div style="background:rgba(0,0,0,0.5);border:1px solid rgba(0,240,255,0.25);border-radius:14px;padding:28px;text-align:center;margin:0 0 24px;">
            <div style="font-size:10px;letter-spacing:4px;text-transform:uppercase;color:rgba(0,240,255,0.5);font-weight:700;margin-bottom:14px;">ACCESS CODE</div>
            <div style="font-size:42px;font-weight:900;letter-spacing:14px;color:#00f0ff;text-shadow:0 0 20px rgba(0,240,255,0.5);">{otp}</div>
            <div style="margin-top:14px;font-size:9px;letter-spacing:3px;text-transform:uppercase;color:rgba(148,163,184,0.5);font-weight:700;">&#9200; EXPIRES IN 5 MINUTES</div>
          </div>
          <p style="margin:0;font-size:11px;color:rgba(148,163,184,0.5);line-height:1.7;">If you did not request this access code, you can safely ignore this message.</p>
        </td></tr>
        <tr><td style="padding:20px 40px 32px;text-align:center;border-top:1px solid rgba(255,255,255,0.04);">
          <p style="margin:0;font-size:9px;letter-spacing:3px;text-transform:uppercase;color:rgba(148,163,184,0.3);font-weight:700;">CODESENTINEL ML &middot; SECURITY OPERATIONS CENTER</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
    return _send_email(to_email, f'[SENTINEL AI] Access Code: {otp}', html_body, plain_body)


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.route('/api/auth/send-otp', methods=['POST'])
def auth_send_otp():
    """Generate a 6-digit OTP and dispatch via SMTP to the provided email."""
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name  = (data.get('name')  or '').strip()
    mode  = (data.get('mode')  or 'login').strip()   # 'login' | 'register'

    if not email or '@' not in email:
        return jsonify({'error': 'A valid email address is required.'}), 400

    if mode == 'register' and not name:
        return jsonify({'error': 'Full name is required for registration.'}), 400

    if not BREVO_API_KEY and (not SMTP_EMAIL or not SMTP_PASSWORD):
        return jsonify({'error': 'Email service not configured on the server.'}), 503

    otp = _generate_otp()
    OTP_STORE[email] = {
        'otp':        otp,
        'expires_at': time.time() + OTP_TTL_SECONDS,
        'name':       name,
        'mode':       mode,
    }

    sent = _send_otp_email(email, otp, name)
    if not sent:
        return jsonify({'error': 'Failed to send OTP email. Check SMTP credentials and try again.'}), 500

    print(f"[AUTH] OTP dispatched to {email} (mode={mode})")
    return jsonify({'success': True, 'message': f'Access code dispatched to {email}. Check your inbox.'})


def _send_welcome_email(to_email: str, name: str) -> bool:
    """Send cyberpunk themed welcome email after successful registration."""
    greeting = name.strip() if name else 'Operator'
    first    = greeting.split()[0]

    plain = (
        'SENTINEL AI v1.0 - Operator Enrollment Complete\n'
        '================================================\n\n'
        'Welcome aboard, ' + greeting + '.\n\n'
        'Identity confirmed. Your secure operator profile is now active.\n'
        f'SOC terminal: {os.environ.get("FRONTEND_URL", "http://localhost:3000")}\n\n'
        'Capabilities:\n'
        '  - Static vulnerability scanning (50+ patterns)\n'
        '  - Attack surface & chain correlation\n'
        '  - ML-powered TF-IDF risk classification\n'
        '  - AI-assisted secure code patching (Gemini)\n'
        '  - PDF / CSV / JSON report exfiltration\n\n'
        'Stay sharp, Operator.\n'
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
    _frontend = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    h.append(f'<a href="{_frontend}" style="display:inline-block;border:1px solid rgba(0,240,255,0.4);color:#fff;font-size:11px;font-weight:900;letter-spacing:3px;text-transform:uppercase;text-decoration:none;padding:14px 36px;border-radius:50px;">ENTER THE SYSTEM &#8250;</a>')
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




@app.route('/api/auth/verify-otp', methods=['POST'])
def auth_verify_otp():
    """Validate the submitted OTP and return a session token on success."""
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    otp   = (data.get('otp')   or '').strip()
    mode  = (data.get('mode')  or 'login').strip()

    if not email or not otp:
        return jsonify({'error': 'Email and access code are required.'}), 400

    record = OTP_STORE.get(email)
    if not record:
        return jsonify({'error': 'No access code found for this email. Request a new one.'}), 400

    if time.time() > record['expires_at']:
        del OTP_STORE[email]
        return jsonify({'error': 'Access code has expired. Request a fresh one.'}), 400

    if record['otp'] != otp:
        return jsonify({'error': 'Invalid access code. Double-check and try again.'}), 400

    # OTP valid — clear it
    name = record.get('name', '')
    del OTP_STORE[email]

    # Generate a simple session token and persist to MongoDB (or in-memory fallback)
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=48))
    _db_set_user(email, {'email': email, 'name': name, 'token': token})

    # Send welcome email for new registrations (non-blocking background thread)
    if mode == 'register':
        import threading
        threading.Thread(
            target=_send_welcome_email,
            args=(email, name),
            daemon=True,
        ).start()

    print(f"[AUTH] Verified OTP for {email} (mode={mode})")
    return jsonify({
        'success': True,
        'token':   token,
        'user':    {'email': email, 'name': name},
    })


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    _db_delete_user(email)
    return jsonify({'success': True})


@app.route('/api/auth/update-name', methods=['POST'])
def auth_update_name():
    """Update the display name for an authenticated operator."""
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    token = (data.get('token') or '').strip()
    name  = (data.get('name')  or '').strip()

    if not email or not token or not name:
        return jsonify({'error': 'Email, token, and name are required.'}), 400

    record = _db_get_user(email)
    if not record or record.get('token') != token:
        return jsonify({'error': 'Unauthorized.'}), 401

    _db_update_user(email, {'name': name})
    print(f'[AUTH] Name updated for {email} -> {name}')
    return jsonify({'success': True, 'user': {'email': email, 'name': name}})


@app.route('/api/auth/delete-account', methods=['POST'])
def auth_delete_account():
    """Permanently remove an operator account from the in-memory store."""
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    token = (data.get('token') or '').strip()

    if not email or not token:
        return jsonify({'error': 'Email and token are required.'}), 400

    record = _db_get_user(email)
    if not record or record.get('token') != token:
        return jsonify({'error': 'Unauthorized — invalid session.'}), 401

    _db_delete_user(email)
    OTP_STORE.pop(email, None)   # also purge any lingering OTP
    print(f'[AUTH] Account deleted: {email}')
    return jsonify({'success': True})




# ═════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════

def read_file_safely(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            lines = content.splitlines(keepends=True)
        return content, lines
    except Exception:
        return None, None


def download_github_repo(repo_url, extract_to):
    repo_url = repo_url.strip().rstrip('/')
    if repo_url.endswith('.git'):
        repo_url = repo_url[:-4]

    # Parse branch name if tree path is embedded in the URL (e.g. /tree/branch-name)
    branch_from_url = None
    import re
    match = re.search(r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)', repo_url, re.IGNORECASE)
    if match:
        owner, repo, branch_from_url = match.groups()
        # Reconstruct base repo url without /tree/branch-name
        repo_url = f"https://github.com/{owner}/{repo}"

    zip_path = os.path.join(extract_to, 'repo.zip')
    
    # Define branches to attempt. Prioritize branch extracted from URL
    branches_to_try = []
    if branch_from_url:
        branches_to_try.append(branch_from_url)
    branches_to_try.extend(['main', 'master', 'dev', 'develop', 'prod'])
    
    # De-duplicate while preserving order
    seen = set()
    branches_to_try = [x for x in branches_to_try if not (x in seen or seen.add(x))]

    for branch in branches_to_try:
        url = f"{repo_url}/archive/refs/heads/{branch}.zip"
        try:
            print(f"[GITHUB_DOWNLOAD] Attempting branch '{branch}' from url: {url}...")
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                with open(zip_path, 'wb') as f:
                    f.write(resp.content)
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(extract_to)
                os.remove(zip_path)
                print(f"[GITHUB_DOWNLOAD] Successfully downloaded and extracted branch '{branch}'!")
                return True
        except Exception as e:
            print(f"[GITHUB_DOWNLOAD_ERROR] Failed branch '{branch}': {e}")
            continue
            
    # As a final fallback, let's try direct main zipball endpoint if branches fail
    fallback_url = f"{repo_url}/zipball/master"
    try:
        print(f"[GITHUB_DOWNLOAD] Running fallback zipball: {fallback_url}...")
        resp = requests.get(fallback_url, timeout=30)
        if resp.status_code == 200:
            with open(zip_path, 'wb') as f:
                f.write(resp.content)
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(extract_to)
            os.remove(zip_path)
            print("[GITHUB_DOWNLOAD] Successfully downloaded master zipball!")
            return True
    except Exception as e:
        print(f"[GITHUB_DOWNLOAD_ERROR] Fallback failed: {e}")

    return False


def generate_pdf_report(fp_data, pf, ac, rf):
    from fpdf import FPDF
    import uuid
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(190, 10, "CodeSentinel ML Security Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(190, 10, "1. Repository Fingerprint", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=11)
    
    for k in ("security_grade", "grade_label", "risk_score", "total_files",
              "total_vulnerabilities", "attack_chains", "critical_count"):
        pdf.cell(190, 8, f"  {k}: {fp_data.get(k, 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(190, 10, "2. Priority Findings (top 10)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    for f in pf[:10]:
        txt = f"[{f.get('priority', 'Low')}] {f.get('file', 'unknown')}:{f.get('line', 0)} - {f.get('issue', 'Vulnerability')}"
        # Let fpdf2 handle text wrapping naturally inside the cell
        pdf.multi_cell(190, 7, txt)
    pdf.ln(4)
    
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(190, 10, "3. Attack Chains (top 5)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    for i, c in enumerate(ac[:5], 1):
        txt = f"Chain {i}: {c.get('attack_type', 'Exploit Flow')} in {c.get('file', 'unknown')}:{c.get('line', 0)}  Source: {c.get('source', '')} -> Sink: {c.get('sink', '')}"
        pdf.multi_cell(190, 7, txt)
    pdf.ln(4)
    
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(190, 10, "4. Top Risky Files", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    for r in rf[:5]:
        txt = f"{r.get('file', 'unknown')} - {r.get('risk_label', 'Safe')} (score {r.get('composite_score', 0)})"
        pdf.multi_cell(190, 7, txt)
    
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, f"report_{uuid.uuid4().hex[:8]}.pdf")
    pdf.output(path)
    return path


def scan_project(project_path):
    all_findings, all_entry_points, file_risks, files_data = [], [], [], []
    project_stats = {
        'total_files': 0, 'total_lines': 0, 'blank_lines': 0,
        'comments': 0, 'imports': 0, 'functions': 0, 'classes': 0, 'size_kb': 0.0
    }

    MAX_FILES = 500  # safeguard for massive repository

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git', 'dist', 'build', 'venv', '.venv')]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext.lower() not in ALLOWED_EXTENSIONS:
                continue
            
            # safeguard for massive repository
            if project_stats['total_files'] >= MAX_FILES:
                continue

            fpath = os.path.join(root, fname)
            
            # Safeguard for extremely large single files (> 1MB)
            try:
                fsize = os.path.getsize(fpath)
                if fsize > 1 * 1024 * 1024:
                    continue
            except Exception:
                pass

            rel = os.path.relpath(fpath, project_path)
            content, lines = read_file_safely(fpath)
            if content is None:
                continue

            project_stats['total_files'] += 1
            meta = extract_metadata(fpath, fname)
            project_stats['size_kb'] += meta['size_kb']

            stats = analyze_code_statistics(lines)
            for k in ['total_lines', 'blank_lines', 'comments', 'imports', 'functions', 'classes']:
                project_stats[k] += stats[k]

            files_data.append({'file': rel, 'content': content, 'lines': lines})

            vulns = scan_vulnerabilities(lines)
            for v in vulns:
                v['file'] = rel
            all_findings.extend(vulns)

            entries = scan_entry_points(lines)
            for e in entries:
                e['file'] = rel
                e['pattern'] = e.get('matched_code', e.get('name', ''))
            all_entry_points.extend(entries)

            ml = predict_risk(content)
            file_risks.append({
                'file': rel,
                'ml_prediction': ml['prediction'],
                'confidence': ml['confidence'],
                'all_scores': ml['all_scores']
            })

    return all_findings, all_entry_points, project_stats, file_risks, files_data


# ═════════════════════════════════════════════════════════════════════════
# ROUTES
# ═════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    from flask import redirect
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    return redirect(frontend_url, code=302)


@app.route('/api/scan/path', methods=['POST'])
def scan_local_path():
    data = request.get_json()
    path = data.get('path', '').strip()
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'Invalid or non-existent directory path.'}), 400
    return _run_scan(path, os.path.basename(path))


@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url.startswith('http'):
        return jsonify({'error': 'Invalid GitHub URL.'}), 400

    tmp = tempfile.mkdtemp(dir=UPLOAD_DIR)
    try:
        ok = download_github_repo(url, tmp)
        if not ok:
            shutil.rmtree(tmp, ignore_errors=True)
            return jsonify({'error': 'Failed to download repository. Check URL or branch.'}), 400
        # Find the extracted folder (first subdirectory)
        subdirs = [d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d))]
        project_path = os.path.join(tmp, subdirs[0]) if subdirs else tmp
        name = url.rstrip('/').split('/')[-1]
        result = _run_scan(project_path, name)
        shutil.rmtree(tmp, ignore_errors=True)
        return result
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/upload', methods=['POST'])
def scan_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded.'}), 400
    f = request.files['file']
    if not f.filename.endswith('.zip'):
        return jsonify({'error': 'Only .zip files supported.'}), 400

    tmp = tempfile.mkdtemp(dir=UPLOAD_DIR)
    try:
        zip_path = os.path.join(tmp, 'upload.zip')
        f.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(tmp)
        os.remove(zip_path)
        subdirs = [d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d))]
        project_path = os.path.join(tmp, subdirs[0]) if subdirs else tmp
        name = f.filename.replace('.zip', '')
        result = _run_scan(project_path, name)
        shutil.rmtree(tmp, ignore_errors=True)
        return result
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return jsonify({'error': str(e)}), 500


def _run_scan(project_path, project_name):
    findings, entry_points, stats, file_risks, files_data = scan_project(project_path)

    # Cache file content globally for on-demand code patch and viewer
    global FILE_CACHE
    FILE_CACHE.clear()
    for fd in files_data:
        FILE_CACHE[fd['file']] = fd['content']

    # Empty repository handling
    if stats['total_files'] == 0:
        return jsonify({'error': 'No supported source files found in the specified path.'}), 400

    chains = detect_attack_chains(files_data)
    all_code = '\n'.join(fd['content'] for fd in files_data)
    vibe = compute_vibe_risk(findings, entry_points, chains, all_code)
    maturity = compute_security_maturity(findings, stats, entry_points)
    
    summary_msg, summary_type, base_score = generate_security_summary(findings)
    attack_surface = generate_attack_surface_summary(entry_points)

    # ML risk calculation
    hr = [r for r in file_risks if r["ml_prediction"] == "High Risk"]
    mr = [r for r in file_risks if r["ml_prediction"] == "Medium Risk"]
    project_ml_risk = "High Risk" if hr else ("Medium Risk" if mr else "Safe")
    ml_adjusted_score = base_score
    if project_ml_risk == "High Risk":
        ml_adjusted_score = max(0, ml_adjusted_score - 20)
    elif project_ml_risk == "Medium Risk":
        ml_adjusted_score = max(0, ml_adjusted_score - 10)

    # Day 5 intelligence calculations
    prioritized = prioritize_findings(findings, chains, entry_points, file_risks)
    grade = compute_security_grade(ml_adjusted_score, chains, prioritized, vibe["score"])
    fingerprint = compute_repository_fingerprint(stats, findings, entry_points, chains, file_risks, grade, ml_adjusted_score)
    narrative = generate_intelligence_summary(findings, chains, entry_points, file_risks, fingerprint)
    ranked_files = rank_files_by_risk(files_data, findings, chains, file_risks)
    terminal_logs = generate_terminal_logs(stats, findings, chains, entry_points, file_risks, fingerprint, grade)

    # Severity counts from prioritized
    high = sum(1 for f in findings if f['severity'] == 'High')
    medium = sum(1 for f in findings if f['severity'] == 'Medium')
    low = sum(1 for f in findings if f['severity'] == 'Low')

    # Top risky files from ML
    top_files = sorted(file_risks, key=lambda x: x['confidence'], reverse=True)[:10]

    # File risks explanation mapping for explanation panels
    ml_explanations = {}
    for fr in file_risks:
        if fr["ml_prediction"] in ("High Risk", "Medium Risk"):
            ml_explanations[fr["file"]] = generate_ml_explanation(
                fr["file"], fr["ml_prediction"], fr["confidence"], findings, chains
            )

    # We also want to include recommendations and explanations for findings!
    recs_map = {}
    exps_map = {}
    for f in findings:
        issue = f["issue"]
        if issue not in recs_map:
            recs_map[issue] = get_recommendation(issue)
        if issue not in exps_map:
            exps_map[issue] = get_explanation(issue)

    stats['size_kb'] = round(stats['size_kb'], 2)

    return jsonify({
        'project_name': project_name,
        'stats': stats,
        'security_score': ml_adjusted_score,
        'base_score': base_score,
        'project_ml_risk': project_ml_risk,
        'vibe_risk': vibe,
        'maturity': maturity,
        'summary': summary_msg,
        'findings': findings[:200],
        'prioritized_findings': prioritized[:200],
        'entry_points': entry_points[:100],
        'attack_surface': attack_surface,
        'attack_chains': chains[:50],
        'file_risks': top_files,
        'ranked_files': ranked_files[:50],
        'severity_counts': {'high': high, 'medium': medium, 'low': low},
        'security_grade': grade,
        'fingerprint': fingerprint,
        'intelligence_narrative': narrative,
        'terminal_logs': terminal_logs,
        'ml_explanations': ml_explanations,
        'recommendations': recs_map,
        'explanations': exps_map
    })


# ═════════════════════════════════════════════════════════════════════════
# EXPORTS
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/report/pdf', methods=['POST'])
def export_pdf():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        fingerprint = data.get('fingerprint', {})
        prioritized = data.get('prioritized_findings', [])
        attack_chains = data.get('attack_chains', [])
        ranked_files = data.get('ranked_files', [])
        
        pdf_path = generate_pdf_report(fingerprint, prioritized, attack_chains, ranked_files)
        return send_from_directory(
            directory=os.path.dirname(pdf_path),
            path=os.path.basename(pdf_path),
            as_attachment=True,
            download_name="CodeSentinel_ML_Report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/csv', methods=['POST'])
def export_csv():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        prioritized = data.get('prioritized_findings', [])
        if not prioritized:
            return jsonify({'error': 'No prioritized findings to export'}), 400
        
        import io
        import pandas as pd
        df = pd.DataFrame(prioritized)
        
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        
        return app.response_class(
            buf.getvalue(),
            mimetype='text/csv',
            headers={'Content-disposition': 'attachment; filename=CodeSentinel_Findings.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/json', methods=['POST'])
def export_json():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        rdata = {
            "fingerprint": data.get('fingerprint', {}),
            "security_grade": data.get('security_grade', {}),
            "attack_chains": data.get('attack_chains', []),
            "prioritized_findings": data.get('prioritized_findings', []),
            "stats": data.get('stats', {})
        }
        
        return jsonify(rdata)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/finding/patch', methods=['POST'])
def patch_finding():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        file_path = data.get('file')
        line_num = data.get('line')
        issue = data.get('issue')
        matched_code = data.get('matched_code', '')
        
        if not file_path or not line_num or not issue:
            return jsonify({'error': 'Missing required fields: file, line, issue'}), 400
            
        # Get from FILE_CACHE
        if file_path not in FILE_CACHE:
            return jsonify({'error': f'File {file_path} not found in scan cache.'}), 404
            
        file_content = FILE_CACHE[file_path]
        file_lines = file_content.splitlines(keepends=True)
        
        try:
            idx = int(line_num) - 1
        except ValueError:
            return jsonify({'error': 'Invalid line number'}), 400
            
        original_line = file_lines[idx] if (0 <= idx < len(file_lines)) else matched_code
        
        # Extract surrounding context lines (5 before, 5 after) for context-aware AI patching
        start_ctx = max(0, idx - 5)
        end_ctx = min(len(file_lines), idx + 6)
        context_lines = [line for line in file_lines[start_ctx:end_ctx]]
        
        fixed_line = None
        explanation = None
        
        # Attempt Online Google Gemini AI patching if configured
        if os.getenv("GEMINI_API_KEY"):
            try:
                from scanner.gemini_patcher import generate_gemini_fix
                fixed_line, explanation = generate_gemini_fix(
                    issue_name=issue,
                    file_path=file_path,
                    line_num=line_num,
                    line_content=original_line,
                    context_lines=context_lines
                )
            except Exception as e:
                print(f"[PATCH_ENDPOINT] Warning: Google Gemini API invocation threw an exception: {e}")
        
        # Fall back to local deterministic patcher if AI patch is unavailable or key is missing
        if not fixed_line or not explanation:
            print("[PATCH_ENDPOINT] Utilizing fallback local offline deterministic patcher.")
            fixed_line, explanation = generate_code_fix(issue, original_line)
            
        if original_line.endswith('\n') and not fixed_line.endswith('\n'):
            if original_line.endswith('\r\n') and not fixed_line.endswith('\r\n'):
                fixed_line_with_nl = fixed_line + '\r\n'
            else:
                fixed_line_with_nl = fixed_line + '\n'
        else:
            fixed_line_with_nl = fixed_line
            
        patched_lines = list(file_lines)
        if 0 <= idx < len(patched_lines):
            patched_lines[idx] = fixed_line_with_nl
            
        patched_file_content = "".join(patched_lines)
        
        return jsonify({
            "vulnerable_line": original_line.rstrip('\r\n'),
            "fixed_line": fixed_line.rstrip('\r\n'),
            "explanation": explanation,
            "patched_file_content": patched_file_content,
            "file_lines": [line.rstrip('\r\n') for line in file_lines]
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n  === CodeSentinel ML - Flask Server ===")
    print("  http://localhost:5000")
    print("  =====================================\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
