# -*- coding: utf-8 -*-
"""
One-time script to inject 120+ new Medium Risk samples into build_dataset.py.
Run once: python backend/ml/inject_medium_risk.py
"""
import os

BUILD_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build_dataset.py')

NEW_SAMPLES = r"""
    # === EXTENDED v3 — Boosting Medium Risk recall ========================
    # Medium Risk = security weakness, NOT directly exploitable with user input
    # (unlike High Risk = direct injection/RCE possible)
    # =====================================================================

    # -- Hardcoded credentials, more variants ---
    ("API_SECRET = 'my-api-secret-key'", "Medium Risk"),
    ("POSTGRES_PASSWORD = 'postgres'", "Medium Risk"),
    ("MYSQL_ROOT_PASSWORD = 'root'", "Medium Risk"),
    ("REDIS_PASSWORD = 'redis123'", "Medium Risk"),
    ("RABBITMQ_DEFAULT_PASS = 'guest'", "Medium Risk"),
    ("admin_password = '123456'", "Medium Risk"),
    ("test_password = 'password'", "Medium Risk"),
    ("default_key = 'changeme'", "Medium Risk"),
    ("secret = 'abc123'", "Medium Risk"),
    ("DB_URI = 'mysql://user:password@127.0.0.1:3306/mydb'", "Medium Risk"),
    ("ftp_credentials = {'host': 'ftp.example.com', 'user': 'admin', 'pass': 'ftp123'}", "Medium Risk"),
    ("SMTP_PASSWORD = 'emailpass123'", "Medium Risk"),
    ("ldap_bind_password = 'ldappass'", "Medium Risk"),
    ("NPM_AUTH_TOKEN = 'npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'", "Medium Risk"),
    ("DOCKER_HUB_PASSWORD = 'my_docker_pass'", "Medium Risk"),
    ("ssh_private_key = open('id_rsa').read()", "Medium Risk"),
    ("certificate = open('server.key').read()", "Medium Risk"),

    # -- Weak cryptography ---
    ("cipher = DES.new(key, DES.MODE_ECB)", "Medium Risk"),
    ("cipher = ARC4.new(key)", "Medium Risk"),
    ("digest = hashlib.new('sha1', data).hexdigest()", "Medium Risk"),
    ("crc = binascii.crc32(data)", "Medium Risk"),
    ("mac = hmac.new(b'weak', msg, hashlib.md5).digest()", "Medium Risk"),
    ("key = b'0123456789abcdef'", "Medium Risk"),
    ("ITERATIONS = 100", "Medium Risk"),
    ("pbkdf2 = hashlib.pbkdf2_hmac('sha1', pwd, salt, 1000)", "Medium Risk"),
    ("token = uuid.uuid4().hex", "Medium Risk"),
    ("session_id = str(int(time.time()))", "Medium Risk"),
    ("nonce = str(random.getrandbits(64))", "Medium Risk"),
    ("salt = 'fixed_salt_value'", "Medium Risk"),

    # -- Insecure config flags ---
    ("SECURE_HSTS_SECONDS = 0", "Medium Risk"),
    ("SESSION_EXPIRE_AT_BROWSER_CLOSE = False", "Medium Risk"),
    ("PERMANENT_SESSION_LIFETIME = timedelta(days=365)", "Medium Risk"),
    ("JSONIFY_PRETTYPRINT_REGULAR = True", "Medium Risk"),
    ("TEMPLATES_AUTO_RELOAD = True", "Medium Risk"),
    ("PRESERVE_CONTEXT_ON_EXCEPTION = True", "Medium Risk"),
    ("DEFAULT_PERMISSION_CLASSES = ['rest_framework.permissions.AllowAny']", "Medium Risk"),
    ("REST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': []}", "Medium Risk"),
    ("app.config['DEBUG_TB_ENABLED'] = True", "Medium Risk"),
    ("app.config['LOGIN_DISABLED'] = True", "Medium Risk"),
    ("MIDDLEWARE = []", "Medium Risk"),

    # -- Debug logging of sensitive data ---
    ("app.logger.debug('Request data: %s', request.data)", "Medium Risk"),
    ("logger.debug('Headers: %s', dict(request.headers))", "Medium Risk"),
    ("print('Auth token:', auth_token)", "Medium Risk"),
    ("log.info('User data: %s', json.dumps(user.__dict__))", "Medium Risk"),
    ("logging.debug('SQL: %s PARAMS: %s', sql, params)", "Medium Risk"),
    ("print(request.cookies)", "Medium Risk"),
    ("app.debug = True; logging.basicConfig(level=logging.DEBUG)", "Medium Risk"),

    # -- Missing access control (unauthenticated endpoints) ---
    ("@app.route('/admin/users'); def list_users(): return jsonify(User.query.all())", "Medium Risk"),
    ("@app.route('/api/internal'); def internal_api(): return jsonify(internal_data())", "Medium Risk"),
    ("@app.route('/export'); def export_data(): return send_file('backup.sql')", "Medium Risk"),
    ("def get_all_users(): return db.session.query(User).all()", "Medium Risk"),
    ("def delete_account(user_id): User.query.filter_by(id=user_id).delete()", "Medium Risk"),

    # -- Insecure transport (cleartext protocols) ---
    ("smtp = smtplib.SMTP('smtp.example.com', 587)", "Medium Risk"),
    ("ftp = ftplib.FTP('ftp.example.com')", "Medium Risk"),
    ("conn = telnetlib.Telnet('192.168.1.1', 23)", "Medium Risk"),
    ("http_client = http.client.HTTPConnection('api.example.com')", "Medium Risk"),
    ("urllib.request.urlopen('http://api.example.com/data')", "Medium Risk"),

    # -- Weak session tokens ---
    ("session_token = hashlib.md5(username.encode()).hexdigest()", "Medium Risk"),
    ("session_id = base64.b64encode(username.encode()).decode()", "Medium Risk"),
    ("csrf_token = str(user_id) + str(int(time.time()))", "Medium Risk"),
    ("auth_header = base64.b64encode(f'{username}:{password}'.encode()).decode()", "Medium Risk"),

    # -- Predictable OTP / token generation ---
    ("otp = random.randint(100000, 999999)", "Medium Risk"),
    ("reset_token = str(random.randint(0, 999999)).zfill(6)", "Medium Risk"),
    ("temp_password = ''.join(random.choices(string.ascii_letters, k=8))", "Medium Risk"),
    ("invoice_id = int(time.time())", "Medium Risk"),

    # -- Overly permissive file permissions ---
    ("os.chmod(uploaded_file, 0o777)", "Medium Risk"),
    ("os.chmod('/var/www/uploads', 0o777)", "Medium Risk"),
    ("os.makedirs(dir_path, mode=0o777, exist_ok=True)", "Medium Risk"),

    # -- Silent exception swallowing ---
    ("except PermissionError: pass", "Medium Risk"),
    ("except AuthenticationError: continue", "Medium Risk"),

    # -- Weak password validation ---
    ("MIN_PASSWORD_LENGTH = 4", "Medium Risk"),
    ("if len(password) >= 1: return True", "Medium Risk"),
    ("PASSWORD_VALIDATORS = []", "Medium Risk"),
    ("def check_password_strength(p): return len(p) >= 4", "Medium Risk"),

    # -- Information leakage ---
    ("return jsonify({'version': sys.version, 'platform': sys.platform})", "Medium Risk"),
    ("return render_template('error.html', error=traceback.format_exc())", "Medium Risk"),
    ("except Exception as e: return str(e), 500", "Medium Risk"),
    ("EXPOSE_HEADERS = ['X-Debug-Token', 'X-Debug-Token-Link']", "Medium Risk"),
    ("return jsonify(request.environ)", "Medium Risk"),

    # -- Timing attack vulnerable comparisons ---
    ("if stored_token == provided_token: grant_access()", "Medium Risk"),
    ("if user.api_key == request.headers['X-API-Key']: return True", "Medium Risk"),
    ("return password == stored_password", "Medium Risk"),

    # -- Insecure cookie settings ---
    ("response.set_cookie('session', token)", "Medium Risk"),
    ("resp.set_cookie('auth', jwt_token, httponly=False, secure=False)", "Medium Risk"),
    ("document.cookie = 'session=' + token", "Medium Risk"),
    ("res.cookie('auth', token, { httpOnly: false })", "Medium Risk"),
]
"""

with open(BUILD_SCRIPT, 'r', encoding='utf-8') as f:
    content = f.read()

MARKER = '\n]\n\n\ndef main():'
if MARKER not in content:
    print('ERROR: Could not find insertion marker in build_dataset.py')
    exit(1)

new_content = content.replace(MARKER, NEW_SAMPLES + '\n]\n\n\ndef main():', 1)

with open(BUILD_SCRIPT, 'w', encoding='utf-8') as f:
    f.write(new_content)

print('Injected successfully into build_dataset.py')
print(f'New file size: {len(new_content)} bytes')
