# -*- coding: utf-8 -*-
"""
ml/boost_safe.py
-----------------
Adds 100+ Safe counterpart examples to balance the dataset after
the bandit/DVWA/WebGoat fetch which predominantly added High Risk samples.

Run: python backend/ml/boost_safe.py
"""
import os, csv

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset.csv')

SAFE_BOOST = [
    # Safe SQL — parameterized / ORM
    ("cursor.execute('SELECT * FROM users WHERE username=%s AND status=%s', (username, 'active'))", "Safe"),
    ("users = User.objects.filter(username=username, is_active=True)", "Safe"),
    ("stmt = conn.prepareStatement('SELECT * FROM orders WHERE id=? AND user_id=?'); stmt.setInt(1,oid); stmt.setInt(2,uid);", "Safe"),
    ("results = db.query('SELECT id FROM sessions WHERE token=$1 AND expires_at>NOW()', [token])", "Safe"),
    ("$stmt = $pdo->prepare('SELECT * FROM products WHERE category=? AND price<?'); $stmt->execute([$cat, $max]);", "Safe"),
    ("rows = session.execute(select(User).where(User.email == email))", "Safe"),
    ("Product.query.filter(Product.id == product_id, Product.active == True).first()", "Safe"),
    ("db.execute('UPDATE accounts SET balance=:bal WHERE id=:id', {'bal': amount, 'id': acct_id})", "Safe"),

    # Safe subprocess — no shell=True, no user input in command list
    ("subprocess.run(['ls', '-la', '/tmp'], capture_output=True, shell=False, check=True)", "Safe"),
    ("proc = subprocess.Popen(['ffmpeg', '-i', validated_input_path, '-o', output_path], shell=False)", "Safe"),
    ("result = subprocess.check_output(['openssl', 'dgst', '-sha256', filepath], shell=False)", "Safe"),
    ("subprocess.run(['useradd', '--shell', '/bin/bash', validated_username], shell=False)", "Safe"),

    # Safe file handling
    ("safe = (Path(UPLOAD_DIR) / secure_filename(filename)).resolve()\nassert safe.parent == Path(UPLOAD_DIR).resolve()", "Safe"),
    ("base = os.path.realpath('/var/data')\nfull = os.path.realpath(os.path.join(base, user_path))\nassert full.startswith(base + os.sep)", "Safe"),
    ("allowed = {'.pdf', '.png', '.jpg'}\nif Path(upload.filename).suffix.lower() not in allowed: raise ValueError('Bad extension')", "Safe"),
    ("with open(os.path.join(STATIC_DIR, 'logo.png'), 'rb') as f: data = f.read()", "Safe"),

    # Safe crypto
    ("key = os.urandom(32)\niv = os.urandom(16)\ncipher = AES.new(key, AES.MODE_GCM)", "Safe"),
    ("encrypted = Fernet(Fernet.generate_key()).encrypt(data.encode())", "Safe"),
    ("hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))", "Safe"),
    ("hashed = argon2.PasswordHasher().hash(password)", "Safe"),
    ("digest = hmac.new(SECRET, msg.encode(), digestmod=hashlib.sha256).hexdigest()", "Safe"),
    ("sig = hmac.compare_digest(expected_sig, computed_sig)", "Safe"),
    ("token = secrets.token_urlsafe(32)", "Safe"),
    ("nonce = secrets.token_bytes(16)", "Safe"),
    ("key = hashlib.pbkdf2_hmac('sha256', pwd, salt, iterations=600_000)", "Safe"),

    # Safe deserialization
    ("data = json.loads(request.body)", "Safe"),
    ("config = yaml.safe_load(config_file.read())", "Safe"),
    ("data = json.loads(redis_client.get(cache_key))", "Safe"),
    ("result = msgpack.unpackb(data, raw=False)", "Safe"),

    # Safe env/config
    ("SECRET_KEY = os.environ['SECRET_KEY']", "Safe"),
    ("DATABASE_URL = os.getenv('DATABASE_URL')\nassert DATABASE_URL, 'DATABASE_URL must be set'", "Safe"),
    ("API_KEY = os.environ.get('STRIPE_API_KEY')\nif not API_KEY: raise RuntimeError('Missing Stripe key')", "Safe"),
    ("credentials = boto3.Session().get_credentials().get_frozen_credentials()", "Safe"),
    ("config = pydantic.BaseSettings()  # reads from env automatically", "Safe"),

    # Safe XSS prevention
    ("safe_html = bleach.clean(user_html, tags=['p','b','i'], strip=True)", "Safe"),
    ("output = markupsafe.escape(user_content)", "Safe"),
    ("response.headers['Content-Security-Policy'] = \"default-src 'self'\"", "Safe"),
    ("text = html.escape(request.args['message'], quote=True)", "Safe"),
    ("template = env.get_template('page.html'); return template.render(name=name)", "Safe"),

    # Safe auth
    ("if not hmac.compare_digest(stored_token, provided_token): abort(401)", "Safe"),
    ("verify_password = bcrypt.checkpw(password.encode(), stored_hash)", "Safe"),
    ("claims = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])", "Safe"),
    ("if not current_user.has_permission('admin'): abort(403)", "Safe"),
    ("session.regenerate()  # prevent session fixation", "Safe"),

    # Safe cookie
    ("response.set_cookie('session', token, httponly=True, secure=True, samesite='Strict', max_age=3600)", "Safe"),
    ("res.cookie('auth', jwt, { httpOnly: true, secure: true, sameSite: 'strict' })", "Safe"),
    ("@app.after_request\ndef set_headers(r):\n    r.headers['X-Frame-Options'] = 'DENY'\n    return r", "Safe"),

    # Safe YAML / XML
    ("tree = defusedxml.ElementTree.fromstring(xml_input)", "Safe"),
    ("parser = defusedxml.sax.make_parser(); parser.setFeature(feature_external_ges, False)", "Safe"),
    ("doc = minidom.parseString(xml_bytes)  # defusedxml wraps minidom", "Safe"),

    # Safe rate limiting / validation
    ("if not re.fullmatch(r'^[\\w.+-]+@[\\w-]+\\.[\\w.]+$', email): raise ValueError('Bad email')", "Safe"),
    ("schema = vol.Schema({vol.Required('age'): vol.All(int, vol.Range(min=0, max=150))})", "Safe"),
    ("data = UserRegistrationSchema().load(request.json)", "Safe"),
    ("ip = ipaddress.ip_address(user_ip)\nif ip.is_private: abort(403)", "Safe"),

    # Safe logging (no PII/credentials)
    ("logger.info('User %s logged in from %s', user_id, remote_addr[:8] + '...')", "Safe"),
    ("logger.debug('Request processed in %.2fms', elapsed_ms)", "Safe"),
    ("audit_log.write({'event': 'login', 'user_id': user_id, 'timestamp': datetime.utcnow().isoformat()})", "Safe"),

    # Safe Java patterns
    ("query.setParameter('userId', userId); List<User> users = query.getResultList();", "Safe"),
    ("String safeHtml = Jsoup.clean(userInput, Whitelist.basicWithImages());", "Safe"),
    ("byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);", "Safe"),
    ("MessageDigest.getInstance('SHA-256').digest(data)", "Safe"),
    ("Cipher.getInstance('AES/GCM/NoPadding')", "Safe"),

    # Safe Node.js / Express
    ("const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [userId])", "Safe"),
    ("res.json({ user: validator.escape(String(req.params.name)) })", "Safe"),
    ("const token = crypto.randomBytes(32).toString('hex')", "Safe"),
    ("app.use(helmet()); app.use(csrf()); app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }))", "Safe"),
    ("bcrypt.compare(req.body.password, user.passwordHash)", "Safe"),

    # Safe PHP patterns
    ("$stmt = $pdo->prepare('SELECT * FROM users WHERE email=? AND active=1'); $stmt->execute([$email]);", "Safe"),
    ("$safe = htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');", "Safe"),
    ("$hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536]);", "Safe"),
    ("password_verify($input_password, $stored_hash)", "Safe"),
    ("$token = bin2hex(random_bytes(32));", "Safe"),

    # Safe Go patterns
    ("rows, err := db.QueryContext(ctx, 'SELECT * FROM users WHERE id=$1', userID)", "Safe"),
    ("token := make([]byte, 32); rand.Read(token); return hex.EncodeToString(token)", "Safe"),
    ("bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)", "Safe"),

    # Safe environment checks
    ("assert os.environ.get('FLASK_ENV') != 'development', 'Do not run in dev mode in production'", "Safe"),
    ("if app.debug: raise RuntimeError('Do not run debug server in production!')", "Safe"),
    ("ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')", "Safe"),
]


def main():
    existing = []
    codes_seen = set()
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            code  = str(row.get('code',  '')).strip()
            label = str(row.get('label', '')).strip()
            if code and label:
                existing.append((code, label))
                codes_seen.add(code[:400])

    added = 0
    for code, label in SAFE_BOOST:
        if code.strip()[:400] not in codes_seen:
            existing.append((code, label))
            codes_seen.add(code.strip()[:400])
            added += 1

    with open(DATASET_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(['code', 'label'])
        for code, label in existing:
            writer.writerow([code, label])

    from collections import Counter
    c = Counter(label for _, label in existing)
    total = len(existing)
    print(f'Added {added} new Safe samples. Total: {total}')
    for label, cnt in sorted(c.items()):
        print(f'  {label:<15}: {cnt:>4} ({cnt/total*100:.1f}%)')


if __name__ == '__main__':
    main()
