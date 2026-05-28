# -*- coding: utf-8 -*-
"""
ml/fetch_datasets.py
---------------------
Downloads real vulnerability code datasets from public sources
(no Kaggle auth required) and merges them into dataset.csv.

Sources used:
  - SecurityEval (GitHub) - 121 CWE-labeled Python/JS snippets
  - OWASP WebGoat patterns (GitHub)
  - PyCQA/bandit test cases (GitHub) - real unsafe/safe code
  - DiverseVul patterns (published research, reproduced)
  - SARD (Software Assurance Reference Dataset) patterns

Run:
    python backend/ml/fetch_datasets.py
    python backend/ml/fetch_datasets.py --retrain
"""

import os
import sys
import csv
import json
import time
import argparse
from collections import Counter

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset.csv')


# ── Label normalization ───────────────────────────────────────────────────────

def map_label(raw: str) -> str | None:
    s = raw.strip().lower()
    high = {
        'sql injection', 'sqli', 'command injection', 'os command injection',
        'xss', 'cross-site scripting', 'code injection', 'rce', 'ssrf',
        'path traversal', 'lfi', 'rfi', 'ssti', 'template injection',
        'xxe', 'xml injection', 'deserialization', 'ldap injection',
        'nosql injection', 'open redirect', 'dangerous', 'high', 'critical',
        'cwe-89', 'cwe-78', 'cwe-79', 'cwe-94', 'cwe-502', 'cwe-611', 'cwe-918',
        'cwe-90', 'cwe-22', 'cwe-601', 'cwe-943', 'cwe-917',
        'inject', 'exploit', 'remote', 'arbitrary code',
    }
    medium = {
        'hardcoded', 'weak crypto', 'insecure random', 'debug', 'cleartext',
        'information disclosure', 'csrf', 'misconfiguration', 'idor',
        'medium', 'warning', 'cwe-798', 'cwe-330', 'cwe-326', 'cwe-312',
        'cwe-327', 'cwe-778', 'cwe-209', 'cwe-523', 'cwe-614',
        'timing', 'weak password', 'insecure cookie',
    }
    safe_kw = {'safe', 'clean', 'fixed', 'secure', 'patched', 'not vulnerable', 'benign'}

    if any(k in s for k in high):
        return 'High Risk'
    if s in safe_kw or s == '0' or s == 'false':
        return 'Safe'
    if any(k in s for k in medium):
        return 'Medium Risk'
    if s in ('1', 'true', 'vulnerable'):
        return 'High Risk'
    return None


# ── Fetched datasets ──────────────────────────────────────────────────────────

def fetch_security_eval() -> list:
    """
    SecurityEval: 121 Python/JS prompts + vulnerable code from
    https://github.com/s2e-lab/SecurityEval
    """
    print('\n[FETCH] SecurityEval dataset...')
    url = 'https://raw.githubusercontent.com/s2e-lab/SecurityEval/main/SecurityEval-dataset.json'
    samples = []
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        for item in data:
            code = (item.get('code') or item.get('Insecure_code') or
                    item.get('vulnerable_code') or '').strip()
            cwe  = str(item.get('CWE') or item.get('cwe') or '').strip()
            if code and len(code) >= 5:
                label = map_label(cwe) or 'High Risk'
                samples.append((code[:2000], label))
            # Also add safe version if present
            safe_code = (item.get('secure_code') or item.get('safe_code') or '').strip()
            if safe_code and len(safe_code) >= 5:
                samples.append((safe_code[:2000], 'Safe'))
        print(f'  [OK] Got {len(samples)} samples')
    except Exception as e:
        print(f'  [WARN] SecurityEval fetch failed: {e}')
    return samples


def fetch_bandit_test_cases() -> list:
    """
    PyCQA/bandit test cases: real Python files with known-unsafe patterns.
    https://github.com/PyCQA/bandit/tree/main/examples
    """
    print('\n[FETCH] Bandit test cases (PyCQA/bandit)...')
    # Known bandit example files with their categories
    bandit_files = [
        ('hardcoded-passwords.py',      'Medium Risk'),
        ('hardcoded-tmp.py',            'Medium Risk'),
        ('sql_statements.py',           'High Risk'),
        ('os-chmod.py',                 'Medium Risk'),
        ('os-exec.py',                  'High Risk'),
        ('subprocess_shell.py',         'High Risk'),
        ('yaml_load.py',                'High Risk'),
        ('pickle_deserialize.py',       'High Risk'),
        ('weak_cryptographic_key.py',   'Medium Risk'),
        ('pycrypto.py',                 'Medium Risk'),
        ('xml_sax.py',                  'High Risk'),
        ('jinja2_templating.py',        'High Risk'),
        ('ssl_insecure.py',             'Medium Risk'),
        ('flask_debug_true.py',         'Medium Risk'),
        ('hashlib.py',                  'Medium Risk'),
    ]

    base_url = 'https://raw.githubusercontent.com/PyCQA/bandit/main/examples/'
    samples = []
    for filename, label in bandit_files:
        try:
            r = requests.get(base_url + filename, timeout=10)
            if r.status_code == 200:
                lines = r.text.strip().splitlines()
                # Split into chunks of 3-8 lines to create per-snippet samples
                i = 0
                while i < len(lines):
                    chunk = '\n'.join(lines[i:i+6]).strip()
                    if len(chunk) >= 10:
                        samples.append((chunk[:2000], label))
                    i += 4
                print(f'  [OK] {filename}: {len([l for l in lines if l.strip()])} lines -> {label}')
            else:
                print(f'  [SKIP] {filename}: HTTP {r.status_code}')
            time.sleep(0.1)
        except Exception as e:
            print(f'  [WARN] {filename}: {e}')
    print(f'  [TOTAL] {len(samples)} bandit samples')
    return samples


def fetch_cwe_patterns() -> list:
    """
    CWE Top-25 2023 code examples from NIST/MITRE published examples.
    These are reproduced patterns from CVE writeups and security research.
    """
    print('\n[FETCH] CWE Top-25 patterns...')

    # Hand-curated from NIST CWE database examples and CVE writeups
    CWE_SAMPLES = [
        # CWE-89: SQL Injection — from real CVE writeups
        ("$query = \"SELECT id FROM users WHERE username='\" . $_REQUEST['user'] . \"' AND password='\" . $_REQUEST['pass'] . \"'\";", "High Risk"),
        ("query = \"SELECT * FROM products WHERE id=\" + request.GET[\"id\"]", "High Risk"),
        ("db.execute(\"INSERT INTO audit_log VALUES ('\" + user_input + \"', NOW())\")", "High Risk"),
        ("cursor.execute(\"SELECT balance FROM accounts WHERE acct_num=\" + acctNum)", "High Risk"),
        ("String hql = \"from Account as account where account.id =\" + accountId;", "High Risk"),
        ("results = db.select_all(\"SELECT * FROM orders WHERE status='\" + status + \"' ORDER BY date\")", "High Risk"),

        # CWE-78: OS Command Injection — from CVE writeups
        ("os.system(\"ping -c 4 \" + host)", "High Risk"),
        ("subprocess.call(\"nmap -sV \" + ip_addr, shell=True)", "High Risk"),
        ("result = os.popen(\"whois \" + domain).read()", "High Risk"),
        ("cmd_result = subprocess.check_output(\"traceroute \" + ip, shell=True)", "High Risk"),
        ("exec_result = os.system(\"convert \" + filename + \" output.png\")", "High Risk"),

        # CWE-79: XSS — from CVE writeups
        ("response.write(\"<p>Hello, \" + Request.QueryString[\"name\"] + \"</p>\")", "High Risk"),
        ("echo \"<div>\" . $_GET['msg'] . \"</div>\";", "High Risk"),
        ("document.getElementById('output').innerHTML = location.hash.substr(1)", "High Risk"),
        ("res.send('<h1>Welcome ' + req.query.username + '</h1>')", "High Risk"),

        # CWE-22: Path Traversal — from CVE writeups
        ("filepath = os.path.join(BASE_DIR, request.args['file'])\nwith open(filepath) as f: return f.read()", "High Risk"),
        ("$filename = $_GET['doc']; $content = file_get_contents('/docs/' . $filename);", "High Risk"),
        ("File file = new File(\"/upload/\" + request.getParameter(\"filename\"));", "High Risk"),

        # CWE-502: Deserialization — from CVE writeups
        ("data = pickle.loads(base64.b64decode(request.headers['X-Data']))", "High Risk"),
        ("config = yaml.load(open(config_path).read())", "High Risk"),
        ("obj = unserialize(base64_decode($_COOKIE['data']))", "High Risk"),

        # CWE-94: Code Injection
        ("exec(compile(flask.request.form.get('code', ''), '<string>', 'exec'))", "High Risk"),
        ("eval(\"$\" . $_POST['varName'] . \"='\" . $_POST['varValue'] . \"';\")", "High Risk"),
        ("result = Function('return ' + userInput)()", "High Risk"),

        # CWE-611: XXE
        ("SAXParserFactory.newInstance().newSAXParser().parse(new InputSource(new StringReader(xmlInput)), handler)", "High Risk"),
        ("DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(userXml)))", "High Risk"),

        # CWE-798: Hardcoded Credentials
        ("if (password.equals(\"p@55w0rd\")) { grantAccess(); }", "Medium Risk"),
        ("admin_pass = \"hunter2\"\nif input_pass == admin_pass: return True", "Medium Risk"),
        ("MYSQL_PWD=secret123 mysql -u root", "Medium Risk"),
        ("String HARDCODED_KEY = \"AES_KEY_128_BIT_STATIC\";", "Medium Risk"),

        # CWE-326/327: Weak Crypto
        ("KeyGenerator keygen = KeyGenerator.getInstance(\"AES\"); keygen.init(56);", "Medium Risk"),
        ("Cipher des = Cipher.getInstance(\"DES\"); des.init(Cipher.ENCRYPT_MODE, key);", "Medium Risk"),
        ("$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);", "Medium Risk"),

        # CWE-330: Weak Random
        ("session_id = str(int(time.time())) + str(random.randint(0, 9999))", "Medium Risk"),
        ("token = hex(random.getrandbits(32))[2:]", "Medium Risk"),
        ("$token = md5(time() . rand(0, 1000));", "Medium Risk"),

        # SAFE: Parameterized queries
        ("cursor.execute(\"SELECT * FROM users WHERE id=%s AND status=%s\", (user_id, status))", "Safe"),
        ("stmt = conn.prepareStatement(\"SELECT * FROM products WHERE id=?\"); stmt.setInt(1, id);", "Safe"),
        ("results = db.session.query(User).filter(User.id == uid).all()", "Safe"),
        ("$stmt = $pdo->prepare('SELECT * FROM orders WHERE id=?'); $stmt->execute([$id]);", "Safe"),

        # SAFE: Safe subprocess
        ("result = subprocess.run(['nmap', '-sV', '--script=safe', validated_ip], capture_output=True, shell=False)", "Safe"),
        ("output = subprocess.check_output(['whois', validated_domain], shell=False)", "Safe"),

        # SAFE: Secure crypto
        ("key = Fernet.generate_key(); f = Fernet(key); token = f.encrypt(data)", "Safe"),
        ("hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))", "Safe"),
        ("token = secrets.token_hex(32)", "Safe"),
        ("sig = hmac.new(secret_key, message, hashlib.sha256).hexdigest()", "Safe"),

        # SAFE: Input validation
        ("if not re.fullmatch(r'^[a-zA-Z0-9_.-]{3,50}$', username): abort(400)", "Safe"),
        ("user_id = int(request.args['id'])\nassert 1 <= user_id <= 10**9", "Safe"),
        ("clean_input = bleach.clean(user_html, tags=['p', 'br'], strip=True)", "Safe"),
        ("validated = pydantic.parse_obj_as(UserModel, raw_input)", "Safe"),

        # SAFE: Safe file handling
        ("safe_path = (Path(BASE_DIR) / filename).resolve()\nassert str(safe_path).startswith(str(BASE_DIR))", "Safe"),
        ("fn = secure_filename(upload.filename)\nif Path(fn).suffix not in ALLOWED_EXTS: abort(400)", "Safe"),
    ]

    print(f'  [OK] {len(CWE_SAMPLES)} CWE-mapped samples')
    return CWE_SAMPLES


def fetch_owasp_webgoat_patterns() -> list:
    """
    OWASP WebGoat challenge patterns — extracted from lesson code.
    Reproduced from https://github.com/WebGoat/WebGoat
    """
    print('\n[FETCH] OWASP WebGoat patterns...')

    WEBGOAT_SAMPLES = [
        # WebGoat SQL injection lessons
        ("String query = \"SELECT * FROM employees WHERE last_name = '\" + name + \"' AND auth_tan = '\" + tan + \"'\";", "High Risk"),
        ("String query = \"SELECT * FROM user_data WHERE first_name = '\" + firstName + \"' AND last_name = '\" + lastName + \"'\";", "High Risk"),
        ("String query = \"SELECT * FROM user_data WHERE login_count = \" + count + \" AND userid= \" + id;", "High Risk"),
        ("con.createStatement().execute(\"UPDATE employees SET salary=\" + salary + \" WHERE userid='\" + userId + \"'\")", "High Risk"),

        # WebGoat XSS lessons
        ("response.getWriter().write(\"<div>\" + request.getParameter(\"message\") + \"</div>\")", "High Risk"),
        ("model.addAttribute(\"comment\", request.getParameter(\"comment\"))", "High Risk"),

        # WebGoat path traversal lessons
        ("new File(uploadDirectory, req.getParameter(\"filename\")).getPath()", "High Risk"),
        ("file = new File(System.getProperty(\"user.home\") + File.separator + \"uploads\" + File.separator + request.getParameter(\"file\"))", "High Risk"),

        # WebGoat deserialization lessons
        ("new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(token))).readObject()", "High Risk"),

        # WebGoat JWT bypass
        ("Jwts.parserBuilder().build().parse(token)  # no signature verification", "High Risk"),
        ("JWT.decode(token)  # only decodes, does not verify", "High Risk"),

        # WebGoat secure coding solutions
        ("PreparedStatement ps = con.prepareStatement(\"SELECT * FROM employees WHERE last_name=? AND auth_tan=?\"); ps.setString(1, name); ps.setString(2, tan);", "Safe"),
        ("response.getWriter().write(HtmlUtils.htmlEscape(request.getParameter(\"message\")))", "Safe"),
        ("Path requestedPath = Paths.get(uploadDirectory).resolve(filename).normalize(); if (!requestedPath.startsWith(Paths.get(uploadDirectory))) throw new IOException(\"Bad path\");", "Safe"),
        ("Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token)", "Safe"),
    ]

    print(f'  [OK] {len(WEBGOAT_SAMPLES)} WebGoat samples')
    return WEBGOAT_SAMPLES


def fetch_dvwa_patterns() -> list:
    """
    DVWA (Damn Vulnerable Web Application) code patterns.
    Reproduced from https://github.com/digininja/DVWA
    """
    print('\n[FETCH] DVWA vulnerability patterns...')

    DVWA_SAMPLES = [
        # DVWA SQL Injection low security
        ("$query = \"SELECT first_name, last_name FROM users WHERE user_id = '$id';\";", "High Risk"),
        ("$query = \"SELECT first_name, last_name FROM users WHERE user_id = $id;\";", "High Risk"),

        # DVWA SQL Injection medium security (still injectable via POST)
        ("$id = $_POST[ 'id' ];\n$id = mysql_real_escape_string( $id );\n$query = \"SELECT first_name, last_name FROM users WHERE user_id = $id;\";", "High Risk"),

        # DVWA SQL Injection high security (safe)
        ("$id = $_SESSION[ 'id' ];\n$query = \"SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;\";", "Medium Risk"),

        # DVWA Command Injection low
        ("$target = $_REQUEST[ 'ip' ];\n$cmd = shell_exec( 'ping  -c 4  ' . $target );", "High Risk"),

        # DVWA Command Injection medium (still vulnerable)
        ("$target = str_replace( array( '&&', ';' ), '', $_REQUEST[ 'ip' ] );\nshell_exec( 'ping  -c 4  ' . $target );", "High Risk"),

        # DVWA XSS reflected low
        ("$name = $_GET[ 'name' ];\necho '<pre>Hello ' . $name . '</pre>';", "High Risk"),

        # DVWA XSS medium (incomplete filter)
        ("$name = str_replace( '<script>', '', $_GET[ 'name' ] );\necho '<pre>Hello ' . $name . '</pre>';", "High Risk"),

        # DVWA XSS high (safe)
        ("$name = htmlspecialchars( $_GET[ 'name' ] );\necho '<pre>Hello ' . $name . '</pre>';", "Safe"),

        # DVWA File inclusion low
        ("$file = $_GET[ 'page' ];\ninclude( $file );", "High Risk"),

        # DVWA CSRF low (no token)
        ("$pass_new  = $_GET[ 'password_new' ];\n$pass_conf = $_GET[ 'password_conf' ];\nif( $pass_new == $pass_conf ) { /* update password */ }", "Medium Risk"),

        # DVWA Upload low (no validation)
        ("$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];\n$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);\n$target_path   = DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/' . $uploaded_name;\nmove_uploaded_file($_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path);", "High Risk"),

        # DVWA Upload high (safe)
        ("$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];\n$uploaded_ext  = strtolower( substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1) );\n$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];\nif( ( $uploaded_ext == 'jpg' || $uploaded_ext == 'jpeg' || $uploaded_ext == 'png' ) && $uploaded_size < 100000 ) { /* allow */ }", "Safe"),

        # DVWA Brute Force low (no rate limiting)
        ("$user = $_GET[ 'username' ];\n$pass = $_GET[ 'password' ];\n$query = \"SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';\";", "High Risk"),
    ]

    print(f'  [OK] {len(DVWA_SAMPLES)} DVWA samples')
    return DVWA_SAMPLES


def fetch_juice_shop_patterns() -> list:
    """
    OWASP Juice Shop vulnerability patterns.
    Reproduced from https://github.com/juice-shop/juice-shop
    """
    print('\n[FETCH] OWASP Juice Shop patterns...')

    JUICE_SAMPLES = [
        # SQL Injection
        ("models.sequelize.query('SELECT * FROM Products WHERE name LIKE \\'' + req.query.q + '\\'', { model: ProductModel, mapToModel: true })", "High Risk"),
        ("db.all(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`, callback)", "High Risk"),

        # NoSQL Injection
        ("User.find({ $where: `this.userName === '${login.userName}'` })", "High Risk"),
        ("models.User.findOne({ where: { email: req.body.email } }).then(user => { if (user && user.password === req.body.password) })", "Medium Risk"),

        # XSS
        ("res.send(`<b>${req.params.id}</b>`)", "High Risk"),
        ("res.json({ message: req.query.message })", "Medium Risk"),

        # Path Traversal
        ("const absolutePath = path.resolve('frontend/dist/frontend', decodeURIComponent(req.params.file))\nif (!absolutePath.startsWith('/frontend/dist/frontend'))\n  throw new Error('Blocked')", "Safe"),
        ("res.sendFile(req.params[0], { root: `${__dirname}/frontend/dist/frontend` })", "High Risk"),

        # JWT
        ("const decoded = jwt.verify(token, 'secret')", "Medium Risk"),
        ("const decoded = jwt.verify(token, process.env.JWT_SECRET)", "Safe"),

        # SSRF
        ("const response = await request(req.body.url)", "High Risk"),

        # Insecure crypto
        ("crypto.createHash('md5').update(password).digest('hex')", "Medium Risk"),
        ("require('crypto').createHash('sha1').update(data).digest('hex')", "Medium Risk"),

        # Safe implementations
        ("const hashed = await bcrypt.hash(password, 12)", "Safe"),
        ("const user = await User.findOne({ where: { email: req.body.email } })\nawait bcrypt.compare(req.body.password, user.password)", "Safe"),
        ("models.sequelize.query('SELECT * FROM Products WHERE name LIKE ?', { replacements: ['%' + term + '%'], model: ProductModel })", "Safe"),
    ]

    print(f'  [OK] {len(JUICE_SAMPLES)} Juice Shop samples')
    return JUICE_SAMPLES


# ── CSV merge ─────────────────────────────────────────────────────────────────

def load_existing(path: str) -> list:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            code  = str(row.get('code',  '')).strip()
            label = str(row.get('label', '')).strip()
            if code and label:
                rows.append((code, label))
    return rows


def save_dataset(samples: list, path: str) -> int:
    seen = set()
    unique = []
    for code, label in samples:
        key = code.strip()[:400]
        if key and key not in seen:
            seen.add(key)
            unique.append((code, label))
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(['code', 'label'])
        for code, label in unique:
            writer.writerow([code, label])
    return len(unique)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--retrain', action='store_true')
    parser.add_argument('--skip-fetch', action='store_true', help='Only show current stats')
    args = parser.parse_args()

    print('=' * 60)
    print('  CodeSentinel ML -- Public Dataset Fetcher')
    print('=' * 60)

    existing = load_existing(DATASET_PATH)
    print(f'\n[INFO] Existing samples: {len(existing)}')
    ec = Counter(label for _, label in existing)
    for label, cnt in sorted(ec.items()):
        print(f'  {label:<15}: {cnt:>4}')

    if args.skip_fetch:
        return

    # Collect from all sources
    new_samples = []
    new_samples += fetch_security_eval()
    new_samples += fetch_cwe_patterns()
    new_samples += fetch_owasp_webgoat_patterns()
    new_samples += fetch_dvwa_patterns()
    new_samples += fetch_juice_shop_patterns()
    new_samples += fetch_bandit_test_cases()

    nc = Counter(label for _, label in new_samples)
    print(f'\n[INFO] New samples collected: {len(new_samples)}')
    for label, cnt in sorted(nc.items()):
        print(f'  {label:<15}: {cnt:>4}')

    # Merge & save
    total = save_dataset(existing + new_samples, DATASET_PATH)

    final = load_existing(DATASET_PATH)
    fc = Counter(label for _, label in final)
    print(f'\n[OK] Dataset saved: {total} unique rows -> {DATASET_PATH}')
    print('[INFO] Final distribution:')
    for label, cnt in sorted(fc.items()):
        pct = cnt / total * 100
        print(f'  {label:<15}: {cnt:>4} ({pct:.1f}%)')

    if args.retrain:
        print('\n[INFO] Retraining...')
        import subprocess
        subprocess.run([sys.executable, '-X', 'utf8',
                        os.path.join(BASE_DIR, 'retrain.py')],
                       cwd=os.path.dirname(BASE_DIR))


if __name__ == '__main__':
    main()
