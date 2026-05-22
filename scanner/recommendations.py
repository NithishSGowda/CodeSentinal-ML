"""
scanner/recommendations.py
--------------------------
Advanced Developer Security Recommendations Engine (Day 5 Enhanced)

For every detected vulnerability category, this module provides:
  - A concrete code example of the INSECURE pattern
  - A concrete code example of the SECURE fix
  - A short remediation explanation
  - A priority_action field: what to do FIRST

All recommendations are rule-based — no AI/LLM used.
"""

# -----------------------------------------------------------------------
# RECOMMENDATION MAP
# Keyed by vulnerability issue name (matches 'issue' field from findings).
# -----------------------------------------------------------------------

RECOMMENDATIONS = {

    # ── Code Execution ───────────────────────────────────────────────────

    "Dangerous Execution (eval)": {
        "title":           "Replace eval() with a safe parser",
        "priority_action": "Remove eval() immediately — this is a direct RCE vector.",
        "insecure_example": "result = eval(user_expression)",
        "secure_example": (
            "# Option 1 — allow only arithmetic with ast.literal_eval\n"
            "import ast\n"
            "result = ast.literal_eval(user_expression)  # raises ValueError on non-literals\n\n"
            "# Option 2 — use a dedicated expression parser library\n"
            "# pip install simpleeval\n"
            "from simpleeval import simple_eval\n"
            "result = simple_eval(user_expression)"
        ),
        "steps": [
            "Identify what eval() is used for (math? JSON? template?).",
            "Replace with ast.literal_eval() for safe Python literal parsing.",
            "For math expressions, use a library like 'simpleeval'.",
            "Never pass raw HTTP request parameters to eval().",
        ],
    },

    "Dangerous Execution (exec)": {
        "title":           "Remove exec() from production code",
        "priority_action": "Refactor the logic to eliminate exec() — any user input reaching it is critical.",
        "insecure_example": "exec(user_script)",
        "secure_example": (
            "# Redesign to avoid dynamic execution entirely.\n"
            "# If you need plugin behaviour, use importlib:\n"
            "import importlib\n"
            "plugin = importlib.import_module('plugins.' + plugin_name)"
        ),
        "steps": [
            "Remove exec() entirely if possible.",
            "If dynamic behaviour is needed, use importlib for loading modules.",
            "Whitelist allowed operations instead of executing arbitrary code.",
        ],
    },

    "System Command Execution (os.system)": {
        "title":           "Replace os.system() with subprocess using shell=False",
        "priority_action": "Switch to subprocess.run() with a list of arguments and shell=False.",
        "insecure_example": "os.system('ping ' + user_ip)",
        "secure_example": (
            "import subprocess\n"
            "# Pass arguments as a list — no shell interpretation\n"
            "result = subprocess.run(['ping', '-c', '1', user_ip],\n"
            "                        capture_output=True, text=True, shell=False)"
        ),
        "steps": [
            "Switch from os.system() to subprocess.run().",
            "Always set shell=False (the default).",
            "Pass the command as a list of strings, not a concatenated string.",
            "Validate/whitelist user-supplied arguments before passing them.",
        ],
    },

    "Subprocess Execution": {
        "title":           "Use subprocess with shell=False and validated arguments",
        "priority_action": "Remove shell=True and pass a list of arguments instead.",
        "insecure_example": "subprocess.Popen(user_cmd, shell=True)",
        "secure_example": (
            "import subprocess, shlex\n"
            "# Never use shell=True with user input\n"
            "safe_args = shlex.split(user_cmd)  # still validate after this\n"
            "result = subprocess.run(safe_args, shell=False, capture_output=True)"
        ),
        "steps": [
            "Set shell=False on all subprocess calls.",
            "Pass a list of arguments, not a string.",
            "Validate or whitelist every argument that comes from user input.",
            "Use shlex.quote() if you must build shell strings (avoid if possible).",
        ],
    },

    "Insecure Deserialization (pickle)": {
        "title":           "Replace pickle with JSON for untrusted data",
        "priority_action": "Never call pickle.loads() on data received from external sources.",
        "insecure_example": "data = pickle.loads(request.data)",
        "secure_example": (
            "import json\n"
            "# JSON cannot execute code — safe for untrusted input\n"
            "data = json.loads(request.data)\n\n"
            "# If you MUST use pickle, only unpickle data you generated yourself\n"
            "# and stored securely — never unpickle client-supplied bytes."
        ),
        "steps": [
            "Replace pickle with json, msgpack, or Protocol Buffers.",
            "If you need pickle internally, sign the data with HMAC before storing.",
            "Verify the HMAC signature before calling pickle.loads().",
            "Never call pickle.loads() on data received from HTTP requests.",
        ],
    },

    "Insecure Deserialization (yaml)": {
        "title":           "Use yaml.safe_load() instead of yaml.load()",
        "priority_action": "Replace yaml.load() with yaml.safe_load() immediately.",
        "insecure_example": "data = yaml.load(user_input)",
        "secure_example": (
            "import yaml\n"
            "# safe_load only parses basic YAML types — no Python object instantiation\n"
            "data = yaml.safe_load(user_input)"
        ),
        "steps": [
            "Replace all yaml.load() calls with yaml.safe_load().",
            "Never deserialize untrusted YAML data.",
            "Validate YAML structure after loading using Pydantic or marshmallow.",
        ],
    },

    "Insecure Template Rendering": {
        "title":           "Avoid render_template_string() with user input",
        "priority_action": "Remove user-controlled variables from template strings immediately.",
        "insecure_example": "return render_template_string(user_template)",
        "secure_example": (
            "# Use static template files instead\n"
            "from flask import render_template\n"
            "return render_template('my_page.html', username=username)\n\n"
            "# Jinja2 auto-escapes variables in template files — no code injection"
        ),
        "steps": [
            "Move templates to .html files and use render_template() instead.",
            "Never pass user-controlled strings to render_template_string().",
            "Ensure Jinja2 auto-escaping is enabled (it is by default in Flask).",
        ],
    },

    "Open Redirect": {
        "title":           "Validate redirect targets against an allowlist",
        "priority_action": "Never redirect to a URL supplied directly by the user.",
        "insecure_example": "return redirect(request.args.get('next'))",
        "secure_example": (
            "from urllib.parse import urlparse, urljoin\n"
            "ALLOWED_HOSTS = {'myapp.com', 'www.myapp.com'}\n\n"
            "def safe_redirect(target):\n"
            "    parsed = urlparse(target)\n"
            "    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
            "        return redirect('/')  # fallback to home\n"
            "    return redirect(target)"
        ),
        "steps": [
            "Build an allowlist of safe redirect destinations.",
            "Parse the URL with urlparse and check the netloc field.",
            "Default to a safe page (e.g. home) if validation fails.",
        ],
    },

    # ── Hardcoded Secrets ────────────────────────────────────────────────

    "Hardcoded Password": {
        "title":           "Move passwords to environment variables",
        "priority_action": "Revoke the exposed password and store the new one in os.getenv().",
        "insecure_example": "db_password = 'supersecret123'",
        "secure_example": (
            "import os\n"
            "db_password = os.getenv('DB_PASSWORD')\n"
            "if not db_password:\n"
            "    raise RuntimeError('DB_PASSWORD environment variable is not set')"
        ),
        "steps": [
            "Remove the hardcoded value from code immediately.",
            "Store it in a .env file (never commit to git — add to .gitignore).",
            "Load it with os.getenv() or the python-dotenv library.",
            "Rotate the password since it may already be exposed.",
        ],
    },

    "Hardcoded API Key": {
        "title":           "Load API keys from environment variables",
        "priority_action": "Revoke the exposed key and generate a new one stored in env vars.",
        "insecure_example": "api_key = 'AIzaSyXXXXXXXXXXXXXXXXX'",
        "secure_example": (
            "import os\n"
            "api_key = os.getenv('MY_API_KEY')\n\n"
            "# Or use python-dotenv:\n"
            "# from dotenv import load_dotenv; load_dotenv()\n"
            "# api_key = os.getenv('MY_API_KEY')"
        ),
        "steps": [
            "Revoke the exposed key immediately via the provider's dashboard.",
            "Generate a new key and store it only in environment variables.",
            "Add .env to .gitignore before committing.",
            "Consider a secrets manager for production (Vault, AWS Secrets Manager).",
        ],
    },

    "Hardcoded Token": {
        "title":           "Load tokens from environment variables",
        "priority_action": "Revoke the token — it is already compromised.",
        "insecure_example": "access_token = 'ghp_XXXXXXXXXXXXXXXXXXXX'",
        "secure_example": (
            "import os\n"
            "access_token = os.getenv('ACCESS_TOKEN')"
        ),
        "steps": [
            "Revoke the token immediately — treat it as compromised.",
            "Store the new token in an environment variable.",
            "Use short-lived tokens and refresh them programmatically.",
        ],
    },

    "Hardcoded Secret": {
        "title":           "Generate secrets dynamically or use environment variables",
        "priority_action": "Remove the hardcoded secret and rotate it now.",
        "insecure_example": "SECRET_KEY = 'my_super_secret_key'",
        "secure_example": (
            "import os\n"
            "# Load from environment (recommended for deployment)\n"
            "SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32).hex())\n\n"
            "# For Flask specifically:\n"
            "app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')"
        ),
        "steps": [
            "Remove the hardcoded secret immediately.",
            "For Flask/Django, load SECRET_KEY from an environment variable.",
            "Generate a cryptographically random key: python -c \"import os; print(os.urandom(32).hex())\"",
            "Never share or commit the actual secret value.",
        ],
    },

    # ── SQL Injection ────────────────────────────────────────────────────

    "SQL Injection (Concatenation)": {
        "title":           "Use parameterised queries instead of string concatenation",
        "priority_action": "Replace every string-concatenated SQL with a parameterised query NOW.",
        "insecure_example": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "secure_example": (
            "# SQLite / most databases: use ? as placeholder\n"
            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n\n"
            "# PostgreSQL with psycopg2: use %s\n"
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        ),
        "steps": [
            "Replace all string concatenation in SQL with ? or %s placeholders.",
            "Pass values as a tuple to cursor.execute().",
            "Consider using an ORM (SQLAlchemy) which handles escaping automatically.",
            "Run a SQL injection scanner like sqlmap on your staging environment.",
        ],
    },

    "SQL Injection (f-string)": {
        "title":           "Replace f-string SQL with parameterised queries",
        "priority_action": "f-string SQL is never safe — switch to parameterised queries immediately.",
        "insecure_example": "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        "secure_example": (
            "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))"
        ),
        "steps": [
            "Search the codebase for f\"...SELECT/INSERT/UPDATE/DELETE...\" patterns.",
            "Replace every one with a parameterised query.",
            "Enable SQL query logging in development to audit all queries.",
        ],
    },

    "SQL Injection (.format)": {
        "title":           "Replace .format() SQL with parameterised queries",
        "priority_action": "Remove all .format() SQL patterns — they are directly injectable.",
        "insecure_example": "cursor.execute('SELECT * FROM users WHERE id = {}'.format(uid))",
        "secure_example": (
            "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"
        ),
        "steps": [
            "Replace all .format() SQL patterns with placeholders.",
            "Audit every database query in the project.",
        ],
    },

    # ── Unsafe Practices ─────────────────────────────────────────────────

    "SSL Verification Disabled": {
        "title":           "Enable SSL certificate verification",
        "priority_action": "Remove verify=False — it opens the connection to MITM attacks.",
        "insecure_example": "requests.get(url, verify=False)",
        "secure_example": (
            "# Default: verify=True (always verify)\n"
            "requests.get(url)\n\n"
            "# If using a self-signed cert, point to the CA bundle:\n"
            "requests.get(url, verify='/path/to/ca-bundle.crt')"
        ),
        "steps": [
            "Remove verify=False from all requests calls.",
            "If you have a self-signed certificate, provide the CA bundle path instead.",
            "In production, use certificates from a trusted CA (e.g. Let's Encrypt).",
        ],
    },

    "Weak Hashing (MD5)": {
        "title":           "Replace MD5 with SHA-256 or bcrypt",
        "priority_action": "MD5 is broken — never use for passwords or integrity checks.",
        "insecure_example": "hash_val = hashlib.md5(password.encode()).hexdigest()",
        "secure_example": (
            "import hashlib\n"
            "# For file integrity checks (not passwords):\n"
            "hash_val = hashlib.sha256(data).hexdigest()\n\n"
            "# For password hashing:\n"
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
        ),
        "steps": [
            "Replace hashlib.md5() with hashlib.sha256() for non-password checksums.",
            "For password storage, use bcrypt, argon2, or PBKDF2 instead.",
            "Rehash all existing MD5 password hashes on next user login.",
        ],
    },

    "Weak Hashing (SHA1)": {
        "title":           "Replace SHA-1 with SHA-256 or stronger",
        "priority_action": "SHA-1 is deprecated — upgrade to SHA-256 minimum.",
        "insecure_example": "digest = hashlib.sha1(data).hexdigest()",
        "secure_example": (
            "import hashlib\n"
            "digest = hashlib.sha256(data).hexdigest()"
        ),
        "steps": [
            "Replace all hashlib.sha1() with hashlib.sha256() or hashlib.sha3_256().",
            "Update any stored digests or hashes to the new algorithm.",
        ],
    },

    "Debug Mode Enabled": {
        "title":           "Disable debug mode in production",
        "priority_action": "Set DEBUG=False before any production deployment.",
        "insecure_example": "app.run(debug=True)",
        "secure_example": (
            "import os\n"
            "# Read from environment — defaults to False\n"
            "app.run(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')\n\n"
            "# Or in config:\n"
            "app.config['DEBUG'] = False"
        ),
        "steps": [
            "Set debug=False (or DEBUG=False) in production configuration.",
            "Use environment variables to control debug mode: FLASK_DEBUG=false.",
            "Ensure error pages do not expose stack traces to end users.",
        ],
    },

    "Insecure Random (random module)": {
        "title":           "Use the secrets module for security-sensitive randomness",
        "priority_action": "Replace random.* with secrets.* for any token, ID, or key generation.",
        "insecure_example": "token = str(random.randint(100000, 999999))",
        "secure_example": (
            "import secrets\n"
            "# Cryptographically secure token (16 bytes = 32 hex chars)\n"
            "token = secrets.token_hex(16)\n\n"
            "# Secure random integer in range:\n"
            "secure_int = secrets.randbelow(1000000)"
        ),
        "steps": [
            "Import secrets instead of random for security-sensitive values.",
            "Use secrets.token_hex(), secrets.token_urlsafe(), or secrets.randbelow().",
            "The random module is fine for simulations — not for security.",
        ],
    },

    "Wildcard CORS / Allowed Hosts": {
        "title":           "Restrict CORS origins to known domains",
        "priority_action": "Remove the wildcard (*) and specify exact allowed origins.",
        "insecure_example": "CORS(app, resources={r'/*': {'origins': '*'}})",
        "secure_example": (
            "from flask_cors import CORS\n"
            "CORS(app, resources={r'/api/*': {'origins': [\n"
            "    'https://myapp.com',\n"
            "    'https://www.myapp.com'\n"
            "]}}, supports_credentials=True)"
        ),
        "steps": [
            "Replace * with an explicit list of trusted origins.",
            "Separate public and private API endpoints.",
            "Enable supports_credentials=True only if session cookies are used.",
        ],
    },

    # ── File Upload Security ──────────────────────────────────────────────

    "Unsafe File Upload": {
        "title":           "Validate uploaded file types and names",
        "priority_action": "Add extension validation and save files outside the web root.",
        "insecure_example": "file = request.files['upload']\nfile.save(os.path.join(UPLOAD_FOLDER, file.filename))",
        "secure_example": (
            "import os\n"
            "from werkzeug.utils import secure_filename\n\n"
            "ALLOWED_EXTENSIONS = {'png', 'jpg', 'gif', 'pdf'}\n\n"
            "def allowed_file(filename):\n"
            "    return '.' in filename and \\\n"
            "           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS\n\n"
            "file = request.files['upload']\n"
            "if file and allowed_file(file.filename):\n"
            "    filename = secure_filename(file.filename)\n"
            "    file.save(os.path.join(UPLOAD_FOLDER, filename))"
        ),
        "steps": [
            "Whitelist allowed file extensions using ALLOWED_EXTENSIONS.",
            "Always use werkzeug.utils.secure_filename() to sanitize the filename.",
            "Store uploads outside the web root (not in /static/).",
            "Scan uploaded files with a virus scanner in sensitive contexts.",
            "Rename uploaded files server-side to prevent path traversal.",
        ],
    },

    # ── Low Severity ─────────────────────────────────────────────────────

    "Suspicious Keyword": {
        "title":           "Resolve all TODO/FIXME/DEBUG items before release",
        "priority_action": "Audit every marker and either fix it or create a tracked issue.",
        "insecure_example": "# TODO: add authentication check here",
        "secure_example": (
            "# Implement proper authentication:\n"
            "if not current_user.is_authenticated:\n"
            "    return redirect(url_for('login'))"
        ),
        "steps": [
            "Search the codebase for TODO, FIXME, DEBUG, TEMP.",
            "Resolve each one or create a tracked issue in your project board.",
            "Add a CI linting rule to block commits with debug code patterns.",
            "Never ship debug endpoints or admin bypasses to production.",
        ],
    },
}


# -----------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------

def get_recommendation(issue_name):
    """
    Return the security recommendation for a given vulnerability issue name.

    Parameters
    ----------
    issue_name : str
        The 'issue' field from a vulnerability finding.

    Returns
    -------
    dict with keys: title, priority_action, insecure_example, secure_example, steps
    OR a generic fallback.
    """
    return RECOMMENDATIONS.get(issue_name, {
        "title":            f"Review and fix: {issue_name}",
        "priority_action":  "Review this pattern and consult OWASP guidelines.",
        "insecure_example": "# Potentially insecure pattern detected",
        "secure_example":   "# Apply secure coding practices for this pattern",
        "steps": [
            "Research secure alternatives for this pattern.",
            "Consult OWASP guidelines for your language/framework.",
            "Have a security-aware colleague review this code.",
        ],
    })


def get_all_recommendations():
    """
    Return a list of all recommendation issue names.
    Useful for building a recommendations catalogue UI.
    """
    return list(RECOMMENDATIONS.keys())
