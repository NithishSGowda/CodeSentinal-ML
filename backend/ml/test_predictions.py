# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, 'backend')
from ml.model import predict_risk

tests = [
    ("eval(user_input)", "High Risk"),
    ("cursor.execute('SELECT * FROM users WHERE id=' + id)", "High Risk"),
    ("subprocess.Popen(request.args.get('cmd'), shell=True)", "High Risk"),
    ("os.system(cmd)", "High Risk"),
    ("pickle.loads(request.data)", "High Risk"),
    ("password = 'admin123'", "Medium Risk"),
    ("app.run(debug=True)", "Medium Risk"),
    ("hashlib.md5(password.encode()).hexdigest()", "Medium Risk"),
    ("SECRET_KEY = 'super_secret'", "Medium Risk"),
    ("cursor.execute('SELECT * FROM users WHERE id=?', (uid,))", "Safe"),
    ("token = secrets.token_hex(32)", "Safe"),
    ("SECRET_KEY = os.environ['SECRET_KEY']", "Safe"),
    ("hashed = bcrypt.generate_password_hash(password)", "Safe"),
    ("yaml.safe_load(data)", "Safe"),
    ("result = subprocess.run(['git', 'status'], shell=False)", "Safe"),
]

correct = 0
print(f"{'Status':<6} {'Conf':>7}  {'Predicted':<15} {'Expected':<15} Code")
print("-" * 80)
for code, expected in tests:
    r = predict_risk(code)
    pred = r['prediction']
    conf = r['confidence']
    status = "PASS" if pred == expected else "FAIL"
    if pred == expected:
        correct += 1
    print(f"{status:<6} {conf:>6.1f}%  {pred:<15} {expected:<15} {code[:45]}")

print()
print(f"Result: {correct}/{len(tests)} correct ({correct/len(tests)*100:.0f}%)")
