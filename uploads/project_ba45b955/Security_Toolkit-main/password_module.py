# password_module.py

def check_password_strength(password):
    """Evaluates password based on length and character diversity."""
    
    min_length = 8
    score = 0
    feedback = []
    
    # 1. Length Check
    if len(password) < min_length:
        feedback.append(f"Password must be at least {min_length} characters long.")
    else:
        score += 1
        
    # 2. Character Diversity Checks
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    has_special = any(c in special_chars for c in password)
    
    if has_upper: score += 1
    else: feedback.append("Missing: At least one UPPERCASE letter.")
    
    if has_lower: score += 1
    else: feedback.append("Missing: At least one lowercase letter.")
    
    if has_digit: score += 1
    else: feedback.append("Missing: At least one DIGIT (0-9).")
    
    if has_special: score += 1
    else: feedback.append("Missing: At least one special character.")
    
    # 3. Determine Strength
    if score == 5:
        strength = "VERY STRONG"
    elif score >= 3:
        strength = "MEDIUM"
    else:
        strength = "WEAK"
        
    return strength, feedback

def run_password_checker():
    """Handles user input and output for the password checker."""
    print("\n--- 🔑 Password Strength Checker ---")
    # Using 'getpass' is better for production, but input() is fine for a beginner tool
    password = input("Enter a password to check: ")
    
    strength, feedback = check_password_strength(password)
    
    print(f"\nPassword Strength: **{strength}**")
    
    if feedback:
        print("\n--- Improvement Needed: ---")
        for item in feedback:
            print(f"- {item}")
    else:
        print("This password meets all basic security criteria.")