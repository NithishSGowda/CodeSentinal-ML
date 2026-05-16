import os
import pickle

# Hardcoded secret
api_key = "sk-1234567890abcdef"
password = 'mysecretpassword'

def unsafe_query(user_id):
    # Unsafe SQL concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    # Unsafe f-string query
    query2 = f"DELETE FROM sessions WHERE token = '{user_id}'"
    return query, query2

def execute_code(code):
    # Dangerous eval
    eval(code)
    # Dangerous os.system
    os.system("rm -rf /")

def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)

# TODO: Fix this security hole
