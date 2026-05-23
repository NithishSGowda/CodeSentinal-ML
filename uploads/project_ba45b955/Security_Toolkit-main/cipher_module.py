# cipher_module.py

def caesar_cipher(text, key, mode='encrypt'):
    """Encrypts or decrypts text using the Caesar Cipher."""
    result = ""
    shift = key if mode == 'encrypt' else -key
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # The core logic: (char_index + shift) % 26 + start_ascii
            new_ord = (ord(char) - start + shift) % 26 + start
            result += chr(new_ord)
        else:
            result += char
            
    return result

def run_caesar_cipher():
    """Handles user input and output for the cipher tool."""
    print("\n--- 🔒 Caesar Cipher Tool ---")
    
    while True:
        mode = input("Mode (encrypt/decrypt): ").lower()
        if mode in ['encrypt', 'decrypt']:
            break
        print("Invalid mode. Please type 'encrypt' or 'decrypt'.")
        
    text = input("Enter your message: ")
    
    while True:
        try:
            key = int(input("Enter the shift key (1-25): "))
            if 1 <= key <= 25:
                break
            print("Key must be a number between 1 and 25.")
        except ValueError:
            print("Invalid input. Please enter a number for the key.")
            
    output = caesar_cipher(text, key, mode)
    print(f"Result: **{output}**")