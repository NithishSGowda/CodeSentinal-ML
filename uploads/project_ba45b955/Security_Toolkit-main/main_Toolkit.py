# main_toolkit.py
# Import the run functions from your three modules
from cipher_module import run_caesar_cipher
from password_module import run_password_checker
from scanner_module import run_port_scanner

def main_menu():
    """Displays the main menu and handles user selection."""
    while True:
        print("\n====================================")
        print("🛡️ Basic Security Utility Toolkit 🛠️")
        print("====================================")
        print("1. Run Caesar Cipher Tool")
        print("2. Run Password Strength Checker")
        print("3. Run Simple Port Scanner")
        print("4. Exit Toolkit")
        print("------------------------------------")
        
        choice = input("Select a tool (1-4): ")
        
        if choice == '1':
            run_caesar_cipher()
        elif choice == '2':
            run_password_checker()
        elif choice == '3':
            run_port_scanner()
        elif choice == '4':
            print("👋 Exiting Toolkit. Stay secure!")
            break
        else:
            print("❌ Invalid choice. Please select 1, 2, 3, or 4.")
        
if __name__ == "__main__":
    main_menu()