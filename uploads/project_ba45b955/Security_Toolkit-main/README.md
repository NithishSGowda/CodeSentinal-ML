# 🛡️ Basic Security Utility Toolkit

## Project Overview
This project is a beginner-level collection of Python utilities designed to introduce fundamental concepts in cybersecurity, including cryptography, password security, and network reconnaissance. Developed as a first major project, it demonstrates proficiency in **Python modular programming**, **CLI (Command Line Interface) development**, and the application of core security principles.

---

## 🛠️ Features

The toolkit includes three main utilities accessible via a central command-line menu:

### 1. Caesar Cipher Tool (`cipher_module.py`)
* **Concept:** Introduces the simplest form of **symmetric-key cryptography** (substitution cipher).
* **Functionality:** Encrypts and decrypts text using a user-defined shift key, demonstrating modular arithmetic to wrap around the alphabet.

### 2. Password Strength Checker (`password_module.py`)
* **Concept:** Implements basic **security policy checks** and **input validation**.
* **Functionality:** Evaluates a password against common industry standards (minimum length, inclusion of uppercase, lowercase, digits, and special characters) and provides a strength score and detailed feedback.

### 3. Simple Port Scanner (`scanner_module.py`)
* **Concept:** Introduces the fundamentals of **network reconnaissance** and the **TCP handshake**.
* **Functionality:** Uses the Python built-in `socket` library to scan a target IP address for common open ports (1-100), utilizing **exception handling** and **timeouts** for stability.

---

## 🚀 Getting Started

### Prerequisites

* **Python 3.x** (Ensure it is added to your system's PATH)

### Installation

1.  **Clone the Repository (once hosted on GitHub):**
    ```bash
    git clone [https://github.com/your-github-username/Security_Toolkit.git](https://github.com/your-github-username/Security_Toolkit.git)
    cd Security_Toolkit
    ```
    *(If not on GitHub yet, simply download the folder.)*

### Execution

1.  **Run the main script from your terminal or VS Code:**
    ```bash
    python main_toolkit.py
    ```
2.  Follow the on-screen menu to select and run the desired tool (1, 2, or 3).

---

## 💻 Technologies Used

* **Python 3.10+**
* **Standard Python Libraries:** `socket`, `time`, `getpass` (optional, for hidden password input)
* **Development Environment:** Visual Studio Code (VS Code) on Windows/Linux

---

## 🧠 Key Learnings and Takeaways

* **Modular Design:** Successfully broke down project functionality into three distinct, reusable Python modules.
* **Networking:** Gained hands-on experience with the `socket` module for low-level network communication (Port Scanning).
* **Error Handling:** Implemented `try...except` blocks to gracefully manage network errors and invalid user input.
* **Security Policy Implementation:** Translated abstract security rules (e.g., password complexity) into tangible code logic.

---

## 👤 Author

* Nithish S Gowda - Cybersecurity Engineering Student


---

## 📜 License

This project is licensed under the MIT License - see the LICENSE.md file for details.
