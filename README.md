# CodeSentinel ML

CodeSentinel ML is an ML-assisted secure code intelligence system that helps identify risky coding practices in source code using static analysis and machine learning.

## Features
- **Source Code Upload System**: Upload various source code files for analysis.
- **Safe File Handling**: Secure reading and processing of uploaded code.
- **File Metadata Analysis**: Extraction of file properties.
- **Basic Static Code Statistics**: Insights into code composition (comments, lines, imports, etc.).
- **Suspicious Keyword Analysis**: Detection of potentially dangerous functions and hardcoded secrets.
- **Interactive Dashboard**: A clean, beginner-friendly Streamlit UI.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   streamlit run app.py
   ```
