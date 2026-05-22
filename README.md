# ⚡ CodeSentinel ML: ML-Assisted Repository Security Intelligence Platform

CodeSentinel ML is a production-style, privacy-first cybersecurity platform that scans, categorizes, prioritizes, and visualizes source-code vulnerabilities using a **hybrid threat engine** (deterministic regex signatures + local supervised machine learning).

It is designed to run **100% locally**—preserving total code privacy without sending any intellectual property or source code to external LLM APIs (OpenAI/Gemini/Claude). It generates advanced visual analytics, calculates custom security indexes, and yields exfiltratable compliance reporting.

---

## 🚀 Key Features

*   **🔍 Repository-Level Static Scanning**: Traverses entire directory structures recursively, parsing `.py`, `.js`, `.ts`, `.php`, and `.java` source code with size safety protection (<1MB) and file count caps (max 500 files) to prevent memory crashes.
*   **🔗 Attack Chain Correlation Engine**: Identifies risky entry vectors (Flask/FastAPI/Express routing, PHP superglobals, form arguments) and traces whether unvalidated user input reaches dangerous sinks (like `eval()`, `exec()`, or direct SQL injection queries) within a 15-line execution window.
*   **🧠 Local Supervised Machine Learning**: Supervised TF-IDF + Logistic Regression trained on secure vs insecure code samples. Yields risk levels (Safe, Medium, High), probability confidence matrices, and explainable key syntactic indicators.
*   **📊 "Vibe Coding" Risk Index**: A customized mathematical scoring model checking development quality indicators. Adds penalties for wildcard CORS, bare exceptions, disabled SSL checks, hardcoded credentials, and lack of parameter validation.
*   **🏆 Security Posture Grading**: Assigns definitive posture grades (A, B, C, D, F) based on a composite vulnerability health score.
*   **🛠️ Architecture Patch Panel**: Displays code remediation examples. Contrasts the vulnerable state side-by-side with secure coding alternatives.
*   **🚨 Animated SOC live Event Console**: Outputs typewriter-style real-time scan event streams.
*   **📥 Data Exfiltration Panel**: Generates physical download files including **JSON extracts**, **CSV flaw matrices**, and **PDF executive reports**.

---

## 🛠️ Technology Stack

### Backend
*   **Python**: Core execution runtime.
*   **Flask Server**: Microservices backend host. Serves Next.js React client requests and hosts threat metrics on port 5000.
*   **Scikit-Learn**: Powering TF-IDF text vectorisation and Logistic Regression local risk classification.
*   **Pandas & FPDF2**: Dataframe manipulations and custom PDF report compilation.

### Frontend
*   **React / Next.js**: Production SPA.
*   **Tailwind CSS**: Dark neon tactical UI ("Kevlar, Chrome & Flare").
*   **Framer Motion**: Smooth telemetry panels transitions and pulsing attack chain elements.
*   **Lucide React**: Clean vector cybersecurity dashboard iconography.

---

## 📂 Repository Structure

```text
CodeSentinel-ML/
│
├── server.py                  # Flask REST API Server (Port 5000)
├── requirements.txt           # Python library dependencies
├── README.md                  # Comprehensive Documentation
├── presentation_material.md   # Academic & Internship Presentation Dossier
│
├── scanner/                   # Static Analysis Core
│   ├── patterns.py            # Central Registry for regexes & signatures
│   ├── detector.py            # Vulnerability detection & LOC statistics
│   ├── entry_detector.py      # Entry point parameter analyzer
│   ├── attack_chain.py        # Input-to-sink flow correlation engine
│   ├── prioritizer.py         # Advanced security score prioritisation
│   ├── intelligence.py        # Posture grading, narrative generator, logs
│   ├── explanations.py        # Vulnerability danger explanation sheets
│   └── recommendations.py     # Remediation secure code state suggestions
│
├── ml/                        # Supervised Machine Learning Pipeline
│   ├── model.py               # Preprocessing, vectorizer, and classifier
│   ├── dataset.csv            # Security-focused training data rows
│   ├── trained_model.pkl      # Serialized Logistic Regression pickle
│   └── vectorizer.pkl         # Serialized TF-IDF vectorizer pickle
│
├── frontend/                  # Next.js React SPA Dashboard
│   ├── app/
│   │   ├── page.tsx           # Full dynamic React SOC dashboard
│   │   ├── layout.tsx         # Global fonts and layouts config
│   │   └── globals.css        # Kevlar, Chrome & Flare custom stylesheet
│   └── package.json           # Next.js workspace config
│
├── uploads/                   # Temporary directory for zip extractions
└── reports/                   # Compiled PDF reports storage
```

---

## 💻 Installation & Setup

Ensure you have **Python 3.10+** and **Node.js 18+** installed.

### 1. Clone & Set Up Python Environment
Clone the repository, create a virtual environment, and install libraries:
```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On macOS/Linux:
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 2. Set Up Frontend Node Packages
Navigate to the Next.js frontend directory and install dependencies:
```bash
cd frontend
npm install
cd ..
```

---

## 🏃 Running the Application

CodeSentinel ML supports two independent visual delivery systems.

### Running the Platform
This project runs as a decoupled modern architecture hosting a Flask REST API backend and a Next.js React frontend console.

1.  **Launch Python Flask Backend** (port 5000):
    ```bash
    python server.py
    ```
2.  **Launch Next.js Cyber Console** (port 3000) in a separate terminal:
    ```bash
    cd frontend
    npm run dev
    ```
3.  Open browser to [http://localhost:3000](http://localhost:3000) to view the interactive dark-neon SOC console.

---

## 🎯 Verification & Manual Testing

### Running Scans
You can scan repositories in three ways on the interactive console:
1.  **Local Folder Path**: Enter the absolute filesystem directory (e.g. `F:\Internship\CodeSentinel-ML`).
2.  **GitHub Repo Web URL**: Input any public git link. The server will download the zip archive, extract it safely, perform a multi-file scan, and delete temp directories on completion.
3.  **Upload ZIP Archive**: Direct drag-and-drop of compressed repositories.

### Exporting Reports
Navigate to the **Downloads / Exfiltration** tab in the console UI to physically download:
*   **PDF Report**: An executive document featuring threat grades, top prioritized vulnerabilities, and detailed attack chain graphs.
*   **CSV Findings Matrix**: Direct developer spreadsheet for issue tracking.
*   **JSON Raw Output**: Full JSON response payload suitable for ingestion into external log managers or SIEM engines.
