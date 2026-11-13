# 🛡️ GitShield — Zero-Dependency Pre-Commit Secret & Permission Blocker

**GitShield** is a lightweight, zero-dependency Python 3 CLI and native Git `pre-commit` security hook that inspects staged code changes (`git diff --cached`) in milliseconds—blocking hardcoded credentials (via regex signatures and **Shannon entropy analysis**) and unsafe world-writable permissions (`chmod 777`) before they ever enter Git history.

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-00FF9D?logoColor=black)
![Shift-Left Security](https://img.shields.io/badge/DevSecOps-Pre--Commit%20Hook-00E5FF?logoColor=black)

---

## 🏗️ Pre-Commit Interception Architecture

<pre lang="mermaid">
flowchart LR
    A[Developer: git commit] --> B[.git/hooks/pre-commit<br/>gitshield.py]
    B --> C[Inspect Staged Files<br/>git diff --cached]
    C --> D[Regex Signature Scanner<br/>AWS Keys, PEM, GitHub PATs]
    C --> E[Shannon Entropy Analyzer<br/>H >= 4.5 bits/char]
    C --> F[POSIX Permission Auditor<br/>Block 100777 / chmod 777]
    D --> G{Violations<br/>Detected?}
    E --> G
    F --> G
    G -->|No Violations| H[Exit 0: Commit Allowed]
    G -->|Violation Found| I[Exit 1: Commit Blocked + Redacted Alert]

    style B fill:#00E5FF,stroke:#00E5FF,color:#000
    style H fill:#00FF9D,stroke:#00FF9D,color:#000
    style I fill:#FF6B6B,stroke:#FF6B6B,color:#000
</pre>

---

## ✨ Key Security Capabilities

* **Deterministic Regex Detection:** Catches AWS Access Key IDs (`AKIA...`), RSA/EC/OpenSSH PEM private key headers, GitHub Personal Access Tokens (`ghp_...`), and generic hardcoded secret assignments.
* **Shannon Entropy Token Detection:** Calculates character-distribution entropy ($H(X) = -\sum P(x_i)\log_2 P(x_i)$) on candidate strings ($\ge 20$ chars) to catch unknown high-randomness API tokens ($H \ge 4.5$) without relying solely on static regex rules.
* **Unsafe Permission Blocker (`chmod 777`):** Inspects both Git index modes (`100777`) and local filesystem `stat` bits (`stat.S_IWOTH`) to prevent world-writable scripts or configs from entering version control.
* **Zero External Dependencies:** Built 100% with Python's standard library (`re`, `math`, `stat`, `subprocess`, `argparse`), requiring zero `pip` packages on developer workstations.
* **Safe Log Redaction & Allowlisting:** Masks detected secrets (`AKIA...MPLE`) in terminal output and supports explicit `# gitshield:ignore` inline markers for intentional unit test fixtures.

---

## 🚀 Installation & CLI Usage

### 1. Install into Any Git Repository
```bash
git clone https://github.com/NejamulHaque/GitShield.git
cd GitShield
bash install.sh
```
*(Or copy `gitshield.py` into any target project and run `python3 gitshield.py --install`.)*

### 2. Automatic Pre-Commit Enforcement
Once installed, every `git commit` triggers GitShield automatically:
```bash
git add config.py
git commit -m "update config"
# 🛡️ GitShield: Staged changes passed secret & permission checks.
```

### 3. Standalone File Audit Mode
Scan any file on disk directly without staging it in Git:
```bash
python3 gitshield.py --file path/to/file.py
```

---

## 🧪 Running the Test Suite

```bash
pip install pytest
pytest -v
```

---

## 👤 Author

**Nejamul Haque** — DevOps, SRE & DevSecOps Engineer  
🌐 [Portfolio](https://nejamulhaque.vercel.app) · 💼 [LinkedIn](https://www.linkedin.com/in/nejamulhaque) · 🐙 [GitHub](https://github.com/NejamulHaque)
