# Contributing to Windows Mini-EDR

Thank you for your interest! This project welcomes bug reports, new detection rules, improved MITRE mapping, and documentation improvements.

## Getting Started

```bat
REM Requires Windows + Python 3.10+
git clone https://github.com/YOUR_USERNAME/windows-mini-edr.git
cd windows-mini-edr

pip install -r requirements.txt
pip install pytest pytest-cov

python -m pytest tests/ -v
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feat/your-feature-name`
3. **Write code** following the style guide below
4. **Add tests** in `tests/`
5. **Run tests**: `python -m pytest tests/ -v`
6. **Submit PR** against `main`

## Code Style

- PEP 8, max line length 120 characters
- Type hints on all public functions
- Docstrings on all classes and public methods

## Adding a Detection Rule

Detection rules live in `config/rules.json`. Each rule has this structure:

```json
{
    "parent": "winword.exe",
    "child": "powershell.exe",
    "severity": "HIGH",
    "description": "Office app spawning PowerShell — possible macro malware",
    "mitre_id": "T1059.001",
    "mitre_name": "PowerShell",
    "mitre_tactic": "Execution"
}
```

Rules are evaluated in `modules/process_detector.py` — see the `check_parent_child()` function.

## Adding to the Blacklist

Edit `config/blacklist.json` to add process names or keyword patterns to detect:

```json
{
    "process_names": ["new-malware.exe"],
    "patterns": ["new-keyword"]
}
```

## Reporting Vulnerabilities

Do **not** open a public issue for security vulnerabilities.
Email: ghimirenitesh8@gmail.com with subject "SECURITY: windows-mini-edr"

## Code of Conduct

Be respectful and constructive. See [Contributor Covenant](https://www.contributor-covenant.org/).
