# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2025-04-15

### Added
- GitHub Actions CI workflow (`ci-windows.yml`) running on `windows-latest`
- Unit tests for `AlertEngine`, `BaselineManager`, `ProcessDetector`
- `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`

## [3.0.0] - 2025-03-15

### Added
- Rich live terminal dashboard (`--watch N --dashboard`)
- Baseline drift detection (`--baseline` / `--compare`)
- Auto-kill HIGH-severity threats (`--kill`, `--kill-dry-run`, `--kill-force`)
- MITRE ATT&CK mapping for all 12+ detection categories
- Per-alert numeric risk scoring (0–100) with category modifiers
- Structured JSONL streaming log output
- 40+ parent-child detection rules in `config/rules.json`
- Typosquatting detection for critical system processes
- Authenticode signature verification (`--signatures`)

### Changed
- Rewrote core detection pipeline: process enum → parent-child → service audit → hash/blacklist
- `AlertEngine` now uses dataclass + MD5 fingerprint deduplication for real-time mode

## [2.0.0] - 2024-12-01

### Added
- Service auditing: unquoted paths, suspicious binary locations, unsigned binaries
- Whitelist/blacklist config files (`config/whitelist.json`, `config/blacklist.json`)
- Known-bad hash database (`config/known_bad_hashes.json`)
- JSON and TXT report generation

## [1.0.0] - 2024-09-01

### Added
- Initial release
- Basic process enumeration using `psutil`
- WMI-based service enumeration
- Colored console output via `colorama`
