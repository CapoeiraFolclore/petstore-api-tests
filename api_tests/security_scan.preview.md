# Security Scanner Preview

> **Cursor Preview tab:** Open this file in Cursor and select **Preview** in the tab bar (`Preview | Markdown`) alongside **Code** and **Blame**.

Companion files for `security_scan.py`:

| File | Tab | Purpose |
|------|-----|---------|
| `security_scan.py` | Code / Blame | Scanner implementation |
| `security_scan.preview.md` | **Preview** | Static documentation (this file) |
| `security_scan.report.md` | **Preview** | Latest scan results (generated) |

Regenerate the results preview:

```bash
./run_security_scan.sh --write-preview
```

---

## Purpose

Static security scanner mapped to:

- **OWASP Top 10 (2021)**
- **ISO/IEC 27001:2022** Annex A control themes
- **NIST Cybersecurity Framework (CSF) 2.0**

Default prompt: **Scan this project for security concerns**

Runs static checks (SEC-001 – SEC-012) and `pip-audit -r requirements.txt`.

---

## How to use

```bash
# Terminal report
./run_security_scan.sh

# JSON for CI
./run_security_scan.sh --format json

# Markdown preview report (opens in Preview tab)
./run_security_scan.sh --write-preview

# HTML report in browser
./run_security_scan.sh --format html --output reports/security_scan.html
```

---

## Check catalog

| ID | Check | Severity | OWASP | ISO 27001 | NIST CSF |
|----|-------|----------|-------|-----------|----------|
| SEC-001 | Hardcoded Secrets Detection | High | A07 | A.8.28 | PR.DS |
| SEC-002 | Injection and Dangerous Execution | High | A03 | A.8.26 | PR.PT |
| SEC-003 | Sensitive Data in Logs | Medium | A09 | A.8.15 | DE.AE |
| SEC-004 | Weak Cryptography | Medium | A02 | A.10.1.1 | PR.DS-1 |
| SEC-005 | TLS Verification Disabled | Medium | A02 | A.8.24 | PR.DS-2 |
| SEC-006 | `.env` Gitignore Protection | High | A02 | A.8.28 | PR.DS |
| SEC-007 | Secrets in Committed Configuration | Medium | A07 | A.8.32 | PR.AC |
| SEC-008 | Path Traversal in Config Loading | Low | A03 | A.8.26 | PR.PT-3 |
| SEC-009 | Unverified Remote Downloads | Low | A06 | A.8.31 | ID.SC |
| SEC-010 | SSRF URL Handling | Low | A10 | A.8.26 | PR.PT |
| SEC-011 | Unsafe Error Handling | Low | A09 | A.8.15 | DE.CM |
| SEC-012 | Dependency Pinning Hygiene | Low | A06 | A.8.31 | ID.RA |

---

## Common remediations

### SEC-001 — Hardcoded secrets

**Issue:** API keys, tokens, or passwords in source code.

**Fix:** Use environment variables or a secrets manager. Rotate any exposed credential.

### SEC-003 — Sensitive data in logs

**Issue:** Full HTTP bodies or auth headers logged.

**Fix:** Redact `Authorization`, `password`, `token`, and `api_key` before logging.

### SEC-005 — TLS verification disabled

**Issue:** `verify=False` or `verify_ssl: false`.

**Fix:** Keep certificate validation enabled in production; use proper trust stores.

### SEC-008 — Path traversal in config

**Issue:** Environment name used directly in file paths.

**Fix:** Allowlist `dev`, `staging`, `prod` and resolve paths under a trusted base directory.

---

## Related documentation

- `docs/SECURITY_GUIDELINES.md` — full secure coding baseline
- `docs/SECURITY_REVIEW_PROMPT.md` — agent/human review prompts
- `.cursor/skills/secure-code-generation/Security_SKILL.md` — Cursor skill

---

## Latest results

Open **`security_scan.report.md`** (Preview tab) for the most recent scan output.

If missing, run:

```bash
./run_security_scan.sh --write-preview
```
