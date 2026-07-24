---
name: secure-code-generation
description: >-
  Generate and review code using OWASP, ISO 27001, and NIST security baselines.
  Use when writing new code, modifying API clients/tests, running security reviews,
  or when the user asks to scan this project for security concerns.
---

# Secure Code Generation & Review

Apply this skill when **generating**, **modifying**, or **reviewing** code in this repository.

## Default prompts

| User intent | Action |
|-------------|--------|
| "Scan this project for security concerns" | Run `./run_security_scan.sh`, summarize findings |
| "Review security" / "/review-security" | Run scanner + manual review against checklist below |
| Writing new Python/shell/config code | Follow generation checklist before finishing |

## Workflow

### 1. Before writing code

Read `docs/SECURITY_GUIDELINES.md` when touching:

- HTTP clients, auth, config loading
- Logging, error handling
- Shell scripts, dependency files
- Files handling user/API input

### 2. While writing code

Apply the **Generation Checklist** (minimum bar):

- [ ] No hardcoded secrets — use env vars or secret managers
- [ ] Validate external input; prefer allowlists
- [ ] No `eval`, `exec`, `shell=True`, or dynamic SQL concatenation
- [ ] TLS verification enabled in production paths (`verify=True` / `verify_ssl: true`)
- [ ] Redact sensitive fields in logs (`Authorization`, `password`, `token`, `api_key`)
- [ ] Generic user-facing errors; detailed logs server-side only
- [ ] Pin dependencies in `requirements.txt`
- [ ] Add `# SECURITY-REVIEW: <reason>` for auth, subprocess, file I/O, external HTTP, deserialization

### 3. After writing code

Run the project scanner:

```bash
./run_security_scan.sh
```

Optional JSON for CI:

```bash
./run_security_scan.sh --format json
```

### 4. When reporting findings

Summarize as a markdown table:

| Severity | Location | Finding | Remediation |
|----------|----------|---------|-------------|

Sort by severity: **High → Medium → Low**.

Include the **test/check name** when available (e.g. `SEC-003 Sensitive Data in Logs`).

Do **not** auto-fix findings unless the user asks.

## Framework mapping (quick reference)

| Topic | OWASP Top 10 | ISO 27001 | NIST CSF |
|-------|--------------|-----------|----------|
| Secrets | A07, A02 | A.8.28 | PR.DS |
| Injection | A03 | A.8.26 | PR.PT |
| Crypto/TLS | A02 | A.8.24, A.10.1.1 | PR.DS-1/2 |
| Logging | A09 | A.8.15 | DE.AE |
| Dependencies | A06 | A.8.31 | ID.SC, ID.RA |
| SSRF | A10 | A.8.26 | PR.PT |

Full control descriptions: `docs/SECURITY_GUIDELINES.md`.

## Code patterns for this project

### HTTP client logging (safe)

```python
# SECURITY-REVIEW: redact sensitive headers/fields before logging
SAFE_LOG_KEYS = {"password", "token", "api_key", "authorization"}
redacted = {k: ("***" if k.lower() in SAFE_LOG_KEYS else v) for k, v in payload.items()}
logger.info("HTTP REQUEST | json=%s", redacted)
```

### Environment config (safe)

```python
ALLOWED_ENVS = {"dev", "staging", "prod"}
if env_name not in ALLOWED_ENVS:
    raise ValueError(f"Unsupported environment: {env_name}")
config_path = (CONFIG_DIR / f"{env_name}.yaml").resolve()
if CONFIG_DIR not in config_path.parents:
    raise ValueError("Invalid config path")
```

### Secrets via environment

```python
api_key = os.getenv("API_KEY")
if not api_key:
    raise ValueError("API_KEY environment variable is required")
```

## Scanner checks (SEC-001 – SEC-012)

The built-in scanner in `api_tests/security_scan.py` runs:

1. Hardcoded secrets
2. Injection / dangerous execution
3. Sensitive data in logs
4. Weak cryptography
5. TLS verification disabled
6. `.env` gitignore protection
7. Secrets in committed config
8. Path traversal in config loading
9. Unverified remote downloads
10. SSRF URL handling
11. Unsafe error handling
12. Dependency pinning hygiene

Each check maps to OWASP / ISO 27001 / NIST and includes remediation text in output.

## Related files

- `docs/SECURITY_GUIDELINES.md` — full standards reference
- `docs/SECURITY_REVIEW_PROMPT.md` — copy/paste prompts for humans and agents
- `api_tests/security_scan.py` — scanner implementation
- `.cursor/rules/security-scan.mdc` — auto-run scan rule
