# Security Guidelines for Code Generation & Review

This document defines the security baseline for the **petstore-api-tests** project and any code generated or reviewed within it. It aligns with:

- **OWASP Top 10 (2021)**
- **ISO/IEC 27001:2022** Annex A control themes
- **NIST Cybersecurity Framework (CSF) 2.0**

Use together with:

- `./run_security_scan.sh` — automated static scan
- `.cursor/skills/secure-code-generation/Security_SKILL.md` — agent skill
- `docs/SECURITY_REVIEW_PROMPT.md` — reusable prompts

---

## 1. Purpose and scope

These guidelines apply to:

- Python framework code (`api_tests/`)
- Test code (`tests/`)
- Configuration (`config/`, `.env.example`)
- Shell runners (`run_tests.sh`, `run_security_scan.sh`)
- Dependencies (`requirements.txt`)

They do **not** replace formal penetration testing, CVE monitoring, or ISO 27001 certification.

---

## 2. Secure development principles

1. **Least privilege** — request only the access, headers, and credentials a component needs.
2. **Defense in depth** — validate at boundaries; never trust external input (API responses, env vars, files).
3. **Fail securely** — on error, do not expose internals, stack traces, or secrets.
4. **Secure by default** — TLS verification on, secrets out of source control, logging redacted.
5. **Auditability** — log security-relevant events without logging sensitive data.

---

## 3. OWASP Top 10 checklist for generated code

### A01:2021 — Broken Access Control

- Enforce authorization in code paths that call protected APIs, not only in tests' assumptions.
- Do not bypass auth checks in production configuration.

**Common fix:** Use established auth libraries; verify tokens on every protected request.

### A02:2021 — Cryptographic Failures

- Never hardcode secrets, API keys, or private keys.
- Use TLS 1.2+; keep certificate verification enabled.
- Do not use MD5/SHA-1/DES for security purposes.

**Common fix:** Store secrets in environment variables or a vault; use `verify=True` on HTTP clients.

### A03:2021 — Injection

- Do not use `eval()`, `exec()`, or `subprocess` with `shell=True` on untrusted data.
- Use parameterized queries/ORMs for any future database work.
- Sanitize/allowlist environment names and file paths.

**Common fix:** Replace string-built SQL/shell with parameterized APIs and allowlists.

### A04:2021 — Insecure Design

- Prefer creating test data dynamically instead of relying on seeded demo IDs.
- Document trust boundaries (public PetStore API vs internal targets).

**Common fix:** Design tests to be self-contained and environment-aware.

### A05:2021 — Security Misconfiguration

- Keep `.env` out of git; provide `.env.example` with placeholders only.
- Do not disable TLS or debug modes in production configs.

**Common fix:** Add `.env` to `.gitignore`; use separate `config/prod.yaml` with strict settings.

### A06:2021 — Vulnerable and Outdated Components

- Pin dependencies in `requirements.txt`.
- Monitor CVEs (e.g. `pip-audit`, Dependabot).

**Common fix:** Use `package>=x,<y` or `==` pins; maintain a lock file if the project grows.

### A07:2021 — Identification and Authentication Failures

- Never commit credentials in YAML/JSON config.
- Do not log session tokens or passwords.

**Common fix:** Load auth headers from env; rotate any exposed credential immediately.

### A08:2021 — Software and Data Integrity Failures

- Do not download artifacts at runtime without checksum/signature verification.
- Prefer vendored swagger specs over live `curl` downloads.

**Common fix:** Commit `specs/petstore.swagger.json`; verify SHA-256 if downloading.

### A09:2021 — Security Logging and Monitoring Failures

- Log request metadata (method, URL, status, latency), not full bodies with secrets.
- Catch specific exceptions; avoid bare `except: pass`.

**Common fix:** Redact sensitive JSON keys before logging; use structured logging.

### A10:2021 — Server-Side Request Forgery (SSRF)

- Restrict `API_BASE_URL` to known hosts in shared/CI environments.
- Avoid passing user-controlled URLs directly to HTTP clients.

**Common fix:** Allowlist hostnames; reject file/metadata IP ranges.

---

## 4. ISO/IEC 27001:2022 mapping (selected Annex A themes)

| Control theme | Requirement in this project |
|---------------|----------------------------|
| **A.8.15 Logging** | Log security events; redact PII and credentials |
| **A.8.24 Use of cryptography** | TLS for all remote API calls in non-local envs |
| **A.8.26 Application security** | Input validation, safe HTTP client usage |
| **A.8.28 Secure coding** | No secrets in source; safe error handling |
| **A.8.31 Separation of environments** | Distinct `dev` / `staging` / `prod` configs |
| **A.8.32 Change management** | No credentials in committed config files |
| **A.10.1.1 Cryptographic controls** | Modern algorithms only when crypto is added |

---

## 5. NIST CSF 2.0 mapping

| Function | Application |
|----------|-------------|
| **Govern (GV)** | Follow this document and run `./run_security_scan.sh` in CI |
| **Identify (ID)** | Track dependencies; assess config/SSRF risks |
| **Protect (PR)** | Secrets management, TLS, secure coding patterns |
| **Detect (DE)** | Logging and scanner findings |
| **Respond (RS)** | Rotate leaked credentials; fix High/Medium findings promptly |
| **Recover (RC)** | Document rollback for bad config deployments |

---

## 6. Required code annotations

Add `# SECURITY-REVIEW: <reason>` when generating code that handles:

- Authentication or session management
- File system access with configurable paths
- External HTTP calls with configurable URLs
- Deserialization of external data
- `subprocess`, shell commands, or OS calls
- PII, PHI, or PCI-related data

Example:

```python
# SECURITY-REVIEW: outbound HTTP with env-controlled base URL
response = self.session.request(method, url, verify=self.config.verify_ssl)
```

---

## 7. Automated scanner

Run before merging:

```bash
./run_security_scan.sh
```

Checks **SEC-001** through **SEC-012** (see skill file for names). Exit code `1` means High/Medium findings exist.

---

## 8. Manual review triggers

Run a manual review when changes touch:

- `api_tests/http_client.py` — logging, TLS, URL building
- `api_tests/config.py` — env loading, path resolution
- `config/*.yaml` — base URLs, auth blocks
- `run_tests.sh` — network downloads, env exports
- `requirements.txt` — new dependencies

---

## 9. Finding severity and response

| Severity | Response |
|----------|----------|
| **High** | Block merge; fix before release |
| **Medium** | Fix before production use; document exception if demo-only |
| **Low** | Fix or accept with documented rationale |

---

## 10. References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- Project scanner: `api_tests/security_scan.py`
