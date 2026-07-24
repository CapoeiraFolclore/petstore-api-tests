# Security Review Prompts

Copy/paste these prompts when working with Cursor agents, PR reviewers, or CI documentation.

---

## Default scan prompt

```text
Scan this project for security concerns
```

**Expected agent behavior:**

1. Run `./run_security_scan.sh` (static scan + `pip-audit -r requirements.txt`)
2. Report each static check executed (SEC-001 – SEC-012)
3. Summarize static findings in a table: Severity | Location | Finding | Remediation
4. Summarize dependency audit results (package, advisory/CVE, fix version) or note none found
5. Do not change code unless asked

---

## Pre-merge code generation prompt

```text
Generate [describe feature] following docs/SECURITY_GUIDELINES.md and the secure-code-generation skill.

Requirements:
- No hardcoded secrets; use environment variables
- Validate external input and restrict config paths to an allowlist
- Redact sensitive fields in logs
- Keep TLS verification enabled
- Add # SECURITY-REVIEW comments where required
- Run ./run_security_scan.sh when done and report findings
```

---

## Security review prompt (manual + automated)

```text
You are a cybersecurity expert. Review this project against OWASP Top 10, ISO 27001 Annex A, and NIST CSF.

Steps:
1. Run ./run_security_scan.sh (static scan + pip-audit)
2. Read docs/SECURITY_GUIDELINES.md
3. Inspect HTTP client, config loader, and test data patterns
4. Report:
   - Each static test/check run and PASS/FAIL/WARN
   - Dependency audit results from pip-audit
   - Findings sorted by severity
   - Common remediation for each violation
5. Do not fix code unless I ask
```

---

## Fix findings prompt

```text
Fix all Medium and High security findings from the latest ./run_security_scan.sh run.

Prioritize:
1. Sensitive data in logs
2. Path traversal / env allowlist in config loading
3. Any hardcoded secrets

Re-run ./run_security_scan.sh and confirm results.
```

---

## CI/CD gate prompt

```text
Add a CI step that runs ./run_security_scan.sh --format json and fails the pipeline on High or Medium findings.
Document the gate in README.md.
```

---

## Skill invocation

In Cursor, reference the project skill:

```text
Use the secure-code-generation skill to implement [task].
```

Skill path: `.cursor/skills/secure-code-generation/Security_SKILL.md`
