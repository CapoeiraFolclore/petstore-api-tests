#!/usr/bin/env python3
"""
Comprehensive Static Security Scanner
=====================================

Purpose
-------
Scan a software project for common security weaknesses using checks mapped to:
  - OWASP Top 10 (2021) categories
  - ISO/IEC 27001:2022 Annex A control themes (information security controls)
  - NIST Cybersecurity Framework (CSF) 2.0 functions

Preview in Cursor
-----------------
Python files do not get a native Preview tab. Use the companion Markdown files:

  - ``security_scan.preview.md``  — static docs (open and click **Preview** in the tab bar)
  - ``security_scan.report.md``   — latest scan results (regenerate with ``--write-preview``)

Both files are nested under ``security_scan.py`` in the Explorer when using ``.vscode/settings.json``.

Usage
-----
    python security_scan.py
    python security_scan.py --project-root /path/to/project
    python security_scan.py --format json
    python security_scan.py --write-preview
    python security_scan.py --format html --output reports/security_scan.html

Default prompt: "Scan this project for security concerns"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# SECTION 1: CONFIGURATION
# ---------------------------------------------------------------------------
# Defines scan scope (file types, ignored directories) and default behavior.
# Keeping scope explicit reduces false positives and scan time.

DEFAULT_PROMPT = "Scan this project for security concerns"
DEFAULT_PROJECT_ROOT = Path.cwd()
MODULE_DIR = Path(__file__).resolve().parent
PREVIEW_DOC_PATH = MODULE_DIR / "security_scan.preview.md"
PREVIEW_REPORT_PATH = MODULE_DIR / "security_scan.report.md"

SCAN_EXTENSIONS = {
    ".py", ".yaml", ".yml", ".json", ".sh", ".bash", ".env", ".example",
    ".toml", ".ini", ".cfg", ".conf",
}
SKIP_DIRS = {
    ".git", ".venv", "venv", ".pytest_cache", "__pycache__",
    "htmlcov", "dist", "build", "node_modules", ".mypy_cache",
}
SELF_FILE_NAME = "security_scan.py"

# Lines commonly safe to ignore during pattern matching (examples/tests/comments).
IGNORE_LINE_MARKERS = (
    "example.com", "test-password", "your-email@example.com",
    "re.compile(", "# nosec", "# noqa", "users.noreply.github.com",
)


# ---------------------------------------------------------------------------
# SECTION 2: DATA MODELS
# ---------------------------------------------------------------------------
# Structured results make it easy to render CLI tables, JSON, or CI artifacts.


class Severity(str, Enum):
    """Normalized severity scale used in reporting."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class CheckStatus(str, Enum):
    """Outcome for an individual security test/check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass(frozen=True)
class SecurityCheck:
    """
    Definition of one security test.

    Each check maps to industry frameworks so auditors and developers can
    understand *why* the control exists, not only *what* was detected.
    """

    check_id: str
    name: str
    description: str
    owasp: str
    iso27001: str
    nist: str
    default_severity: Severity
    remediation: str
    runner: Callable[["ScanContext", "SecurityCheck"], "CheckResult"]


@dataclass(frozen=True)
class SecurityFinding:
    """A single violation discovered by a check."""

    check_id: str
    test_name: str
    severity: Severity
    location: str
    finding: str
    remediation: str
    owasp: str
    iso27001: str
    nist: str


@dataclass
class CheckResult:
    """Result of running one security check."""

    check: SecurityCheck
    status: CheckStatus
    findings: List[SecurityFinding] = field(default_factory=list)
    notes: str = ""


@dataclass
class SecurityScanReport:
    """Aggregate report for the full scan run."""

    prompt: str
    project_root: Path
    check_results: List[CheckResult] = field(default_factory=list)

    @property
    def findings(self) -> List[SecurityFinding]:
        items: List[SecurityFinding] = []
        for result in self.check_results:
            items.extend(result.findings)
        return items

    @property
    def failed_checks(self) -> int:
        return sum(1 for result in self.check_results if result.status == CheckStatus.FAIL)

    @property
    def warning_checks(self) -> int:
        return sum(1 for result in self.check_results if result.status == CheckStatus.WARN)

    @property
    def passed(self) -> bool:
        return self.failed_checks == 0


@dataclass
class ScanContext:
    """Shared scan state passed to each check runner."""

    project_root: Path
    files: List[Path]

    def rel(self, path: Path) -> str:
        return path.relative_to(self.project_root).as_posix()

    def read_lines(self, path: Path) -> List[str]:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# SECTION 3: PATTERN LIBRARIES
# ---------------------------------------------------------------------------
# Regex and heuristics grouped by security theme. Patterns are intentionally
# conservative: they flag *potential* issues for human review.


SECRET_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    (
        "Possible hardcoded credential assignment",
        re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|auth)\s*=\s*['\"][^'\"]{8,}['\"]"),
    ),
    (
        "Possible AWS access key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "Possible private key material",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "Possible GitHub personal access token",
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    ),
)

INJECTION_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("Use of eval()", re.compile(r"\beval\s*\(")),
    ("Use of exec()", re.compile(r"\bexec\s*\(")),
    ("subprocess with shell=True", re.compile(r"shell\s*=\s*True")),
    (
        "Possible SQL string concatenation",
        re.compile(r"(?i)(select|insert|update|delete).*(%s|\+|\.format\(|f\").*from"),
    ),
    ("Use of os.system()", re.compile(r"\bos\.system\s*\(")),
    ("Use of pickle.loads()", re.compile(r"\bpickle\.loads\s*\(")),
)

LOGGING_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("Logging full HTTP response body", re.compile(r"response\.text\[:?\d*\]")),
    ("Logging raw request JSON payload", re.compile(r"json\.dumps\([^)]*body")),
    ("Logging authorization headers", re.compile(r"(?i)log.*authorization")),
)

CRYPTO_WEAK_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("MD5 used for security-sensitive purpose", re.compile(r"(?i)hashlib\.md5\s*\(")),
    ("SHA-1 used for security-sensitive purpose", re.compile(r"(?i)hashlib\.sha1\s*\(")),
    ("DES / 3DES cipher usage", re.compile(r"(?i)(DES3|TripleDES|DES\.new)")),
)


# ---------------------------------------------------------------------------
# SECTION 4: CHECK RUNNERS
# ---------------------------------------------------------------------------
# Each function implements one security test. Runners return PASS when no issue
# is found, FAIL/WARN when violations exist, or SKIP when not applicable.


def _should_ignore_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return True
    return any(marker in line for marker in IGNORE_LINE_MARKERS)


def _find_pattern_matches(
    context: ScanContext,
    check: SecurityCheck,
    patterns: Sequence[Tuple[str, re.Pattern[str]]],
    *,
    skip_self: bool = True,
) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    for file_path in context.files:
        rel_path = context.rel(file_path)
        if skip_self and rel_path.endswith(SELF_FILE_NAME):
            continue
        for line_no, line in enumerate(context.read_lines(file_path), start=1):
            if _should_ignore_line(line):
                continue
            for label, pattern in patterns:
                if pattern.search(line):
                    findings.append(
                        SecurityFinding(
                            check_id=check.check_id,
                            test_name=check.name,
                            severity=check.default_severity,
                            location=f"{rel_path}:{line_no}",
                            finding=label,
                            remediation=check.remediation,
                            owasp=check.owasp,
                            iso27001=check.iso27001,
                            nist=check.nist,
                        )
                    )
    return findings


def check_hardcoded_secrets(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A07:2021 Identification and Authentication Failures
    ISO 27001 A.8.28 / A.8.32 secure coding and secret handling
    NIST CSF PR.DS (Data Security)
    """
    findings = _find_pattern_matches(context, check, SECRET_PATTERNS)
    return _result_from_findings(check, findings)


def check_injection_and_dangerous_execution(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A03:2021 Injection
    ISO 27001 A.8.26 Application security requirements
    NIST CSF PR.PT (Protective Technology)
    """
    findings = _find_pattern_matches(context, check, INJECTION_PATTERNS)
    return _result_from_findings(check, findings)


def check_sensitive_logging(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A09:2021 Security Logging and Monitoring Failures
    ISO 27001 A.8.15 Logging
    NIST CSF DE.AE (Adverse Event Analysis)
    """
    findings = _find_pattern_matches(context, check, LOGGING_PATTERNS, skip_self=False)
    py_files = [path for path in context.files if path.suffix == ".py"]
    scoped = [item for item in findings if any(item.location.startswith(context.rel(p)) for p in py_files)]
    return _result_from_findings(check, scoped)


def check_weak_cryptography(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A02:2021 Cryptographic Failures
    ISO 27001 A.10.1.1 Cryptographic controls policy
    NIST CSF PR.DS-1 (Data-at-rest protection)
    """
    findings = _find_pattern_matches(context, check, CRYPTO_WEAK_PATTERNS)
    return _result_from_findings(check, findings)


def _is_scanner_file(rel_path: str) -> bool:
    return rel_path.endswith(SELF_FILE_NAME) or rel_path.endswith("security_scan.py")


def check_tls_verification_disabled(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A02:2021 Cryptographic Failures (transport security)
    ISO 27001 A.8.24 Use of cryptography
    NIST CSF PR.DS-2 (Data-in-transit protection)
    """
    findings: List[SecurityFinding] = []
    for file_path in context.files:
        rel_path = context.rel(file_path)
        if _is_scanner_file(rel_path):
            continue
        if file_path.suffix.lower() not in {".py", ".yaml", ".yml", ".ini", ".cfg"}:
            continue
        for line_no, line in enumerate(context.read_lines(file_path), start=1):
            if _should_ignore_line(line):
                continue
            normalized = line.replace(" ", "").lower()
            if "verify_ssl:false" in normalized or "verify=false" in normalized:
                findings.append(
                    _finding(
                        check,
                        f"{rel_path}:{line_no}",
                        "TLS certificate verification appears disabled",
                    )
                )
            if re.search(r"verify\s*=\s*False", line) and "requests" in context.read_text(file_path):
                findings.append(
                    _finding(
                        check,
                        f"{rel_path}:{line_no}",
                        "HTTP client may skip TLS certificate validation",
                    )
                )
    return _result_from_findings(check, findings)


def check_env_file_gitignore(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A02:2021 Cryptographic Failures / secret exposure
    ISO 27001 A.8.28 Secure coding (prevent secret leakage)
    NIST CSF PR.DS (Data Security)
    """
    gitignore = context.project_root / ".gitignore"
    env_file = context.project_root / ".env"
    if env_file.exists() and not _gitignore_contains(gitignore, ".env"):
        return CheckResult(
            check=check,
            status=CheckStatus.FAIL,
            findings=[
                _finding(
                    check,
                    ".gitignore",
                    ".env file exists but is not listed in .gitignore",
                )
            ],
        )
    if not gitignore.exists():
        return CheckResult(
            check=check,
            status=CheckStatus.WARN,
            notes="No .gitignore file found",
        )
    if not _gitignore_contains(gitignore, ".env"):
        return CheckResult(
            check=check,
            status=CheckStatus.WARN,
            findings=[
                _finding(check, ".gitignore", ".env is not ignored; local secrets may be committed"),
            ],
        )
    return CheckResult(check=check, status=CheckStatus.PASS)


def check_secrets_in_config(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A07:2021 Identification and Authentication Failures
    ISO 27001 A.8.32 Change management / configuration protection
    NIST CSF PR.AC (Identity Management and Access Control)
    """
    findings: List[SecurityFinding] = []
    auth_pattern = re.compile(r"(?i)^\s*(api[_-]?key|authorization|token|password|secret)\s*:\s*\S+")
    for config_dir_name in ("config", "configs", "settings"):
        config_dir = context.project_root / config_dir_name
        if not config_dir.is_dir():
            continue
        for path in config_dir.rglob("*"):
            if path.suffix.lower() not in {".yaml", ".yml", ".json", ".env", ".ini"}:
                continue
            for line_no, line in enumerate(context.read_lines(path), start=1):
                if "example" in line.lower() or "changeme" in line.lower():
                    continue
                if auth_pattern.search(line):
                    findings.append(
                        _finding(
                            check,
                            f"{context.rel(path)}:{line_no}",
                            "Credential-like value appears committed in configuration",
                        )
                    )
    return _result_from_findings(check, findings)


def check_path_traversal_config_loading(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A03:2021 Injection / path traversal
    ISO 27001 A.8.26 Application security requirements
    NIST CSF PR.PT-3 (Access permissions managed)
    """
    findings: List[SecurityFinding] = []
    risky_patterns = (
        re.compile(r"f[\"'].*\{.*env.*\}.*\.ya?ml"),
        re.compile(r"os\.getenv\([^)]+\).*/"),
        re.compile(r"Path\([^)]*\+"),
    )
    for file_path in context.files:
        if file_path.suffix != ".py":
            continue
        rel_path = context.rel(file_path)
        if _is_scanner_file(rel_path):
            continue
        content = context.read_text(file_path)
        if "env_name" in content and '.yaml"' in content and "allowlist" not in content.lower():
            findings.append(
                _finding(
                    check,
                    rel_path,
                    "Environment name influences config file path without documented allowlist",
                )
            )
        for line_no, line in enumerate(context.read_lines(file_path), start=1):
            if _should_ignore_line(line):
                continue
            for pattern in risky_patterns:
                if pattern.search(line):
                    findings.append(
                        _finding(
                            check,
                            f"{rel_path}:{line_no}",
                            "Potential path traversal via dynamic file path construction",
                        )
                    )
    return _result_from_findings(check, findings, warn_only=True)


def check_unverified_remote_downloads(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A06:2021 Vulnerable and Outdated Components / supply chain
    ISO 27001 A.8.31 Separation of development, test, and production
    NIST CSF ID.SC (Supply Chain Risk Management)
    """
    findings: List[SecurityFinding] = []
    for file_path in context.files:
        if file_path.suffix not in {".sh", ".bash", ".py"}:
            continue
        rel_path = context.rel(file_path)
        if _is_scanner_file(rel_path):
            continue
        content = context.read_text(file_path)
        if re.search(r"\bcurl\b.*-L?", content) and "sha256" not in content.lower():
            if re.search(r"https?://", content):
                findings.append(
                    _finding(
                        check,
                        rel_path,
                        "Remote artifact downloaded without checksum/signature verification",
                    )
                )
        if "urllib.request.urlretrieve" in content and "hashlib" not in content:
            findings.append(
                _finding(
                    check,
                    rel_path,
                    "urlretrieve used without integrity validation",
                )
            )
    return _result_from_findings(check, findings, warn_only=True)


def check_ssrf_url_patterns(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A10:2021 Server-Side Request Forgery (SSRF)
    ISO 27001 A.8.26 Application security requirements
    NIST CSF PR.PT (Protective Technology)
    """
    findings: List[SecurityFinding] = []
    for file_path in context.files:
        if file_path.suffix != ".py":
            continue
        rel_path = context.rel(file_path)
        if _is_scanner_file(rel_path):
            continue
        content = context.read_text(file_path)
        if 'startswith("http' in content or "startswith('http" in content:
            findings.append(
                _finding(
                    check,
                    rel_path,
                    "Absolute URLs accepted in request paths; validate against allowlist",
                )
            )
        for line_no, line in enumerate(context.read_lines(file_path), start=1):
            if re.search(r"requests\.(get|post|put|delete)\(\s*[^'\"/\s]", line):
                findings.append(
                    _finding(
                        check,
                        f"{rel_path}:{line_no}",
                        "HTTP request URL may be fully user-controlled (SSRF risk)",
                    )
                )
    return _result_from_findings(check, findings, warn_only=True)


def check_error_handling(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A09:2021 Security Logging and Monitoring Failures
    ISO 27001 A.8.15 Logging / A.8.16 Monitoring
    NIST CSF DE.CM (Continuous Monitoring)
    """
    findings: List[SecurityFinding] = []
    bare_except = re.compile(r"^\s*except\s*:\s*(pass|$)")
    for file_path in context.files:
        if file_path.suffix != ".py":
            continue
        rel_path = context.rel(file_path)
        for line_no, line in enumerate(context.read_lines(file_path), start=1):
            if bare_except.search(line):
                findings.append(
                    _finding(
                        check,
                        f"{rel_path}:{line_no}",
                        "Bare except clause may hide security-relevant failures",
                    )
                )
    return _result_from_findings(check, findings, warn_only=True)


def check_dependency_hygiene(context: ScanContext, check: SecurityCheck) -> CheckResult:
    """
    OWASP A06:2021 Vulnerable and Outdated Components
    ISO 27001 A.8.31 Separation of environments / secure SDLC
    NIST CSF ID.RA (Risk Assessment)
    """
    req_file = context.project_root / "requirements.txt"
    if not req_file.exists():
        return CheckResult(check=check, status=CheckStatus.SKIP, notes="requirements.txt not found")

    findings: List[SecurityFinding] = []
    for line_no, line in enumerate(context.read_lines(req_file), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-") or "://" in stripped:
            continue
        if "==" not in stripped and ">=" not in stripped and "~=" not in stripped:
            findings.append(
                _finding(
                    check,
                    f"requirements.txt:{line_no}",
                    f"Dependency '{stripped}' is unpinned; supply-chain drift risk",
                )
            )
    return _result_from_findings(check, findings, warn_only=True)


# ---------------------------------------------------------------------------
# SECTION 5: CHECK CATALOG
# ---------------------------------------------------------------------------
# Central registry of all tests. Add new checks here to extend coverage.


SECURITY_CHECKS: List[SecurityCheck] = [
    SecurityCheck(
        check_id="SEC-001",
        name="Hardcoded Secrets Detection",
        description="Detects API keys, tokens, passwords, and private key material in source files.",
        owasp="A07:2021 Identification and Authentication Failures",
        iso27001="A.8.28 Secure coding / A.8.32 Change control",
        nist="PR.DS - Data Security",
        default_severity=Severity.HIGH,
        remediation=(
            "Move secrets to environment variables or a secrets manager "
            "(AWS Secrets Manager, Azure Key Vault, HashiCorp Vault). Rotate exposed credentials."
        ),
        runner=check_hardcoded_secrets,
    ),
    SecurityCheck(
        check_id="SEC-002",
        name="Injection and Dangerous Execution",
        description="Detects eval/exec, shell injection, unsafe SQL construction, and unsafe deserialization.",
        owasp="A03:2021 Injection",
        iso27001="A.8.26 Application security requirements",
        nist="PR.PT - Protective Technology",
        default_severity=Severity.HIGH,
        remediation=(
            "Use parameterized queries/ORMs, avoid shell=True, replace eval/exec with safe parsers, "
            "and validate all external input against allowlists."
        ),
        runner=check_injection_and_dangerous_execution,
    ),
    SecurityCheck(
        check_id="SEC-003",
        name="Sensitive Data in Logs",
        description="Detects logging patterns that may expose credentials, tokens, or full payloads.",
        owasp="A09:2021 Security Logging and Monitoring Failures",
        iso27001="A.8.15 Logging",
        nist="DE.AE - Adverse Event Analysis",
        default_severity=Severity.MEDIUM,
        remediation=(
            "Redact sensitive fields before logging (Authorization, password, token, api_key). "
            "Log metadata (status, latency) instead of full bodies in production."
        ),
        runner=check_sensitive_logging,
    ),
    SecurityCheck(
        check_id="SEC-004",
        name="Weak Cryptography",
        description="Detects MD5/SHA-1/DES usage that is inappropriate for security controls.",
        owasp="A02:2021 Cryptographic Failures",
        iso27001="A.10.1.1 Cryptographic controls",
        nist="PR.DS-1 - Data-at-rest protections",
        default_severity=Severity.MEDIUM,
        remediation=(
            "Use modern algorithms: AES-256-GCM, ChaCha20-Poly1305, bcrypt/scrypt/Argon2 for passwords, "
            "SHA-256+ for integrity where appropriate."
        ),
        runner=check_weak_cryptography,
    ),
    SecurityCheck(
        check_id="SEC-005",
        name="TLS Verification Disabled",
        description="Detects HTTP clients or configs that disable certificate validation.",
        owasp="A02:2021 Cryptographic Failures",
        iso27001="A.8.24 Use of cryptography",
        nist="PR.DS-2 - Data-in-transit protections",
        default_severity=Severity.MEDIUM,
        remediation=(
            "Keep verify=True/verify_ssl=true in production. Use enterprise trust stores or pinned certs "
            "instead of disabling TLS validation."
        ),
        runner=check_tls_verification_disabled,
    ),
    SecurityCheck(
        check_id="SEC-006",
        name=".env Gitignore Protection",
        description="Ensures local environment files containing secrets are excluded from version control.",
        owasp="A02:2021 Cryptographic Failures",
        iso27001="A.8.28 Secure coding",
        nist="PR.DS - Data Security",
        default_severity=Severity.HIGH,
        remediation="Add `.env` to `.gitignore`, provide `.env.example` with placeholders, and scan git history for leaks.",
        runner=check_env_file_gitignore,
    ),
    SecurityCheck(
        check_id="SEC-007",
        name="Secrets in Committed Configuration",
        description="Detects credential-like entries in YAML/JSON/INI configuration committed to the repo.",
        owasp="A07:2021 Identification and Authentication Failures",
        iso27001="A.8.32 Change control / configuration management",
        nist="PR.AC - Access Control",
        default_severity=Severity.MEDIUM,
        remediation=(
            "Store credentials in secret stores or CI variables. Keep config files limited to non-secret settings."
        ),
        runner=check_secrets_in_config,
    ),
    SecurityCheck(
        check_id="SEC-008",
        name="Path Traversal in Config Loading",
        description="Detects dynamic file path construction that may allow directory traversal.",
        owasp="A03:2021 Injection",
        iso27001="A.8.26 Application security requirements",
        nist="PR.PT-3 - Access permissions managed",
        default_severity=Severity.LOW,
        remediation=(
            "Allowlist environment names (dev/staging/prod) and resolve paths with Path.resolve() "
            "under a trusted base directory."
        ),
        runner=check_path_traversal_config_loading,
    ),
    SecurityCheck(
        check_id="SEC-009",
        name="Unverified Remote Downloads",
        description="Detects curl/urlretrieve downloads without integrity verification.",
        owasp="A06:2021 Vulnerable and Outdated Components",
        iso27001="A.8.31 Separation of development/test/production",
        nist="ID.SC - Supply Chain Risk Management",
        default_severity=Severity.LOW,
        remediation=(
            "Vendor remote artifacts in-repo or verify SHA-256 checksum/signature before use. "
            "Prefer package managers with lock files."
        ),
        runner=check_unverified_remote_downloads,
    ),
    SecurityCheck(
        check_id="SEC-010",
        name="SSRF URL Handling",
        description="Detects patterns where outbound HTTP URLs may be attacker-controlled.",
        owasp="A10:2021 Server-Side Request Forgery (SSRF)",
        iso27001="A.8.26 Application security requirements",
        nist="PR.PT - Protective Technology",
        default_severity=Severity.LOW,
        remediation=(
            "Validate outbound URLs against an allowlist of hosts/schemes, block metadata endpoints, "
            "and avoid passing raw user input to HTTP clients."
        ),
        runner=check_ssrf_url_patterns,
    ),
    SecurityCheck(
        check_id="SEC-011",
        name="Unsafe Error Handling",
        description="Detects bare except blocks that can hide security failures.",
        owasp="A09:2021 Security Logging and Monitoring Failures",
        iso27001="A.8.15 Logging / A.8.16 Monitoring activities",
        nist="DE.CM - Continuous Monitoring",
        default_severity=Severity.LOW,
        remediation=(
            "Catch specific exceptions, log sanitized errors server-side, and return generic messages to users."
        ),
        runner=check_error_handling,
    ),
    SecurityCheck(
        check_id="SEC-012",
        name="Dependency Pinning Hygiene",
        description="Checks requirements.txt for unpinned dependencies that increase supply-chain risk.",
        owasp="A06:2021 Vulnerable and Outdated Components",
        iso27001="A.8.31 Secure SDLC / environment separation",
        nist="ID.RA - Risk Assessment",
        default_severity=Severity.LOW,
        remediation=(
            "Pin dependencies with == or compatible ranges plus lock files. Monitor CVEs with pip-audit or Dependabot."
        ),
        runner=check_dependency_hygiene,
    ),
]


# ---------------------------------------------------------------------------
# SECTION 6: SCAN ORCHESTRATION
# ---------------------------------------------------------------------------


def scan_project_for_security_concerns(
    project_root: Optional[Path] = None,
    *,
    prompt: str = DEFAULT_PROMPT,
    checks: Optional[Sequence[SecurityCheck]] = None,
) -> SecurityScanReport:
    """
    Run all registered security checks against a project directory.

    This is the primary API entry point and matches the default user prompt:
    "Scan this project for security concerns".
    """
    root = (project_root or DEFAULT_PROJECT_ROOT).resolve()
    context = ScanContext(project_root=root, files=list(_iter_scan_files(root)))
    report = SecurityScanReport(prompt=prompt, project_root=root)

    for check in checks or SECURITY_CHECKS:
        try:
            result = check.runner(context, check)
        except OSError as exc:
            result = CheckResult(
                check=check,
                status=CheckStatus.SKIP,
                notes=f"Check skipped due to filesystem error: {exc}",
            )
        report.check_results.append(result)

    return report


def print_security_scan_report(report: SecurityScanReport) -> None:
    """Render a human-readable report that calls out each test and remediation."""
    print("=" * 78)
    print(f"Security Scan: {report.prompt}")
    print(f"Project Root:  {report.project_root}")
    print(f"Standards:     OWASP Top 10 | ISO/IEC 27001 Annex A | NIST CSF")
    print("=" * 78)
    print()

    for result in report.check_results:
        check = result.check
        print(f"[RUN] {check.check_id} {check.name} -> {result.status.value}")
        print(f"      Description : {check.description}")
        print(f"      OWASP       : {check.owasp}")
        print(f"      ISO 27001   : {check.iso27001}")
        print(f"      NIST CSF    : {check.nist}")

        if result.notes:
            print(f"      Notes       : {result.notes}")

        if result.findings:
            print("      Findings    :")
            for finding in result.findings:
                print(f"        - [{finding.severity.value}] {finding.location}")
                print(f"          Issue       : {finding.finding}")
                print(f"          Remediation : {finding.remediation}")
        elif result.status == CheckStatus.PASS:
            print("      Result      : No violations detected for this test.")
        print()

    print("-" * 78)
    print("SUMMARY")
    print("-" * 78)
    total = len(report.check_results)
    passed = sum(1 for item in report.check_results if item.status == CheckStatus.PASS)
    failed = report.failed_checks
    warned = report.warning_checks
    skipped = sum(1 for item in report.check_results if item.status == CheckStatus.SKIP)

    print(f"Checks executed : {total}")
    print(f"Passed          : {passed}")
    print(f"Failed          : {failed}")
    print(f"Warnings        : {warned}")
    print(f"Skipped         : {skipped}")
    print(f"Total findings  : {len(report.findings)}")
    print()

    if not report.findings and failed == 0:
        print("Overall Result  : PASS")
    elif failed == 0:
        print("Overall Result  : PASS WITH WARNINGS")
    else:
        print("Overall Result  : FAIL")

    if report.findings:
        print()
        print("| Severity | Test | Location | Finding | Remediation |")
        print("|----------|------|----------|---------|-------------|")
        for finding in sorted(report.findings, key=_severity_rank):
            remediation = finding.remediation.replace("|", "/")
            print(
                f"| {finding.severity.value} | {finding.test_name} | {finding.location} | "
                f"{finding.finding} | {remediation} |"
            )


def report_to_json(report: SecurityScanReport) -> str:
    """Serialize the report for CI pipelines or dashboards."""

    payload = {
        "prompt": report.prompt,
        "project_root": str(report.project_root),
        "passed": report.passed,
        "summary": {
            "checks_executed": len(report.check_results),
            "failed_checks": report.failed_checks,
            "warning_checks": report.warning_checks,
            "total_findings": len(report.findings),
        },
        "checks": [
            {
                "check_id": result.check.check_id,
                "name": result.check.name,
                "status": result.status.value,
                "owasp": result.check.owasp,
                "iso27001": result.check.iso27001,
                "nist": result.check.nist,
                "notes": result.notes,
                "findings": [asdict(finding) for finding in result.findings],
            }
            for result in report.check_results
        ],
    }
    return json.dumps(payload, indent=2, default=lambda obj: obj.value if isinstance(obj, Enum) else str(obj))


def _overall_result_label(report: SecurityScanReport) -> str:
    if not report.findings and report.failed_checks == 0:
        return "PASS"
    if report.failed_checks == 0:
        return "PASS WITH WARNINGS"
    return "FAIL"


def report_to_markdown(report: SecurityScanReport) -> str:
    """Render the scan report as Markdown for Cursor's Preview tab."""
    lines = [
        "# Security Scan Report",
        "",
        f"**Prompt:** {report.prompt}  ",
        f"**Project:** `{report.project_root}`  ",
        f"**Overall result:** {_overall_result_label(report)}  ",
        f"**Standards:** OWASP Top 10 | ISO/IEC 27001 Annex A | NIST CSF",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|------:|",
        f"| Checks executed | {len(report.check_results)} |",
        f"| Passed | {sum(1 for item in report.check_results if item.status == CheckStatus.PASS)} |",
        f"| Failed | {report.failed_checks} |",
        f"| Warnings | {report.warning_checks} |",
        f"| Skipped | {sum(1 for item in report.check_results if item.status == CheckStatus.SKIP)} |",
        f"| Total findings | {len(report.findings)} |",
        "",
        "## Checks Run",
        "",
    ]

    for result in report.check_results:
        check = result.check
        lines.extend(
            [
                f"### {check.check_id} {check.name} — **{result.status.value}**",
                "",
                check.description,
                "",
                f"- **OWASP:** {check.owasp}",
                f"- **ISO 27001:** {check.iso27001}",
                f"- **NIST CSF:** {check.nist}",
                f"- **Default remediation:** {check.remediation}",
                "",
            ]
        )
        if result.notes:
            lines.extend([f"*Notes:* {result.notes}", ""])
        if result.findings:
            lines.extend(
                [
                    "| Severity | Location | Finding | Remediation |",
                    "|----------|----------|---------|-------------|",
                ]
            )
            for finding in result.findings:
                finding_text = finding.finding.replace("|", "/")
                remediation = finding.remediation.replace("|", "/")
                lines.append(
                    f"| {finding.severity.value} | `{finding.location}` | {finding_text} | {remediation} |"
                )
            lines.append("")
        else:
            lines.extend(["No violations detected for this test.", ""])

    if report.findings:
        lines.extend(["## All Findings (by severity)", ""])
        for finding in sorted(report.findings, key=_severity_rank):
            lines.extend(
                [
                    f"### [{finding.severity.value}] {finding.test_name}",
                    "",
                    f"- **Location:** `{finding.location}`",
                    f"- **Issue:** {finding.finding}",
                    f"- **Remediation:** {finding.remediation}",
                    "",
                ]
            )

    lines.extend(
        [
            "---",
            "",
            "Regenerate this report:",
            "",
            "```bash",
            "./run_security_scan.sh --write-preview",
            "```",
            "",
            "Static documentation: `security_scan.preview.md`",
        ]
    )
    return "\n".join(lines)


def report_to_html(report: SecurityScanReport) -> str:
    """Render the scan report as HTML for browser preview."""
    rows = []
    for result in report.check_results:
        check = result.check
        finding_items = "".join(
            (
                f"<li><strong>{finding.severity.value}</strong> "
                f"<code>{finding.location}</code> — {finding.finding}"
                f"<br><em>Fix:</em> {finding.remediation}</li>"
            )
            for finding in result.findings
        )
        if not finding_items:
            finding_items = "<li>No violations detected.</li>"
        rows.append(
            "<section>"
            f"<h3>{check.check_id} {check.name} — {result.status.value}</h3>"
            f"<p>{check.description}</p>"
            f"<ul><li>OWASP: {check.owasp}</li>"
            f"<li>ISO 27001: {check.iso27001}</li>"
            f"<li>NIST: {check.nist}</li></ul>"
            f"<ul>{finding_items}</ul>"
            "</section>"
        )

    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Security Scan Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;"
        "line-height:1.5}code{background:#f4f4f4;padding:0.1rem 0.3rem}"
        "section{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}</style>"
        "</head><body>"
        f"<h1>Security Scan Report</h1>"
        f"<p><strong>Project:</strong> <code>{report.project_root}</code></p>"
        f"<p><strong>Overall:</strong> {_overall_result_label(report)}</p>"
        f"{''.join(rows)}"
        "</body></html>"
    )


def write_preview_report(
    report: SecurityScanReport,
    output_path: Optional[Path] = None,
) -> Path:
    """Write Markdown preview report beside security_scan.py for Cursor Preview tab."""
    path = (output_path or PREVIEW_REPORT_PATH).resolve()
    path.write_text(report_to_markdown(report), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# SECTION 7: HELPERS
# ---------------------------------------------------------------------------


def _result_from_findings(
    check: SecurityCheck,
    findings: List[SecurityFinding],
    *,
    warn_only: bool = False,
) -> CheckResult:
    if not findings:
        return CheckResult(check=check, status=CheckStatus.PASS)
    status = CheckStatus.WARN if warn_only or check.default_severity == Severity.LOW else CheckStatus.FAIL
    if check.default_severity in {Severity.HIGH, Severity.MEDIUM} and not warn_only:
        status = CheckStatus.FAIL
    return CheckResult(check=check, status=status, findings=findings)


def _finding(check: SecurityCheck, location: str, message: str) -> SecurityFinding:
    return SecurityFinding(
        check_id=check.check_id,
        test_name=check.name,
        severity=check.default_severity,
        location=location,
        finding=message,
        remediation=check.remediation,
        owasp=check.owasp,
        iso27001=check.iso27001,
        nist=check.nist,
    )


def _severity_rank(finding: SecurityFinding) -> Tuple[int, str]:
    order = {
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 1,
        Severity.LOW.value: 2,
        Severity.INFO.value: 3,
    }
    return (order.get(finding.severity.value, 4), finding.location)


def _iter_scan_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS and path.name not in {".env", ".env.example"}:
            continue
        yield path


def _gitignore_contains(gitignore_path: Path, entry: str) -> bool:
    if not gitignore_path.is_file():
        return False
    return any(line.strip() == entry for line in gitignore_path.read_text(encoding="utf-8").splitlines())


# ---------------------------------------------------------------------------
# SECTION 8: CLI ENTRY POINT
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=DEFAULT_PROMPT,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=DEFAULT_PROJECT_ROOT,
        help="Root directory of the project to scan",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "html"),
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write markdown/html report to this file instead of stdout",
    )
    parser.add_argument(
        "--write-preview",
        action="store_true",
        help="Write api_tests/security_scan.report.md for Cursor Markdown Preview",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    report = scan_project_for_security_concerns(args.project_root)

    if args.write_preview:
        preview_path = write_preview_report(report)
        print(f"Preview report written to: {preview_path}")
        print("Open it in Cursor and use the Preview tab (Preview | Markdown).")

    if args.format == "json":
        output = report_to_json(report)
    elif args.format == "markdown":
        output = report_to_markdown(report)
    elif args.format == "html":
        output = report_to_html(report)
    else:
        print_security_scan_report(report)
        return 0 if report.passed else 1

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Report written to: {args.output.resolve()}")
    else:
        print(output)

    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
