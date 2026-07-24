"""Static security scanner for the API test project."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROMPT = "Scan this project for security concerns"

SCAN_EXTENSIONS = {".py", ".yaml", ".yml", ".sh", ".env", ".example"}
SKIP_DIRS = {".git", ".venv", "venv", ".pytest_cache", "__pycache__", "htmlcov", "dist", "build"}

SECRET_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("possible hardcoded secret", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]")),
    ("possible AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("possible private key header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

DANGEROUS_CODE_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("eval() usage", re.compile(r"\beval\s*\(")),
    ("exec() usage", re.compile(r"\bexec\s*\(")),
    ("shell=True in subprocess", re.compile(r"shell\s*=\s*True")),
)

SENSITIVE_LOG_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("logs full response body", re.compile(r"response\.text\[:?\d*\]")),
    ("logs request json payload", re.compile(r"json\.dumps\(json_body")),
)


@dataclass(frozen=True)
class SecurityFinding:
    severity: str
    location: str
    finding: str


@dataclass
class SecurityScanReport:
    prompt: str = DEFAULT_PROMPT
    findings: List[SecurityFinding] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for item in self.findings if item.severity.lower() in {"high", "medium"})

    @property
    def warnings(self) -> int:
        return sum(1 for item in self.findings if item.severity.lower() == "low")

    @property
    def passed(self) -> bool:
        return self.failed == 0


def scan_project_for_security_concerns(
    project_root: Optional[Path] = None,
    *,
    prompt: str = DEFAULT_PROMPT,
) -> SecurityScanReport:
    """Scan this project for security concerns."""
    root = (project_root or PROJECT_ROOT).resolve()
    report = SecurityScanReport(prompt=prompt)

    for file_path in _iter_scan_files(root):
        rel_path = file_path.relative_to(root).as_posix()
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        _scan_patterns(report, rel_path, lines, SECRET_PATTERNS, "High")
        if rel_path != "api_tests/security_scan.py":
            _scan_patterns(report, rel_path, lines, DANGEROUS_CODE_PATTERNS, "High")

        if rel_path == "api_tests/http_client.py":
            _scan_patterns(report, rel_path, lines, SENSITIVE_LOG_PATTERNS, "Medium")

        if rel_path.startswith("config/") and "verify_ssl: false" in content.lower():
            report.findings.append(
                SecurityFinding("Medium", rel_path, "TLS certificate verification is disabled")
            )

        if rel_path == "api_tests/config.py" and 'f"{env_name}.yaml"' in content:
            report.findings.append(
                SecurityFinding(
                    "Low",
                    rel_path,
                    "Environment name is used in a file path; restrict API_ENV to an allowlist",
                )
            )

        if rel_path == "api_tests/http_client.py" and "startswith(\"http" in content:
            report.findings.append(
                SecurityFinding(
                    "Low",
                    rel_path,
                    "Absolute URLs are accepted in request paths; restrict API_BASE_URL in shared environments",
                )
            )

        if rel_path == "run_tests.sh" and "curl -sL" in content and "swagger.json" in content:
            report.findings.append(
                SecurityFinding(
                    "Low",
                    rel_path,
                    "Swagger spec is downloaded without checksum verification",
                )
            )

    if not _gitignore_contains(root / ".gitignore", ".env"):
        report.findings.append(
            SecurityFinding("High", ".gitignore", ".env is not ignored; secrets may be committed")
        )

    if _file_contains_secret_like_values(root / "config"):
        report.findings.append(
            SecurityFinding("Medium", "config/", "Auth credentials appear to be stored in committed config files")
        )

    return report


def print_security_scan_report(report: SecurityScanReport) -> None:
    """Print a pass/fail security scan report."""
    print(f"Security scan: {report.prompt}")
    print(f"Project: {PROJECT_ROOT}")
    print("")

    if not report.findings:
        print("Result: PASS")
        print("Security review found no issues.")
        return

    print("| Severity | Location | Finding |")
    print("|----------|----------|---------|")
    for item in sorted(report.findings, key=_severity_rank):
        print(f"| {item.severity} | {item.location} | {item.finding} |")

    print("")
    if report.passed:
        print(f"Result: PASS WITH WARNINGS ({report.warnings} low-severity finding(s))")
    else:
        print(f"Result: FAIL ({report.failed} high/medium finding(s), {report.warnings} low)")


def _severity_rank(finding: SecurityFinding) -> Tuple[int, str]:
    order = {"high": 0, "medium": 1, "low": 2}
    return (order.get(finding.severity.lower(), 3), finding.location)


def _iter_scan_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS and path.name not in {".env", ".env.example"}:
            continue
        yield path


def _scan_patterns(
    report: SecurityScanReport,
    rel_path: str,
    lines: Sequence[str],
    patterns: Sequence[Tuple[str, re.Pattern[str]]],
    severity: str,
) -> None:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or "example.com" in stripped or "test-password" in stripped:
            continue
        for label, pattern in patterns:
            if pattern.search(line):
                report.findings.append(
                    SecurityFinding(severity, f"{rel_path}:{line_number}", label)
                )


def _gitignore_contains(gitignore_path: Path, entry: str) -> bool:
    if not gitignore_path.is_file():
        return False
    return any(line.strip() == entry for line in gitignore_path.read_text(encoding="utf-8").splitlines())


def _file_contains_secret_like_values(config_dir: Path) -> bool:
    if not config_dir.is_dir():
        return False
    auth_pattern = re.compile(r"(?i)^\s*(api[_-]?key|authorization|token|password)\s*:")
    for path in config_dir.glob("*.yaml"):
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if auth_pattern.search(line) and "example" not in line.lower():
                return True
    return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=DEFAULT_PROMPT)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Project root to scan (defaults to repository root)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    report = scan_project_for_security_concerns(args.project_root)
    print_security_scan_report(report)
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
