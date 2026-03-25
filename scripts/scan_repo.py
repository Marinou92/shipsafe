#!/usr/bin/env python3
"""
ShipSafe Lite scanner.

The free edition covers secrets, config hygiene, and a small set of
production-safety checks. It does not review auth logic or apply fixes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".vercel",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
}

TEXT_EXTENSIONS = {
    ".cjs",
    ".conf",
    ".css",
    ".env",
    ".example",
    ".html",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".py",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

SECRET_PATTERNS = [
    ("openai-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("stripe-key", re.compile(r"rk_live_[A-Za-z0-9]+|sk_live_[A-Za-z0-9]+")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z\\-_]{35}")),
]

GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key|
        auth[_-]?token|
        bearer|
        client[_-]?secret|
        db[_-]?password|
        password|
        private[_-]?key|
        secret|
        token
    )\b
    \s*[:=]\s*
    ["'][^"'\n]{8,}["']
    """
)

NEXT_PUBLIC_SECRET = re.compile(
    r"\bNEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE|SERVICE_ROLE|API_KEY)[A-Z0-9_]*\b"
)
NEXT_PUBLIC_RUNTIME_USAGE = re.compile(
    r"""
    (
        process\.env\.NEXT_PUBLIC_[A-Z0-9_]+
        |
        import\.meta\.env\.NEXT_PUBLIC_[A-Z0-9_]+
        |
        NEXT_PUBLIC_[A-Z0-9_]+\s*=
        |
        ["']NEXT_PUBLIC_[A-Z0-9_]+["']
    )
    """,
    re.VERBOSE,
)

CORS_WILDCARD_PATTERNS = [
    re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]"),
    re.compile(r"origin\s*:\s*['\"]\*['\"]"),
]

SELECT_STAR = re.compile(r"\bselect\s*\(\s*['\"]\*['\"]\s*\)")
CONSOLE_LOG = re.compile(r"\bconsole\.(log|debug|info)\s*\(")
SOURCE_MAP_CONFIG_PATTERNS = [
    re.compile(r"productionBrowserSourceMaps\s*:\s*true"),
    re.compile(r"\bsourcemap\s*:\s*true\b"),
    re.compile(r"\bdevtool\s*:\s*['\"]source-map['\"]"),
]

PLACEHOLDER_HINTS = ("example", "placeholder", "dummy", "sample", "changeme", "test")


@dataclass
class Finding:
    check_id: str
    severity: str
    category: str
    path: str
    line: int | None
    message: str
    fix: str


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    return path.name.startswith(".env")


def iter_files(root: Path, excluded: set[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [name for name in dirnames if name not in excluded]
        for filename in filenames:
            path = current / filename
            if any(part in excluded for part in path.relative_to(root).parts):
                continue
            if is_text_file(path):
                yield path


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def find_line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def merge_dependencies(package_data: dict | None) -> dict[str, str]:
    if not package_data:
        return {}
    deps: dict[str, str] = {}
    deps.update(package_data.get("dependencies", {}))
    deps.update(package_data.get("devDependencies", {}))
    return deps


def detect_next_project(package_data: dict | None) -> bool:
    return package_data is not None and "next" in json.dumps(package_data)


def detect_express_project(package_data: dict | None) -> bool:
    return package_data is not None and "express" in json.dumps(package_data)


def next_security_headers_present(root: Path) -> bool:
    next_config_files = [
        root / "next.config.js",
        root / "next.config.mjs",
        root / "next.config.ts",
    ]
    for config in next_config_files:
        if not config.exists():
            continue
        text = read_text(config) or ""
        if "headers()" in text or "Content-Security-Policy" in text:
            return True

    return any(
        path.exists()
        for path in (
            root / "middleware.ts",
            root / "middleware.js",
            root / "src" / "middleware.ts",
            root / "src" / "middleware.js",
        )
    )


def express_security_headers_present(root: Path, excluded: set[str], package_data: dict | None) -> bool:
    deps = merge_dependencies(package_data)
    if "helmet" in deps:
        return True
    for path in iter_files(root, excluded):
        text = read_text(path) or ""
        if "helmet(" in text or "Content-Security-Policy" in text or "X-Frame-Options" in text:
            return True
    return False


def scan_gitignore(root: Path, findings: list[Finding]) -> None:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        findings.append(
            Finding(
                check_id="gitignore-missing",
                severity="warning",
                category="config",
                path=".gitignore",
                line=None,
                message="No root .gitignore found.",
                fix="Create a root .gitignore that excludes .env files and build artifacts.",
            )
        )
        return

    contents = gitignore.read_text(encoding="utf-8")
    if ".env" not in contents and ".env.*" not in contents:
        findings.append(
            Finding(
                check_id="gitignore-env",
                severity="critical",
                category="config",
                path=".gitignore",
                line=None,
                message=".env patterns are missing from .gitignore.",
                fix="Add `.env` and `.env.*` to .gitignore while keeping `.env.example` committed.",
            )
        )


def scan_env_example(root: Path, findings: list[Finding]) -> None:
    env_files = [path for path in root.iterdir() if path.is_file() and path.name.startswith(".env")]
    has_real_env = any(path.name not in {".env.example"} for path in env_files)
    if has_real_env and not (root / ".env.example").exists():
        findings.append(
            Finding(
                check_id="env-example-missing",
                severity="warning",
                category="config",
                path=".env.example",
                line=None,
                message="Environment files exist but no .env.example was found.",
                fix="Commit a .env.example file with placeholder variable names and safe sample values.",
            )
        )


def scan_security_headers(root: Path, excluded: set[str], package_data: dict | None, findings: list[Finding]) -> None:
    if detect_next_project(package_data) and not next_security_headers_present(root):
        findings.append(
            Finding(
                check_id="security-headers-missing",
                severity="warning",
                category="security",
                path="next.config.*",
                line=None,
                message="No evidence of security headers configuration was found.",
                fix="Add CSP, X-Frame-Options, Referrer-Policy, and X-Content-Type-Options before shipping.",
            )
        )
        return

    if detect_express_project(package_data) and not express_security_headers_present(root, excluded, package_data):
        findings.append(
            Finding(
                check_id="security-headers-missing",
                severity="warning",
                category="security",
                path="server",
                line=None,
                message="No obvious security headers middleware was found.",
                fix="Add security headers such as CSP, X-Frame-Options, and X-Content-Type-Options.",
            )
        )


def scan_source_maps(root: Path, findings: list[Finding]) -> None:
    for path in root.rglob("*.map"):
        if any(part in DEFAULT_EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        findings.append(
            Finding(
                check_id="source-map-exposed",
                severity="warning",
                category="security",
                path=str(path.relative_to(root)),
                line=None,
                message="A source map file is present and may expose source code in production artifacts.",
                fix="Avoid shipping production source maps publicly unless they are explicitly protected.",
            )
        )


def should_skip_regex_line(path: Path, line: str) -> bool:
    return path.name == "scan_repo.py" and ("re.compile(" in line or "NEXT_PUBLIC_RUNTIME_USAGE" in line)


def scan_file(path: Path, root: Path, findings: list[Finding]) -> None:
    text = read_text(path)
    if text is None:
        return

    relative_path = str(path.relative_to(root))
    lines = text.splitlines()

    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line_number = find_line_number(text, match.start())
            line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
            if should_skip_regex_line(path, line):
                continue
            snippet = match.group(0)
            if looks_placeholder(snippet):
                continue
            findings.append(
                Finding(
                    check_id=f"secret-{name}",
                    severity="critical",
                    category="secrets",
                    path=relative_path,
                    line=line_number,
                    message=f"Hardcoded credential-like value matched `{name}`.",
                    fix="Move the secret to an environment variable or secret manager and rotate the exposed value.",
                )
            )

    for match in GENERIC_SECRET_ASSIGNMENT.finditer(text):
        line_number = find_line_number(text, match.start())
        line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
        if should_skip_regex_line(path, line):
            continue
        snippet = match.group(0)
        if "process.env" in snippet or "import.meta.env" in snippet or looks_placeholder(snippet):
            continue
        findings.append(
            Finding(
                check_id="secret-generic-assignment",
                severity="critical",
                category="secrets",
                path=relative_path,
                line=line_number,
                message="Potential hardcoded password, token, or API key assignment.",
                fix="Replace the inline value with an environment variable and rotate the credential if it was ever committed.",
            )
        )

    for index, line in enumerate(lines, start=1):
        if NEXT_PUBLIC_SECRET.search(line) and NEXT_PUBLIC_RUNTIME_USAGE.search(line) and not should_skip_regex_line(path, line):
            findings.append(
                Finding(
                    check_id="next-public-secret",
                    severity="critical",
                    category="secrets",
                    path=relative_path,
                    line=index,
                    message="A secret-like environment variable is exposed with the NEXT_PUBLIC_ prefix.",
                    fix="Rename it to a server-only variable and remove the client-side exposure.",
                )
            )

    for pattern in CORS_WILDCARD_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    check_id="cors-wildcard",
                    severity="warning",
                    category="security",
                    path=relative_path,
                    line=find_line_number(text, match.start()),
                    message="Wildcard CORS configuration detected.",
                    fix="Restrict allowed origins to the domains that actually need access.",
                )
            )

    for match in CONSOLE_LOG.finditer(text):
        findings.append(
            Finding(
                check_id="console-log",
                severity="warning",
                category="readiness",
                path=relative_path,
                line=find_line_number(text, match.start()),
                message="Production logging statement detected.",
                fix="Remove the log or replace it with structured logging that avoids leaking secrets or user data.",
            )
        )

    for match in SELECT_STAR.finditer(text):
        findings.append(
            Finding(
                check_id="select-star",
                severity="suggestion",
                category="readiness",
                path=relative_path,
                line=find_line_number(text, match.start()),
                message="`select('*')` detected.",
                fix="Request only the columns required by the UI or endpoint.",
            )
        )

    for pattern in SOURCE_MAP_CONFIG_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    check_id="source-map-config",
                    severity="warning",
                    category="security",
                    path=relative_path,
                    line=find_line_number(text, match.start()),
                    message="Source maps appear to be enabled in build configuration.",
                    fix="Disable public production source maps unless you explicitly need them and protect access to them.",
                )
            )


def calculate_score(findings: list[Finding]) -> int:
    penalty_by_severity = {
        "critical": 15,
        "warning": 7,
        "suggestion": 3,
    }
    score = 100
    for finding in findings:
        score -= penalty_by_severity[finding.severity]
    return max(0, score)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "warning": 0, "suggestion": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def to_markdown(score: int, findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    lines = ["# ShipSafe Report", "", f"Score: {score}/100", ""]
    lines.append(f"Critical: {counts['critical']} | Warning: {counts['warning']} | Suggestion: {counts['suggestion']}")
    lines.append("")

    if not findings:
        lines.append("No heuristic findings detected.")
        return "\n".join(lines)

    for severity in ("critical", "warning", "suggestion"):
        bucket = [finding for finding in findings if finding.severity == severity]
        if not bucket:
            continue
        lines.append(severity.upper())
        for finding in bucket:
            location = finding.path if finding.line is None else f"{finding.path}:{finding.line}"
            lines.append(f"- [{finding.category}] {finding.message}")
            lines.append(f"  -> {location}")
            lines.append(f"  -> Fix: {finding.fix}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repo with ShipSafe Lite.")
    parser.add_argument("--root", default=".", help="Repo root to scan.")
    parser.add_argument("--format", choices={"json", "markdown"}, default="json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    findings: list[Finding] = []
    package_json = root / "package.json"
    package_data = None
    if package_json.exists():
        try:
            package_data = json.loads(package_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            package_data = None

    scan_gitignore(root, findings)
    scan_env_example(root, findings)
    scan_security_headers(root, set(DEFAULT_EXCLUDED_DIRS), package_data, findings)
    scan_source_maps(root, findings)
    for path in iter_files(root, set(DEFAULT_EXCLUDED_DIRS)):
        scan_file(path, root, findings)

    findings.sort(key=lambda item: ({"critical": 0, "warning": 1, "suggestion": 2}[item.severity], item.path, item.line or 0))
    score = calculate_score(findings)
    payload = {
        "root": str(root),
        "score": score,
        "counts": severity_counts(findings),
        "findings": [asdict(item) for item in findings],
    }

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(to_markdown(score, findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
