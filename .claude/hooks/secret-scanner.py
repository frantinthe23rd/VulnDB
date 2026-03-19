#!/usr/bin/env python3
"""
Pre-commit secret scanner for Claude Code.
Blocks git commits if sensitive patterns are found in staged files.
"""
import json
import re
import subprocess
import sys

PATTERNS = [
    # AWS account IDs embedded in ARNs
    (r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:', "AWS account ID in ARN"),
    # Generic API keys / tokens
    (r'(?i)(api_key|api_token|secret_key|secret_token)\s*=\s*["\'][A-Za-z0-9+/\-_]{16,}["\']', "Hardcoded API key or token"),
    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9]{36,}', "GitHub token"),
    # AWS access keys
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    # Generic passwords
    (r'(?i)password\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded password"),
    # Basic auth credentials in URLs
    (r'https?://[^:]+:[^@]{4,}@', "Credentials in URL"),
]

# File extensions to skip (binary / generated)
SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.pyc', '.exe'}


def get_staged_files():
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        capture_output=True, text=True
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]


def get_staged_content(filepath):
    result = subprocess.run(
        ['git', 'show', f':{filepath}'],
        capture_output=True, text=True, errors='replace'
    )
    return result.stdout


def scan_file(filepath, content):
    findings = []
    for pattern, label in PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            findings.append(f"  {label} — {filepath}:{line_num}")
    return findings


def main():
    data = json.load(sys.stdin)
    command = data.get('tool_input', {}).get('command', '')

    # Only intercept git commit commands
    if 'git commit' not in command:
        sys.exit(0)

    staged = get_staged_files()
    if not staged:
        sys.exit(0)

    all_findings = []
    for filepath in staged:
        ext = '.' + filepath.rsplit('.', 1)[-1] if '.' in filepath else ''
        if ext.lower() in SKIP_EXTENSIONS:
            continue
        content = get_staged_content(filepath)
        all_findings.extend(scan_file(filepath, content))

    if all_findings:
        print("SECRET SCAN BLOCKED: Potential sensitive data detected in staged files:\n")
        for f in all_findings:
            print(f)
        print("\nReview the above before committing. If these are false positives, commit manually.")
        sys.exit(2)

    sys.exit(0)


if __name__ == '__main__':
    main()
