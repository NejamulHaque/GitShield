#!/usr/bin/env python3
import argparse
import math
import os
import re
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 1. High-Confidence Secret Signatures (Regex)
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    "PEM Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "GitHub Personal Access Token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
    "Generic Hardcoded Secret": re.compile(
        r"(?i)\b(?:api_key|apikey|secret_key|aws_secret_access_key|password|passwd|auth_token|private_key)\b\s*[:=]\s*['\"]([A-Za-z0-9/+=_\-]{12,})['\"]"
    ),
}

# Candidate token extractor for Shannon entropy analysis
TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9/+=_\-]{20,}")
ENTROPY_THRESHOLD = 4.5

# Allowlist markers so developers can explicitly mark fake test fixtures
IGNORE_MARKER = "gitshield:ignore"


def calculate_shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def scan_line_for_secrets(line: str) -> list[dict]:
    """Scan a single added line for regex secret patterns and high-entropy tokens."""
    if IGNORE_MARKER in line:
        return []

    findings = []
    matched_spans = []

    # 1. Check deterministic regex signatures
    for rule_name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(line):
            findings.append({
                "type": rule_name,
                "snippet": redact_secret(match.group(0)),
            })
            matched_spans.append(match.span())

    # 2. Check high-entropy tokens not already caught by regex
    for token_match in TOKEN_CANDIDATE_RE.finditer(line):
        start, end = token_match.span()
        if any(s <= start and end <= e for s, e in matched_spans):
            continue
        token = token_match.group(0)
        # Skip common paths, URLs, or repetitive strings
        if "/" in token and token.startswith(("http", "usr", "var", "etc", "app")):
            continue
        entropy = calculate_shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({
                "type": f"High-Entropy Token (H={entropy:.2f})",
                "snippet": redact_secret(token),
            })

    return findings


def redact_secret(value: str) -> str:
    """Safely mask secret values before printing to terminal logs."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def get_staged_files_and_modes() -> list[tuple[str, str]]:
    """Return list of (git_mode, filepath) for all staged Added/Modified files."""
    cmd = ["git", "diff", "--cached", "--raw", "--diff-filter=ACM"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return []

    entries = []
    for line in res.stdout.strip().splitlines():
        # Format: :old_mode new_mode old_sha new_sha status\tfilepath
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        meta, filepath = parts
        meta_fields = meta.split()
        new_mode = meta_fields[1] if len(meta_fields) >= 2 else "100644"
        entries.append((new_mode, filepath))
    return entries


def check_unsafe_permissions(git_mode: str, filepath: str) -> str | None:
    """Detect chmod 777 / world-writable permissions in Git index or local disk."""
    if git_mode == "100777":
        return "Staged with unsafe Git mode 100777 (world-writable)"

    if os.path.exists(filepath) and not os.path.islink(filepath):
        st_mode = os.stat(filepath).st_mode
        if bool(st_mode & stat.S_IWOTH):
            octal_perm = oct(stat.S_IMODE(st_mode))
            return f"World-writable file permissions detected on disk ({octal_perm} / chmod 777 risk)"
    return None


def get_staged_added_lines(filepath: str) -> list[tuple[int, str]]:
    """Extract added lines (+...) and their line numbers from staged diff."""
    cmd = ["git", "diff", "--cached", "-U0", "--", filepath]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", check=False)
    if res.returncode != 0:
        return []

    added = []
    current_line = 0
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in res.stdout.splitlines():
        hunk_match = hunk_re.match(raw_line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added.append((current_line, raw_line[1:]))
            current_line += 1
    return added


def scan_staged() -> int:
    """Main pre-commit entry point: audits staged files for permissions and secrets."""
    staged_entries = get_staged_files_and_modes()
    if not staged_entries:
        return 0

    violations = []

    for git_mode, filepath in staged_entries:
        perm_issue = check_unsafe_permissions(git_mode, filepath)
        if perm_issue:
            violations.append(f"[PERMISSION] {filepath}: {perm_issue}")

        for line_no, content in get_staged_added_lines(filepath):
            for finding in scan_line_for_secrets(content):
                violations.append(
                    f"[SECRET]     {filepath}:{line_no} -> {finding['type']} ({finding['snippet']})"
                )

    if violations:
        print("\n" + "=" * 68)
        print("🛡️  GITSHIELD BLOCKED COMMIT — SECURITY VIOLATIONS DETECTED")
        print("=" * 68)
        for v in violations:
            print(f"  ✖ {v}")
        print("-" * 68)
        print("Fix: Remove hardcoded secrets or fix permissions (chmod 644 <file>).")
        print(f"Tip: Add '# {IGNORE_MARKER}' on a line only for intentional test fixtures.")
        print("=" * 68 + "\n")
        return 1

    print("🛡️  GitShield: Staged changes passed secret & permission checks.")
    return 0


def scan_standalone_file(filepath: str) -> int:
    """Audit a single file directly via CLI (--file)."""
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        return 2

    violations = []
    perm_issue = check_unsafe_permissions("100644", filepath)
    if perm_issue:
        violations.append(f"[PERMISSION] {filepath}: {perm_issue}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            for finding in scan_line_for_secrets(line):
                violations.append(
                    f"[SECRET]     {filepath}:{idx} -> {finding['type']} ({finding['snippet']})"
                )

    if violations:
        for v in violations:
            print(f"✖ {v}")
        return 1

    print(f"✔ {filepath}: Clean")
    return 0


def install_hook() -> int:
    """Install GitShield into the current Git repository's .git/hooks/pre-commit."""
    git_dir_res = subprocess.run(
        ["git", "rev-parse", "--git-dir"], capture_output=True, text=True, check=False
    )
    if git_dir_res.returncode != 0:
        print("Error: Not inside a Git repository.", file=sys.stderr)
        return 1

    hooks_dir = os.path.join(git_dir_res.stdout.strip(), "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    target_hook = os.path.join(hooks_dir, "pre-commit")
    source_script = os.path.abspath(__file__)

    shutil.copy2(source_script, target_hook)
    os.chmod(target_hook, 0o755)
    print(f"✔ GitShield installed successfully to {target_hook}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="GitShield — Zero-Dependency Pre-Commit Secret & Permission Blocker"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install GitShield as the active .git/hooks/pre-commit hook",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Scan a specific file directly instead of staged Git changes",
    )
    args = parser.parse_args()

    if args.install:
        return install_hook()
    if args.file:
        return scan_standalone_file(args.file)
    return scan_staged()


if __name__ == "__main__":
    sys.exit(main())
