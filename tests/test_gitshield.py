import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gitshield import (
    calculate_shannon_entropy,
    check_unsafe_permissions,
    scan_line_for_secrets,
)


def test_detects_aws_access_key():
    line = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'  # gitshield:ignore
    findings = scan_line_for_secrets(line)
    assert any(f["type"] == "AWS Access Key ID" for f in findings)


def test_detects_pem_private_key():
    line = "-----BEGIN RSA PRIVATE KEY-----"  # gitshield:ignore
    findings = scan_line_for_secrets(line)
    assert any(f["type"] == "PEM Private Key Header" for f in findings)


def test_detects_high_entropy_token():
    token = "9xK7vL2mP8qR4tY6wZ3nB5cV1jH0gF4d"  # gitshield:ignore
    line = f'WEBHOOK_SIGNING_SECRET = "{token}"'
    findings = scan_line_for_secrets(line)
    assert len(findings) >= 1
    assert calculate_shannon_entropy(token) > 4.5


def test_allows_clean_code():
    line = "def compute_latency(start_ms: float, end_ms: float) -> float:"
    assert scan_line_for_secrets(line) == []


def test_ignore_marker_bypasses_finding():
    line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitshield:ignore'
    assert scan_line_for_secrets(line) == []


def test_blocks_chmod_777_on_disk():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        os.chmod(tmp_path, 0o777)
        issue = check_unsafe_permissions("100644", tmp_path)
        assert issue is not None
        assert "World-writable" in issue

        os.chmod(tmp_path, 0o644)
        assert check_unsafe_permissions("100644", tmp_path) is None
    finally:
        os.remove(tmp_path)
