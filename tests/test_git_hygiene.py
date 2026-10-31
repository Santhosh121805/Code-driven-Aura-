"""Goal 3 / FR-6: secrets never in plain text in configs, never in logs, never committed to Git.
These tests read real secret VALUES from .env only to check they do not leak; they never print them."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.conftest import ROOT

SECRET_KEYS = re.compile(r"token|password|secret|api_?key|client_secret|webhook", re.I)
NOT_SECRET = {"SECRET_AGE_OVERRIDES"}  # setting names that contain "secret" but hold no secret
SECRET_FIELDS = {"token", "password", "api_key", "client_secret", "secret"}  # config fields that hold secrets
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),            # GitHub classic tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{60,}"),          # GitHub fine-grained tokens (the demo's INVALID token is short)
    re.compile(r"\bSSWS\s+[A-Za-z0-9_\-]{30,}"),          # Okta API token in a header value
    re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,}"),           # Slack tokens
    re.compile(r"https://hooks\.slack\.com/services/\S+"),  # real Slack webhook
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),          # AWS access keys
    re.compile(r"ATATT[A-Za-z0-9_\-=]{20,}"),              # Atlassian API tokens
    re.compile(r"\bgAAAAA[A-Za-z0-9_=-]{40,}"),            # Fernet ciphertext (vault rows must stay in the DB)
]


def env_secret_values() -> dict[str, str]:
    """Secret-looking values from the developer's .env (real keys, vault master key). Public mock values are excluded."""
    env = ROOT / ".env"
    if not env.exists():
        return {}
    out = {}
    for line in env.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key.startswith("MOCK_") or key in NOT_SECRET or len(value) < 8 or value.startswith("http://localhost"):
            continue
        if SECRET_KEYS.search(key) or key == "SECRETS_KEY":
            out[key] = value
    return out


def walk(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, value


def test_configs_hold_only_secret_references():
    for path in sorted((ROOT / "configs").rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key_path, value in walk(data):
            leaf = key_path.split(".")[-1]
            if isinstance(value, str) and leaf in SECRET_FIELDS and value:
                assert re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", value), f"{path.name}:{key_path} is not a ${{NAME}} reference"
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(text), f"{path.name} contains something that looks like a real secret ({pattern.pattern})"


def git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


needs_git = pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="not a git checkout")


@needs_git
def test_env_vault_db_and_logs_are_ignored_and_untracked():
    for path in (".env", "data/platform.db", "data/platform.db-wal", "logs/platform.log", ".venv/x", "tests/__pycache__/x.pyc"):
        assert git("check-ignore", "-q", path).returncode == 0, f"{path} is not git-ignored"
    tracked = set(git("ls-files").stdout.split())
    assert ".env" not in tracked and not any(t.startswith(("data/", "logs/", ".venv/")) or t.endswith((".db", ".log")) for t in tracked)
    assert ".env.example" in tracked


@needs_git
def test_committed_files_contain_no_real_secret_values():
    secrets = env_secret_values()
    for name in git("ls-files").stdout.split():
        path = ROOT / name
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for key, value in secrets.items():
            assert value not in text, f"the value of {key} from .env appears in committed file {name}"
        for pattern in SECRET_PATTERNS:
            hits = [m.group(0) for m in pattern.finditer(text) if "EXAMPLE" not in m.group(0)]  # AWS's documented AKIA...EXAMPLE key
            assert not hits, f"committed file {name} contains something that looks like a real secret ({pattern.pattern})"


def test_logs_contain_no_secret_values():
    logs = sorted((ROOT / "logs").glob("*.log*"))
    if not logs:
        pytest.skip("no log files yet (start the platform once)")
    secrets = env_secret_values()
    for log in logs:
        text = log.read_text(encoding="utf-8", errors="replace")
        for key, value in secrets.items():
            assert value not in text, f"the value of {key} appears in {log.name}"
        assert not re.search(r"Bearer\s+(?!\*\*\*\*)[A-Za-z0-9._~+/=-]{12,}", text), f"unmasked bearer token in {log.name}"
