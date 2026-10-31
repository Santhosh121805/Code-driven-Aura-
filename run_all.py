"""Start the platform and all mock tools as separate processes: `python run_all.py`.

Options:
  --mocks-only     start only the 4 mock tools
  --no-mocks       start only the platform
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def ensure_env_file() -> None:
    env_file, example = ROOT / ".env", ROOT / ".env.example"
    if not env_file.exists() and example.exists():
        shutil.copy(example, env_file)
        print("Created .env from .env.example (demo credentials).")
        return
    # Existing .env from an older version: append any keys that .env.example has gained since.
    def keys(path: Path) -> dict[str, str]:
        out = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                out[line.split("=", 1)[0].strip()] = line
        return out
    # Mock credentials were renamed to MOCK_*. The old names must go: on Windows env vars are case-insensitive,
    # so a leftover JIRA_TOKEN (mock) would shadow the REAL Jira secret `jira_token`.
    legacy = {"JIRA_USER", "JIRA_TOKEN", "OKTA_CLIENT_ID", "OKTA_CLIENT_SECRET", "ACME_FW_API_KEY", "AWS_CLOUDTRAIL_TOKEN"}
    lines = env_file.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.split("=", 1)[0].strip() not in legacy or line.lstrip().startswith("#")]
    if len(kept) != len(lines):
        env_file.write_text("\n".join(kept) + "\n", encoding="utf-8")
        print(f"Removed {len(lines) - len(kept)} obsolete mock setting(s) from .env (renamed to MOCK_*).")
    have, want = keys(env_file), keys(example)
    missing = [line for key, line in want.items() if key not in have]
    if missing:
        with env_file.open("a", encoding="utf-8") as f:
            f.write("\n# Added from .env.example by run_all.py\n" + "\n".join(missing) + "\n")
        print(f"Added {len(missing)} new setting(s) to .env: {', '.join(k for k in want if k not in have)}")


def ensure_secrets_key() -> None:
    """Generate the vault master key into .env on first run (a Fernet key is 32 random bytes, url-safe base64)."""
    env_file = ROOT / ".env"
    lines = env_file.read_text(encoding="utf-8").splitlines()
    if any(line.startswith("SECRETS_KEY=") and line.split("=", 1)[1].strip() for line in lines) or os.environ.get("SECRETS_KEY"):
        return
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    if any(line.startswith("SECRETS_KEY=") for line in lines):
        lines = [f"SECRETS_KEY={key}" if line.startswith("SECRETS_KEY=") else line for line in lines]
    else:
        lines.append(f"SECRETS_KEY={key}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Generated SECRETS_KEY in .env (master key for the encrypted secret vault).")


def load_env() -> dict[str, str]:
    """Process env + .env (process env wins)."""
    merged: dict[str, str] = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                merged[key.strip()] = value.strip().strip('"').strip("'")
    merged.update(os.environ)
    merged["PYTHONUNBUFFERED"] = "1"
    return merged


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def wait_healthy(url: str, timeout: float = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def check_environment() -> bool:
    if sys.version_info < (3, 11):
        print(f"ERROR: Python 3.11+ is required (this is {sys.version.split()[0]}). Try: py -3.11 run_all.py  /  python3.11 run_all.py")
        return False
    missing = [m for m in ("fastapi", "uvicorn", "httpx", "pydantic", "yaml", "jmespath", "jinja2", "apscheduler", "dotenv", "multipart",
                           "cryptography")
               if importlib.util.find_spec(m) is None]
    if missing:
        print(f"ERROR: missing packages: {', '.join(missing)}")
        print(f"Run: {sys.executable} -m pip install -r requirements.txt")
        return False
    return True


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)  # show progress immediately even when output is redirected
    if not check_environment():
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--mocks-only", action="store_true")
    parser.add_argument("--no-mocks", action="store_true")
    args = parser.parse_args()

    ensure_env_file()
    ensure_secrets_key()
    env = load_env()
    py = sys.executable

    services: list[tuple[str, int, list[str]]] = []
    if not args.no_mocks:
        services += [
            ("Mock CloudTrail", int(env.get("MOCK_CLOUDTRAIL_PORT", 9001)), [py, "-m", "mocks.mock_cloudtrail"]),
            ("Mock Firewall", int(env.get("MOCK_FIREWALL_PORT", 9002)), [py, "-m", "mocks.mock_firewall"]),
            ("Mock Okta", int(env.get("MOCK_OKTA_PORT", 9003)), [py, "-m", "mocks.mock_okta"]),
            ("Mock Jira", int(env.get("MOCK_JIRA_PORT", 9004)), [py, "-m", "mocks.mock_jira"]),
        ]
    if not args.mocks_only:
        port = int(env.get("PLATFORM_PORT", 8000))
        services.append(("Platform", port, [py, "-m", "uvicorn", "integration_platform.api:app",
                                            "--host", env.get("BIND_HOST", "127.0.0.1"), "--port", str(port), "--log-level", "warning"]))

    busy = [f"{name} (port {port})" for name, port, _ in services if not port_free(port)]
    if busy:
        print("ERROR: these ports are already in use: " + ", ".join(busy))
        print("Stop the other process (maybe an earlier run_all.py) and try again.")
        return 1

    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, port, cmd in services:
            procs.append((name, subprocess.Popen(cmd, cwd=ROOT, env=env)))
        for name, port, _ in services:
            ok = wait_healthy(f"http://127.0.0.1:{port}/health")
            print(f"  {'OK  ' if ok else 'FAIL'} {name:<14} http://localhost:{port}")
            if not ok:
                raise RuntimeError(f"{name} did not become healthy")
        if not args.mocks_only:
            print(f"\n  Dashboard:  http://localhost:{env.get('PLATFORM_PORT', 8000)}")
        if not args.no_mocks:
            print(f"  Jira board: http://localhost:{env.get('MOCK_JIRA_PORT', 9004)}")
        print("\nAll services running. Press Ctrl+C to stop.")
        while True:
            for name, proc in procs:
                if proc.poll() is not None:
                    raise RuntimeError(f"{name} exited unexpectedly (code {proc.returncode})")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        return 1
    finally:
        for _, proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for _, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
