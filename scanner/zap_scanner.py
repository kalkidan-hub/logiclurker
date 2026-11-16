import subprocess
import time
import tempfile
import os
from pathlib import Path
from zapv2 import ZAPv2


def _resolve_zap_executable() -> str:
    """
    Resolve the ZAP launcher on Windows.

    Lookup order:
    1) ZAP_PATH (full path to zap.bat)
    2) ZAP_HOME (folder containing zap.bat)
    3) Common install locations
    4) Plain zap.bat from PATH
    """
    env_path = os.environ.get("ZAP_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return str(p)

    env_home = os.environ.get("ZAP_HOME")
    if env_home:
        p = Path(env_home) / "zap.bat"
        if p.is_file():
            return str(p)

    candidates = [
        Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"),
        Path(r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"),
        Path(r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    # Fall back to PATH-based resolution.
    return "zap.bat"

def launch_zap_and_scan(target_url: str) -> str:
    """
    Launches ZAP, runs active scan against target, returns session db path.
    """
    # Create a dedicated session directory so the path is deterministic
    session_dir  = tempfile.mkdtemp(prefix="zap_session_")
    session_path = os.path.join(session_dir, "scan")  # ZAP appends .session

    zap_executable = _resolve_zap_executable()

    try:
        zap_proc = subprocess.Popen([
            zap_executable,
            "-daemon",
            "-port", "8090",
            "-config", "api.key=mysecretkey",
            "-config", "api.disablekey=false",
            "-newsession", session_path,     # ZAP creates session_path.session here
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "Could not find OWASP ZAP launcher. Set ZAP_PATH to the full path to zap.bat "
            "or add zap.bat to PATH. Example: "
            r"$env:ZAP_PATH='C:\Program Files\ZAP\Zed Attack Proxy\zap.bat'"
        ) from exc

    # Wait for ZAP to be ready
    zap = ZAPv2(apikey="mt7qkr8arskpqul1q9f6ul41f5", proxies={"http": "http://127.0.0.1:8090"})
    _wait_for_zap(zap)

    try:
        # Spider first, then active scan
        print(f"[*] Spidering {target_url}")
        spider_id = zap.spider.scan(target_url)
        _wait_for_completion(zap.spider, spider_id, "Spider")

        print(f"[*] Active scanning {target_url}")
        scan_id = zap.ascan.scan(target_url)
        _wait_for_completion(zap.ascan, scan_id, "Active scan")

        # Ask ZAP for the current session file path directly
        session_info = zap.core.session_location()
        db_path = session_info + ".session"
        print(f"[*] Session DB: {db_path}")

        return db_path

    finally:
        zap.core.shutdown()
        zap_proc.wait()


def _wait_for_zap(zap: ZAPv2, timeout: int = 60):
    import requests
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            zap.core.version()
            print("[*] ZAP is ready")
            return
        except Exception:
            time.sleep(2)
    raise TimeoutError("ZAP did not start in time")


def _wait_for_completion(component, scan_id: str, label: str):
    while True:
        progress = int(component.status(scan_id))
        print(f"\r[*] {label}: {progress}%", end="", flush=True)
        if progress >= 100:
            print()
            return
        time.sleep(3)


if __name__ == "__main__":
    target  = "http://juice-shop.herokuapp.com"
    db_path = launch_zap_and_scan(target)
    print("db_path:", db_path)

    # Feed directly into your record builder
    from build_records import build_records
    import json

    records = build_records(db_path)
    with open("sqli_records.json", "w") as f:
        json.dump(records, f, indent=2)

    print(f"[*] Wrote {len(records)} records → sqli_records.json")