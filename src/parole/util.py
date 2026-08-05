from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_cmd(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if err:
            out = f"{out}\n{err}".strip() if out else err
        return p.returncode, out
    except FileNotFoundError:
        return 127, f"no está: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 1, str(e)


def is_linux() -> bool:
    return os.name == "posix" and Path("/etc").exists()


def default_state_path() -> Path:
    env = os.environ.get("PAROLE_STATE", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".parole" / "baseline.json"
