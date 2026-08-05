from __future__ import annotations

import json
from pathlib import Path

from parole.model import Snapshot


def load_baseline(path: Path) -> Snapshot:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("baseline inválido")
    return Snapshot.from_dict(data)


def save_baseline(path: Path, snap: Snapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snap.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
