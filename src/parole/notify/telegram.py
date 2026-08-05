from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable

from parole.model import Drift
from parole.render import format_telegram

SendFn = Callable[[str, str, str], tuple[bool, str]]


def send_telegram(
    token: str,
    chat_id: str,
    drifts: list[Drift],
    *,
    hostname: str = "",
    sender: SendFn | None = None,
) -> tuple[bool, str]:
    if not drifts:
        return True, "skip: sin drift"
    if not token.strip() or not chat_id.strip():
        return True, "sin telegram"
    text = format_telegram(drifts, hostname=hostname)
    fn = sender or _http_send
    return fn(token.strip(), chat_id.strip(), text)


def _http_send(token: str, chat_id: str, text: str) -> tuple[bool, str]:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            if isinstance(data, dict) and data.get("ok"):
                return True, "ok"
            return False, raw[:300] or "telegram fail"
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as e:
        return False, str(e)[:300]
