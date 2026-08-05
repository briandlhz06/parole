from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from parole import __version__
from parole.collect import take_snapshot
from parole.diff import diff_snapshots
from parole.notify.telegram import send_telegram
from parole.render import render_json_payload, render_markdown
from parole.state import load_baseline, save_baseline
from parole.util import default_state_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="parole",
        description="Parole - día N: el VPS en libertad condicional.",
    )
    p.add_argument("--version", action="version", version=f"parole {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Guardar baseline")
    p_init.add_argument("--force", action="store_true", help="Pisar baseline existente")
    p_init.add_argument("--state", type=Path, default=None, help="Path del baseline JSON")

    p_check = sub.add_parser("check", help="Comparar contra baseline")
    p_check.add_argument("--state", type=Path, default=None)
    p_check.add_argument("--json", type=Path, default=None, help="Guardar JSON")
    p_check.add_argument("--md", type=Path, default=None, help="Guardar Markdown")
    p_check.add_argument("--telegram-token", default="", help="Bot token (o PAROLE_TELEGRAM_TOKEN)")
    p_check.add_argument("--telegram-chat", default="", help="Chat id (o PAROLE_TELEGRAM_CHAT_ID)")
    p_check.add_argument("-q", "--quiet", action="store_true")

    p_show = sub.add_parser("show", help="Mostrar baseline")
    p_show.add_argument("--state", type=Path, default=None)

    args = p.parse_args(argv)
    state = args.state if getattr(args, "state", None) else default_state_path()

    try:
        if args.cmd == "init":
            return cmd_init(state, force=args.force)
        if args.cmd == "check":
            return cmd_check(
                state,
                json_path=args.json,
                md_path=args.md,
                telegram_token=args.telegram_token or os.environ.get("PAROLE_TELEGRAM_TOKEN", ""),
                telegram_chat=args.telegram_chat or os.environ.get("PAROLE_TELEGRAM_CHAT_ID", ""),
                quiet=args.quiet,
            )
        if args.cmd == "show":
            return cmd_show(state)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 1


def cmd_init(state: Path, *, force: bool) -> int:
    if state.is_file() and not force:
        print(f"Ya hay baseline en {state}. Usá --force si querés regenerarlo.", file=sys.stderr)
        return 1
    snap = take_snapshot()
    save_baseline(state, snap)
    print(f"Baseline guardado: {state}")
    if not snap.linux:
        print("Nota: no-Linux; el snapshot quedó vacío de checks.")
    return 0


def cmd_show(state: Path) -> int:
    if not state.is_file():
        print(f"No hay baseline en {state}. Corré: parole init", file=sys.stderr)
        return 1
    snap = load_baseline(state)
    print(json.dumps(snap.to_dict(), indent=2, ensure_ascii=False))
    return 0


def cmd_check(
    state: Path,
    *,
    json_path: Path | None,
    md_path: Path | None,
    telegram_token: str,
    telegram_chat: str,
    quiet: bool,
) -> int:
    if not state.is_file():
        print(f"No hay baseline en {state}. Corré: parole init", file=sys.stderr)
        return 1

    baseline = load_baseline(state)
    current = take_snapshot()
    drifts = diff_snapshots(baseline, current)

    md = render_markdown(
        drifts,
        hostname=current.hostname or baseline.hostname,
        baseline_at=baseline.collected_at,
        checked_at=current.collected_at,
    )
    payload = render_json_payload(
        drifts,
        hostname=current.hostname or baseline.hostname,
        baseline_at=baseline.collected_at,
        checked_at=current.collected_at,
        baseline=baseline,
        current=current,
    )

    if md_path:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md, encoding="utf-8")
        if not quiet:
            print(f"md: {md_path}")
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not quiet:
            print(f"json: {json_path}")

    if not quiet:
        if drifts:
            print(f"{len(drifts)} drifts.", flush=True)
        else:
            print("Sin drift.", flush=True)
        if not md_path and not json_path:
            print(md)

    if drifts:
        ok, msg = send_telegram(
            telegram_token,
            telegram_chat,
            drifts,
            hostname=current.hostname or baseline.hostname,
        )
        if not quiet:
            if msg == "sin telegram":
                print("sin telegram")
            elif not ok:
                print(f"telegram: {msg}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
