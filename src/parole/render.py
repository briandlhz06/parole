from __future__ import annotations

from parole.hozfix_map import hozfix_command, unique_remediate
from parole.model import Drift, Snapshot


def render_markdown(
    drifts: list[Drift],
    *,
    hostname: str = "",
    baseline_at: str = "",
    checked_at: str = "",
) -> str:
    lines: list[str] = ["# Parole", ""]
    if hostname:
        lines.append(f"Host: `{hostname}`")
    if baseline_at:
        lines.append(f"Baseline: {baseline_at}")
    if checked_at:
        lines.append(f"Check: {checked_at}")
    if hostname or baseline_at or checked_at:
        lines.append("")

    if not drifts:
        lines.append("Sin drift.")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"{len(drifts)} drifts.")
    lines.append("")
    for d in drifts:
        lines.append(f"### {d.id} - {d.title}")
        lines.append("")
        lines.append(f"{d.before} -> {d.after}")
        if d.remediate:
            lines.append(f"remediate: {', '.join(d.remediate)}")
        lines.append("")

    ids = unique_remediate(drifts)
    cmd = hozfix_command(ids)
    if cmd:
        lines.append(f"Hozfix: `{cmd}`")
        lines.append("")
    return "\n".join(lines)


def render_json_payload(
    drifts: list[Drift],
    *,
    hostname: str = "",
    baseline_at: str = "",
    checked_at: str = "",
    baseline: Snapshot | None = None,
    current: Snapshot | None = None,
) -> dict:
    ids = unique_remediate(drifts)
    return {
        "hostname": hostname,
        "baseline_at": baseline_at,
        "checked_at": checked_at,
        "drift_count": len(drifts),
        "drifts": [
            {
                "id": d.id,
                "title": d.title,
                "before": d.before,
                "after": d.after,
                "remediate": list(d.remediate),
            }
            for d in drifts
        ],
        "hozfix_ids": ids,
        "hozfix_hint": hozfix_command(ids),
        "baseline": baseline.to_dict() if baseline else None,
        "current": current.to_dict() if current else None,
    }


def format_telegram(drifts: list[Drift], *, hostname: str = "") -> str:
    host = hostname or "?"
    lines = [f"parole drift en {host}: {len(drifts)}"]
    for d in drifts[:20]:
        tag = f" [{', '.join(d.remediate)}]" if d.remediate else ""
        lines.append(f"- {d.id}: {d.title}{tag}")
    if len(drifts) > 20:
        lines.append(f"... y {len(drifts) - 20} más")
    cmd = hozfix_command(unique_remediate(drifts))
    if cmd:
        lines.append(f"corré: {cmd}")
    return "\n".join(lines)
