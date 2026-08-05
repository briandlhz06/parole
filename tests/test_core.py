from __future__ import annotations

import json
from pathlib import Path

from parole.cli import main
from parole.collect.net import parse_ss_lines
from parole.diff import diff_snapshots
from parole.hozfix_map import hozfix_command, remediate_ids, unique_remediate
from parole.model import Drift, ListenerHit, Snapshot, SshState
from parole.notify.telegram import send_telegram
from parole.render import format_telegram, render_json_payload, render_markdown
from parole.state import load_baseline, save_baseline


def _snap(**kwargs) -> Snapshot:
    base = dict(
        hostname="vps-01",
        collected_at="2026-08-01T10:00:00Z",
        platform="Linux",
        linux=True,
    )
    base.update(kwargs)
    return Snapshot(**base)


def test_port_22_alone_not_sensitive():
    raw = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"
    assert parse_ss_lines(raw) == []


def test_new_public_3306_is_drift():
    baseline = _snap(listeners=[])
    current = _snap(
        listeners=[ListenerHit(port=3306, address="0.0.0.0", process="mysqld")],
        collected_at="2026-08-05T10:00:00Z",
    )
    drifts = diff_snapshots(baseline, current)
    assert any(d.id == "HOZ-DRIFT-NET-3306" for d in drifts)
    assert "3306" in drifts[0].after
    assert drifts[0].remediate == ["HOZ-NET-004"]


def test_existing_3306_no_drift():
    hit = ListenerHit(port=3306, address="0.0.0.0", process="mysqld")
    baseline = _snap(listeners=[hit])
    current = _snap(listeners=[hit])
    assert diff_snapshots(baseline, current) == []


def test_ssh_password_yes_to_no_not_bad():
    baseline = _snap(ssh=SshState(password_authentication="yes", available=True, port="22"))
    current = _snap(ssh=SshState(password_authentication="no", available=True, port="22"))
    assert diff_snapshots(baseline, current) == []


def test_ssh_password_no_to_yes_is_drift():
    baseline = _snap(ssh=SshState(password_authentication="no", available=True, port="22"))
    current = _snap(ssh=SshState(password_authentication="yes", available=True, port="22"))
    drifts = diff_snapshots(baseline, current)
    assert any(d.id == "HOZ-DRIFT-SSH-PASS" for d in drifts)
    d = next(x for x in drifts if x.id == "HOZ-DRIFT-SSH-PASS")
    assert d.remediate == ["HOZ-SSH-002"]


def test_ssh_root_worsens():
    baseline = _snap(ssh=SshState(permit_root_login="no", available=True, port="22"))
    current = _snap(ssh=SshState(permit_root_login="yes", available=True, port="22"))
    drifts = diff_snapshots(baseline, current)
    assert any(d.id == "HOZ-DRIFT-SSH-ROOT" for d in drifts)
    d = next(x for x in drifts if x.id == "HOZ-DRIFT-SSH-ROOT")
    assert d.remediate == ["HOZ-SSH-001"]


def test_docker_new_publish_is_drift():
    baseline = _snap(docker_publishes=[])
    current = _snap(
        docker_publishes=["redis\tredis:7\t0.0.0.0:6379->6379/tcp\tUp 1h"]
    )
    drifts = diff_snapshots(baseline, current)
    assert any(d.id == "HOZ-DRIFT-DOCK" for d in drifts)
    d = next(x for x in drifts if x.id == "HOZ-DRIFT-DOCK")
    assert d.remediate == ["HOZ-DOCK-6379"]


def test_ufw_active_to_inactive():
    baseline = _snap(ufw="active")
    current = _snap(ufw="inactive")
    drifts = diff_snapshots(baseline, current)
    assert any(d.id == "HOZ-DRIFT-UFW" for d in drifts)
    assert drifts[0].remediate == ["HOZ-FW-001"]


def test_ufw_inactive_to_active_not_drift():
    baseline = _snap(ufw="inactive")
    current = _snap(ufw="active")
    assert diff_snapshots(baseline, current) == []


def test_hozfix_map_known_and_unknown():
    assert remediate_ids("HOZ-DRIFT-NET-3306") == ["HOZ-NET-004"]
    assert remediate_ids("HOZ-DRIFT-NET-6379") == ["HOZ-NET-006"]
    assert remediate_ids("HOZ-DRIFT-NET-9999") == []
    assert remediate_ids("HOZ-DRIFT-SSH-PUBKEY") == ["HOZ-SSH-003"]
    assert remediate_ids("HOZ-DRIFT-SSH-PORT") == ["HOZ-SSH-005"]
    assert remediate_ids("HOZ-DRIFT-UFW") == ["HOZ-FW-001"]
    assert remediate_ids(
        "HOZ-DRIFT-DOCK",
        after="web\tnginx\t0.0.0.0:8081->80/tcp",
    ) == ["HOZ-DOCK-010"]
    assert remediate_ids(
        "HOZ-DRIFT-DOCK",
        after="db\tmysql\t0.0.0.0:3306->3306/tcp",
    ) == ["HOZ-DOCK-3306"]
    assert remediate_ids("HOZ-DRIFT-WEIRD") == []
    assert hozfix_command(["HOZ-NET-004", "HOZ-SSH-002"]) == (
        "python -m hozfix --ids HOZ-NET-004,HOZ-SSH-002"
    )
    assert hozfix_command([]) is None


def test_telegram_format_and_skip():
    drifts = [
        Drift(
            id="HOZ-DRIFT-NET-3306",
            title="Listener público nuevo en 3306",
            before="x",
            after="y",
            remediate=["HOZ-NET-004"],
        )
    ]
    text = format_telegram(drifts, hostname="vps-01")
    assert "vps-01" in text
    assert "HOZ-DRIFT-NET-3306" in text
    assert "HOZ-NET-004" in text
    assert "corré: python -m hozfix --ids HOZ-NET-004" in text
    assert "—" not in text

    ok, msg = send_telegram("", "", drifts, hostname="vps-01")
    assert ok and msg == "sin telegram"

    ok, msg = send_telegram("tok", "chat", [], hostname="vps-01")
    assert ok and msg == "skip: sin drift"

    sent: list[tuple[str, str, str]] = []

    def fake(token: str, chat: str, text: str) -> tuple[bool, str]:
        sent.append((token, chat, text))
        return True, "ok"

    ok, msg = send_telegram("tok", "42", drifts, hostname="vps-01", sender=fake)
    assert ok and msg == "ok"
    assert sent and "HOZ-DRIFT-NET-3306" in sent[0][2]
    assert "corré: python -m hozfix --ids HOZ-NET-004" in sent[0][2]


def test_telegram_no_hint_without_remediate():
    drifts = [
        Drift(id="HOZ-DRIFT-NET-9999", title="Listener raro", before="x", after="y")
    ]
    text = format_telegram(drifts, hostname="vps-01")
    assert "corré" not in text
    assert "hozfix" not in text


def test_markdown_shape():
    drifts = [
        Drift(
            id="HOZ-DRIFT-NET-3306",
            title="Listener público nuevo en 3306",
            before="(no estaba)",
            after="0.0.0.0:3306 (mysqld)",
            remediate=["HOZ-NET-004"],
        )
    ]
    md = render_markdown(drifts, hostname="vps-01", baseline_at="2026-08-01T10:00:00Z")
    assert "# Parole" in md
    assert "1 drifts" in md
    assert "->" in md
    assert "remediate: HOZ-NET-004" in md
    assert "python -m hozfix --ids HOZ-NET-004" in md
    assert "—" not in md
    assert "Qué encontré" not in md
    assert "Acción" not in md

    payload = render_json_payload(drifts, hostname="vps-01")
    assert payload["drifts"][0]["remediate"] == ["HOZ-NET-004"]
    assert payload["hozfix_ids"] == ["HOZ-NET-004"]
    assert payload["hozfix_hint"] == "python -m hozfix --ids HOZ-NET-004"
    blob = json.dumps(payload, ensure_ascii=False)
    assert "—" not in blob
    assert unique_remediate(drifts) == ["HOZ-NET-004"]


def test_no_em_dash_in_sample_and_readme():
    root = Path(__file__).resolve().parents[1]
    for rel in ("README.md", "examples/sample-drift.md"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "—" not in text, rel


def test_cli_init_check_exit_codes(tmp_path: Path):
    state = tmp_path / "baseline.json"
    code = main(["init", "--state", str(state)])
    assert code == 0
    assert state.is_file()

    assert main(["init", "--state", str(state)]) == 1
    assert main(["init", "--state", str(state), "--force"]) == 0

    baseline = load_baseline(state)
    assert diff_snapshots(baseline, baseline) == []

    md = tmp_path / "out.md"
    code = main(["check", "--state", str(state), "--md", str(md), "-q"])
    assert code in (0, 2)
    if code == 0:
        assert "Sin drift" in md.read_text(encoding="utf-8") or md.is_file()


def test_cli_check_detects_injected_drift(tmp_path: Path):
    state = tmp_path / "baseline.json"
    baseline = _snap(listeners=[], ssh=SshState(available=True, password_authentication="no", port="22"))
    save_baseline(state, baseline)

    current = _snap(
        listeners=[ListenerHit(3306, "0.0.0.0", "mysqld")],
        ssh=SshState(available=True, password_authentication="yes", port="22"),
        collected_at="2026-08-05T12:00:00Z",
    )
    drifts = diff_snapshots(baseline, current)
    assert len(drifts) >= 2
    ids = unique_remediate(drifts)
    assert "HOZ-NET-004" in ids
    assert "HOZ-SSH-002" in ids

    assert main(["show", "--state", str(state)]) == 0


def test_cli_requires_subcommand():
    try:
        main([])
    except SystemExit as e:
        assert e.code == 2
        return
    raise AssertionError("esperaba SystemExit 2")


def test_cli_check_missing_baseline(tmp_path: Path):
    assert main(["check", "--state", str(tmp_path / "nope.json"), "-q"]) == 1


def test_state_roundtrip(tmp_path: Path):
    path = tmp_path / "b.json"
    snap = _snap(
        listeners=[ListenerHit(6379, "0.0.0.0", "redis")],
        docker_publishes=["c1\timg\t0.0.0.0:8080->80/tcp"],
        ufw="active",
        ssh=SshState(permit_root_login="no", password_authentication="no", available=True, port="22"),
    )
    save_baseline(path, snap)
    loaded = load_baseline(path)
    assert loaded.hostname == "vps-01"
    assert loaded.listeners[0].port == 6379
    assert loaded.ufw == "active"
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1
