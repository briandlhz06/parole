# Parole

Guardás cómo quedó el VPS después de arreglarlo. Cada tanto comparás: si aparece MySQL a internet, SSH peor o un Docker público nuevo, te avisa.

Día N de la Trilogía VPS: [Hoztage](https://github.com/briandlhz06/hoztage) mira el server el día 1, [Hozfix](https://github.com/briandlhz06/hozfix) arma el arreglo el día 2, Parole vigila que no se desvíe después. No remedia ni hace intake completo.

```bash
pip install "git+https://github.com/briandlhz06/parole.git"
python -m parole init
python -m parole check
python -m parole check --md drift.md --json drift.json
python -m parole show
```

Baseline por defecto: `~/.parole/baseline.json`. Con `--state PATH` o `PAROLE_STATE` lo movés.
`init --force` regenera el baseline a propósito.

## Qué mira

Listeners públicos sensibles (3306, 6379, 2375, etc.; el 22 solo no cuenta), SSH efectivo (`sshd -T`), Docker publish a `0.0.0.0`/`:::`, UFW active/inactive si hay ufw.

## Hozfix

Si un drift mapea a un finding conocido, el check expone IDs de remediación (`remediate` / `hozfix_ids`): `HOZ-NET-004`, `HOZ-SSH-001`, `HOZ-DOCK-010`, `HOZ-FW-001`, etc. Sin mapeo: no inventa IDs.

```bash
python -m hozfix --ids HOZ-NET-004,HOZ-SSH-002
```

## Cron

```bash
0 */6 * * * parole check
```

## Telegram (opcional)

Solo avisa si hay drift. Incluye hint de Hozfix cuando hay IDs mapeados.

```bash
export PAROLE_TELEGRAM_TOKEN=...
export PAROLE_TELEGRAM_CHAT_ID=...
parole check
```

O `--telegram-token` / `--telegram-chat`. Sin credenciales: no falla, no manda nada.

## Demo

```text
$ parole check
3 drifts.
# Parole

Host: `cliente-wp-07`
Baseline: 2026-07-28T14:22:11Z
Check: 2026-08-05T06:00:00Z

3 drifts.

### HOZ-DRIFT-NET-3306 - Listener público nuevo en 3306

(no estaba) -> 0.0.0.0:3306 (mysqld)
remediate: HOZ-NET-004

### HOZ-DRIFT-SSH-PASS - PasswordAuthentication empeoró

no -> yes
remediate: HOZ-SSH-002

### HOZ-DRIFT-DOCK - Docker publish público nuevo (redis)

(no estaba) -> redis	redis:7	0.0.0.0:6379->6379/tcp	Up 1h
remediate: HOZ-DOCK-6379

Hozfix: `python -m hozfix --ids HOZ-NET-004,HOZ-SSH-002,HOZ-DOCK-6379`
sin telegram
```

Sample completo: [`examples/sample-drift.md`](examples/sample-drift.md)

## Exit

`0` limpio. `1` error. `2` hay drift.

MIT
