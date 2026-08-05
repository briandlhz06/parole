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

### HOZ-DRIFT-DOCK - Docker publish público nuevo (mailcowdockerized-nginx-mailcow-1)

(no estaba) -> mailcowdockerized-nginx-mailcow-1	mailcow/nginx:1.0	0.0.0.0:8081->80/tcp	Up 3 weeks
remediate: HOZ-DOCK-010

Hozfix: `python -m hozfix --ids HOZ-NET-004,HOZ-SSH-002,HOZ-DOCK-010`
