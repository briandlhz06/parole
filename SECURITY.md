# Seguridad

## Reportar

Mandá un mail a briandlhz@proton.me con "parole" en el asunto. No abras un issue público para algo explotable.

Incluí qué versión usaste, en qué distro, y cómo reproducirlo.

Contesto en unos días. Esto lo mantengo yo solo, no esperes SLA de empresa.

## Qué cuenta

Parole compara el estado del VPS contra un baseline y avisa si empeoró. Interesa:

- Un drift real que no se detecta (por ejemplo, un listener público que pasa desapercibido).
- Ejecución de comandos vía datos del sistema o del baseline.
- Filtrar el token de Telegram en logs o en la salida.

## Qué no

- Que el baseline en `~/.parole/baseline.json` se pueda editar. Quien tiene escritura en tu HOME ya ganó; Parole no defiende contra eso.
- Que no detecte cambios hacia mejor. Es a propósito: solo reporta si empeoró.

## Versiones

Se arregla sobre `main`. No hay backports.
