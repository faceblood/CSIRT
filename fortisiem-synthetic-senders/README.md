# fortisiem-synthetic-senders

[![CI](https://github.com/faceblood/fortisiem-synthetic-senders/actions/workflows/ci.yml/badge.svg)](https://github.com/faceblood/fortisiem-synthetic-senders/actions/workflows/ci.yml)

Herramientas **por fuente** para generar y enviar syslog sintético orientado a FortiSIEM. Este repo contiene las mismas plantillas (`log_repository/`) y datos (`config/`) que el proyecto de campañas, pero **sin** CSV de campañas, `--campaign`, ni pasos encadenados: cada ejecutable solo cubre una fuente y categoría acotada.

## Requisitos

- Python 3.10+
- Dependencias: `scapy>=2.5.0` (ver `requirements.txt` / `pyproject.toml`)

## Instalación

Desde la raíz del repo (donde están `config/` y `log_repository/`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install .
```

Los scripts de consola quedan como: `send-fortigate-vpn`, `send-fortigate-traffic`, `send-fortiedr`, `send-vmware`, `send-windows`, `send-linux`, `send-fortimail`.

Sin instalar en el entorno, puedes usar:

```bash
export PYTHONPATH=src
python3 -m fortisiem_send.cli.fortigate_vpn --help
```

## Uso

Por defecto se buscan `config/` y `log_repository/` en el **directorio actual**. Opcional: `--repo-root /ruta/al/repo` o `--config-dir /ruta/al/repo/config` (la raíz de datos será el directorio padre de `config/`).

**Cada script tiene sus propios parámetros** (no comparten un mega `--help`). Comparten envío, rutas y **reporting IP del syslog**: `--repo-root`, `--config-dir`, `--target`, `--port`, `--syslog-hostname`, `--count`, `--rate`, `--dry-run`, **`--syslog-src-ip`** (IPv4 origen del paquete UDP hacia el collector; en FortiSIEM suele corresponder al *reporting IP* / IP vista por el parser; **no** sustituye los placeholders del cuerpo del evento — para eso siguen `--attacker-ip` y flags por fuente). El resto es por ejecutable; usa `send-… --help`.

| Script | Parámetros propios (además de los comunes y `--syslog-src-ip`; ver `--help`) |
|--------|-------------------------------------------|
| `send-fortigate-vpn` | `--src-ip-mode`, `--attacker-ip`, `--fortigate-devname`, `--fortigate-serial`, **`--vpn-remote-ip`** (solo VPN / `remip`), `--user-samaccountname`, `--event-hint` |
| `send-fortigate-traffic` | `--src-ip-mode`, `--attacker-ip`, `--fortigate-devname`, `--fortigate-serial`, `--c2-ip`, `--c2-domain`, `--event-hint` |
| `send-fortiedr` | `--src-ip-mode`, `--attacker-ip`, `--user-samaccountname`, `--endpoint-ip`, `--initial-asset-ip`, `--initial-asset-hostname`, `--hostname`, `--category`, `--event-hint` |
| `send-vmware` | `--src-ip-mode`, `--attacker-ip`, `--vmware-user`, `--vmware-asset-ip`, `--category`, `--event-hint` |
| `send-windows` | `--src-ip-mode`, `--attacker-ip`, `--user-samaccountname`, `--endpoint-ip`, `--initial-asset-ip`, `--initial-asset-hostname`, `--hostname`, `--lateral-asset-ip`, `--category`, `--event-hint` |
| `send-linux` | `--src-ip-mode`, `--attacker-ip`, `--user-samaccountname`, `--linux-asset-ip`, `--category`, `--event-hint` |
| `send-fortimail` | `--src-ip-mode`, `--attacker-ip`, `--user-samaccountname`, `--c2-domain`, `--category`, `--event-hint` |

### Ejemplos

FortiGate VPN (categoría fija `vpn`):

```bash
send-fortigate-vpn --dry-run --count 5 --event-hint "tunnel"
```

Reporting IP (origen UDP) distinto del `src_ip` del mensaje (cualquier CLI; ejemplo VPN con `remip`):

```bash
send-fortigate-vpn --dry-run --count 1 \
  --attacker-ip 10.0.0.1 --vpn-remote-ip 10.0.0.2 --syslog-src-ip 192.0.2.88
```

FortiGate tráfico (`traffic`):

```bash
send-fortigate-traffic --dry-run --count 3 --c2-ip 203.0.113.50
```

FortiEDR (categoría por defecto `detection`):

```bash
send-fortiedr --dry-run --count 2 --category ransomware --event-hint "Ransomware"
```

VMware vCenter (categoría por defecto `auth`):

```bash
send-vmware --dry-run --count 2 --vmware-user administrator --event-hint "login"
```

Windows (categoría por defecto `powershell`):

```bash
send-windows --dry-run --count 2 --user-samaccountname jgarcia
```

Linux (categoría por defecto `ssh`):

```bash
send-linux --dry-run --count 2 --linux-asset-ip 10.10.50.10
```

FortiMail (categoría por defecto `phishing`):

```bash
send-fortimail --dry-run --count 2
```

## Equivalencia con `fortisiem-simple-log-campaign`

| Monolito (`fortisiem_log_sender.py`) | Este repo |
|--------------------------------------|-----------|
| `--sources fortigate --category vpn` | `send-fortigate-vpn` |
| `--sources fortigate --category traffic` | `send-fortigate-traffic` |
| `--sources fortiedr --category …` | `send-fortiedr --category …` |
| `--sources vmware` | `send-vmware --category …` |
| `--sources windows` | `send-windows --category …` |
| `--sources linux` | `send-linux --category …` |
| `--sources fortimail` | `send-fortimail --category …` |
| `--campaign` / `log_repository/campaigns/` | No soportado aquí (usar el proyecto de campañas) |

## Estructura

- `src/fortisiem_send/`: paquete compartido (carga CSV, plantillas, render, syslog Scapy).
- `config/`, `log_repository/`: datos y plantillas (las carpetas `campaigns/` se ignoran al cargar plantillas).

## Proyecto Git aparte (otra cuenta u organización)

Este directorio es un **repositorio Git independiente** (`git init` en la raíz, rama `main`). No depende de que vivas dentro del repo CSIRT: puedes **moverlo o clonarlo** a otra ruta (por ejemplo `~/Projects/fortisiem-synthetic-senders`) y seguir trabajando igual.

Para publicarlo en GitHub **con otra cuenta** (no la que usas por defecto en el Mac):

1. Crea en esa cuenta un repo **vacío** (sin README) con el nombre que quieras.
2. En esta carpeta, ajusta autor si hace falta: `git config user.name "…"` y `git config user.email "…"` (local, sin `--global`, solo para este repo).
3. Añade el remoto y sube:

   ```bash
   git remote add origin https://github.com/OTRA-CUENTA/fortisiem-synthetic-senders.git
   git push -u origin main
   ```

   Con **SSH** y una clave asociada a la otra cuenta: `git remote add origin git@github.com:OTRA-CUENTA/fortisiem-synthetic-senders.git`.

Si el repo CSIRT también es Git y no quieres un “repo dentro del repo”, añade `fortisiem-synthetic-senders/` al `.gitignore` del padre o mueve esta carpeta fuera del árbol CSIRT.

## Licencia / procedencia

Lógica y plantillas derivadas del proyecto interno de campañas FortiSIEM; este repo es un troceo operativo por fuente.
