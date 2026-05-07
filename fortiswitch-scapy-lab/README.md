# FortiSwitch Scapy Lab

Script standalone para enviar eventos FortiSwitch (UDP syslog-like) hacia FortiSIEM usando Scapy.

## Requisitos

- Python 3.9+
- Scapy
- Permisos admin/root (normalmente necesarios para `send()` de Scapy)

## Instalacion

```bash
python3 -m pip install scapy
```

## Uso rapido

```bash
cd /Users/jojsemanuelfrancesamoros/Documents/CSIRT/fortiswitch-scapy-lab
sudo python3 fortiswitch_scapy_sender.py \
  --dst-ip 10.20.30.40 \
  --dst-port 514 \
  --template admin_login_failed \
  --count 30 \
  --delay 0.15
```

## Templates disponibles

- `admin_login_success`
- `admin_login_failed`
- `port_down`
- `stp_root_guard`

## Nota

Los mensajes incluyen `device_id` y `log_id` para encajar con el parser FortiSwitch compartido.
