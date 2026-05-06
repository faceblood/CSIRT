# fortisiem-simple-log-campaign

Generador CLI de logs sinteticos para laboratorio SOC y validacion de parsing/correlacion en FortiSIEM.

## Requisitos

- Python 3.11+
- Dependencias Python en `requirements.txt`
- Para envio real con Scapy: ejecutar con permisos `root`/`sudo`.

## Instalacion desde GitHub

```bash
git clone git@github.com:faceblood/CSIRT.git
cd CSIRT/fortisiem-simple-log-campaign
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Prueba rapida (sin enviar):

```bash
python fortisiem_log_sender.py --campaign phishing --sources fortimail,windows,fortiedr,fortigate --count 5 --dry-run --print-raw
```

## Estructura

- `fortisiem_log_sender.py`: motor de campanas.
- `config/`: usuarios, assets, malware, C2.
- `log_repository/`: plantillas por fuente y secuencias de campana.

## Uso rapido

```bash
cd fortisiem-simple-log-campaign
python fortisiem_log_sender.py --campaign phishing --sources fortimail,windows,fortiedr,fortigate --count 20 --dry-run --print-raw
```

```bash
cd fortisiem-simple-log-campaign
sudo python fortisiem_log_sender.py --target 10.255.9.3 --campaign vmware-compromise --sources vmware,fortigate --count 50 --rate 3 --src-ip-mode random
```

## Parametros clave

- `--campaign`: phishing, ransomware, apt, bruteforce, vmware-compromise, mixed.
- `--sources`: lista CSV de fuentes.
- `--src-ip-mode random|asset|<ipv4>`: IP atacante aleatoria, desde `assets.csv` o fija (ej. `192.168.1.50`).
- `--dry-run`: no envia, solo genera.
- `--print-raw`: imprime logs sin encapsulado adicional.
- `--step-mode`: avanza paso a paso (ENTER/s/r/q).

## FortiSIEM checklist

- Verificar llegada en Event Search.
- Revisar `eventType` y que no quede como `Unknown_Event_Type`.
- Revisar campos: `srcIpAddr`, `destIpAddr`, `user`, `hostName`, `action`.
- Confirmar parsers de FortiGate, FortiMail, Linux, Windows, FortiEDR y VMware.

## Troubleshooting

- No llegan logs: revisar target/puerto/firewall.
- Error Scapy: instalar dependencia y usar `sudo`.
- Mucho EPS: bajar `--rate` y/o `--count`.
- Parser no reconoce: ajustar plantillas CSV de `log_repository/`.

## Seguridad

Uso exclusivo de laboratorio controlado. No ejecutar contra terceros.
