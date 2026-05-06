# fortisiem-simple-log-campaign

Generador CLI de logs sinteticos para laboratorio SOC y validacion de parsing/correlacion en FortiSIEM.

## Requisitos

- Python 3.11+
- Scapy (`pip install scapy`)
- Para envio real con Scapy: ejecutar con permisos `root`/`sudo`.

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
- `--src-ip-mode random|asset`: IP atacante aleatoria o desde `assets.csv`.
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
