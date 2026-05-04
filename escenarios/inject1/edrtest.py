#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import random

SIEM_IP = "10.255.9.3"
SIEM_PORT = 514

REPORTING_IP = "10.255.9.202"
REPORTING_HOST = "loggen-edr01"


def syslog_ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


message = (
    f"<133>{syslog_ts()} {REPORTING_HOST} "
    "CEF:0|Fortinet|FortiEDR|7.2.3|300101|Privileged Logon|6|"
    "cs1Label=Organization cs1=1 "
    "cs2Label=OrganizationId cs2=1 "
    "eventid=300101 "
    "cs6Label=RawDataId cs6=123456 "
    "shost=JUMP-WIN-01 "
    "cs5Label=DeviceState cs5=Running "
    "cs3Label=OS cs3=Windows Server 2019 "
    "fname=lsass.exe "
    "filePath=C:\\\\Windows\\\\System32\\\\lsass.exe "
    "Classification=Suspicious "
    "dst=10.0.40.22 "
    "deviceCustomDate1Label=FirstSeen "
    "deviceCustomDate1=02-05-2026, 12:00:00 "
    "deviceCustomDate2Label=LastSeen "
    "deviceCustomDate2=02-05-2026, 12:00:00 "
    "act=Detected "
    "cnt=1 "
    "AppSigned=yes "
    "reason=Privileged account logon observed outside expected pattern "
    "suser=proveedor_soporte "
    "deviceTranslatedAddress=10.0.40.22 "
    "threatAttackID=Valid Accounts "
    "frameworkName=MITRE ATT&CK "
    "MitreTags=T1078 "
    "EventTarget=JUMP-WIN-01"
)

packet = (
    IP(src=REPORTING_IP, dst=SIEM_IP)
    / UDP(sport=random.randint(20000, 65000), dport=SIEM_PORT)
    / Raw(load=message.encode("utf-8"))
)

send(packet, verbose=1)

print(f"Enviado evento FortiEDR CEF desde {REPORTING_IP} hacia {SIEM_IP}:{SIEM_PORT}/UDP")
