#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send
from datetime import datetime
import time
import random

FORTISIEM_IP = "10.255.9.3"
FORTISIEM_PORT = 514

DEVICES = [
    {
        "ip": "10.0.20.101",
        "hostname": "fortigate-fw01",
        "logs": [
            'firewall: action=deny srcip=185.231.88.45 dstip=10.0.10.20 dstport=22 proto=tcp msg="External SSH scan"',
            'firewall: action=accept srcip=10.0.10.30 dstip=45.83.120.10 dstport=443 proto=tcp sentbyte=52428800 msg="Possible data exfiltration"',
        ],
    },
    {
        "ip": "10.0.20.102",
        "hostname": "linux-web01",
        "logs": [
            'sshd[2241]: Failed password for invalid user admin from 185.231.88.45 port 50101 ssh2',
            'sshd[2241]: Accepted password for j.garcia from 185.231.88.45 port 50122 ssh2',
            'sudo: j.garcia : TTY=pts/0 ; PWD=/home/j.garcia ; USER=root ; COMMAND=/bin/bash',
        ],
    },
    {
        "ip": "10.0.20.103",
        "hostname": "proxy01",
        "logs": [
            'proxy: action=allowed srcip=10.0.10.30 dstip=45.83.120.10 url="http://45.83.120.10/checkin" method=GET user=j.garcia msg="Periodic C2 beacon"',
            'proxy: action=allowed srcip=10.0.10.30 dstip=45.83.120.10 url="https://45.83.120.10/upload" method=POST user=j.garcia bytes_out=52428800 msg="Large outbound upload"',
        ],
    },
    {
        "ip": "10.0.20.104",
        "hostname": "windows-wks01",
        "logs": [
            'windows_security: EventID=4625 AccountName=administrator SourceAddress=10.0.10.20 LogonType=3 FailureReason="Bad password"',
            'windows_security: EventID=4624 AccountName=j.garcia SourceAddress=10.0.10.20 LogonType=3 LogonProcess=NtLmSsp',
            'sysmon: EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell -nop -w hidden -enc <redacted>" User="corp\\j.garcia"',
        ],
    },
]

def send_syslog(spoofed_ip, hostname, message):
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    payload = f"<134>{timestamp} {hostname} {message}"

    packet = (
        IP(src=spoofed_ip, dst=FORTISIEM_IP)
        / UDP(sport=random.randint(20000, 65000), dport=FORTISIEM_PORT)
        / Raw(load=payload)
    )

    send(packet, verbose=False)
    print(f"[+] {hostname} / {spoofed_ip} -> {message}")

for device in DEVICES:
    for log in device["logs"]:
        send_syslog(device["ip"], device["hostname"], log)
        time.sleep(1)
