#!/usr/bin/env bash
set -euo pipefail
REPO="${REPO:-$HOME/CSIRT/fortisiem-synthetic-senders}"
cd "$REPO"
TARGET="${TARGET:-10.255.9.3}"
VPN_CLIENT="${VPN_CLIENT:-198.51.100.50}"
REPORTING="${REPORTING:-192.0.2.10}"

python3 -m fortisiem_send.cli.fortigate_vpn --target "$TARGET" "${DRY[@]}" \
  --vpn-remote-ip "$VPN_CLIENT" --syslog-src-ip "$REPORTING" \
  --event-hint "SSLVPN login success" --count 2 --rate 2
python3 -m fortisiem_send.cli.fortigate_vpn --target "$TARGET" "${DRY[@]}" \
  --vpn-remote-ip "$VPN_CLIENT" --syslog-src-ip "$REPORTING" \
  --event-hint "SSLVPN tunnel up" --count 2 --rate 2

python3 -m fortisiem_send.cli.fortigate_traffic --target "$TARGET" "${DRY[@]}" \
  --syslog-src-ip "$REPORTING" --attacker-ip "$VPN_CLIENT" --c2-ip "203.0.113.50" \
  --event-hint "outbound" --count 60 --rate 5

python3 -m fortisiem_send.cli.fortigate_vpn --target "$TARGET" "${DRY[@]}" \
  --vpn-remote-ip "$VPN_CLIENT" --syslog-src-ip "$REPORTING" \
  --event-hint "SSLVPN tunnel down" --count 2 --rate 2
python3 -m fortisiem_send.cli.fortigate_vpn --target "$TARGET" "${DRY[@]}" \
  --vpn-remote-ip "$VPN_CLIENT" --syslog-src-ip "$REPORTING" \
  --event-hint "SSLVPN logout" --count 1 --rate 2
