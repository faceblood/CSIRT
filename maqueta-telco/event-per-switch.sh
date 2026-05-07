#!/bin/bash

CSV="fortiswitch_inventory_200.csv"
SCRIPT="fortiswitch_portsecurity_scapy_csv.py"
VENV_PYTHON=".venv/bin/python"

TARGET="10.255.9.3"
EVENT="dot1x_fail"
INTERVAL="0.2"

if [ ! -f "$CSV" ]; then
  echo "[ERROR] No existe el CSV: $CSV"
  exit 1
fi

if [ ! -f "$SCRIPT" ]; then
  echo "[ERROR] No existe el script: $SCRIPT"
  exit 1
fi

echo "[INFO] Lanzando 1 evento '$EVENT' por cada FortiSwitch del CSV..."
echo

tail -n +2 "$CSV" | while IFS=, read -r name serial src_ip
do
  name=$(echo "$name" | tr -d '\r"')
  serial=$(echo "$serial" | tr -d '\r"')
  src_ip=$(echo "$src_ip" | tr -d '\r"')

  if [ -z "$name" ] || [ -z "$serial" ] || [ -z "$src_ip" ]; then
    continue
  fi

  echo "[SEND] switch=$name serial=$serial src_ip=$src_ip event=$EVENT"

  sudo "$VENV_PYTHON" "$SCRIPT" \
    --inventory-csv "$CSV" \
    --target "$TARGET" \
    --switch-name "$name" \
    --src-ip "$src_ip" \
    --event "$EVENT"

  sleep "$INTERVAL"
done

echo
echo "[OK] Finalizado. Se lanzó 1 evento por cada switch del CSV."
