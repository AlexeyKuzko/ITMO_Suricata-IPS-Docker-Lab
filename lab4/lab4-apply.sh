#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="$(dirname "$0")/rules/lab4.rules"

if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run as root (sudo)."
  exit 1
fi

if [[ ! -f "$RULES_FILE" ]]; then
  echo "[!] Rules file not found: $RULES_FILE"
  exit 1
fi

echo "[*] Backing up /etc/suricata/rules/local.rules to /etc/suricata/rules/local.rules.bak.$(date +%s)"
cp /etc/suricata/rules/local.rules "/etc/suricata/rules/local.rules.bak.$(date +%s)" 2>/dev/null || true

echo "[*] Installing Lab 4 rules into /etc/suricata/rules/local.rules"
mkdir -p /etc/suricata/rules
{
  echo ""
  echo "# ===== BEGIN LAB 4 RULES ====="
  cat "$RULES_FILE"
  echo "# ===== END LAB 4 RULES ====="
} >> /etc/suricata/rules/local.rules

echo "[*] Validating configuration (if suricata is installed)"
if command -v suricata >/dev/null 2>&1; then
  suricata -T -c /etc/suricata/suricata.yaml || {
    echo "[!] Suricata test (-T) failed. Please review rules."
    exit 1
  }
  echo "[*] Restarting Suricata service"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart suricata
  else
    service suricata restart || true
  fi
else
  echo "[!] Suricata binary not found; skipping validation and restart."
fi

echo "[+] Lab 4 rules installed."
