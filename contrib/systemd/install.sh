#!/usr/bin/env bash
# Install rtc2tcp-broker as a systemd service.
#
# Idempotent: safe to re-run after an upgrade. The broker binary, unit
# file, and environment file are all replaced; previously-edited values
# in /etc/rtc2tcp/broker.env are left alone.

set -euo pipefail

BIN_SRC="${BIN_SRC:-$(dirname "$0")/../../bin/rtc2tcp-broker}"
BIN_DST="${BIN_DST:-/usr/local/bin/rtc2tcp-broker}"
UNIT_SRC="$(dirname "$0")/rtc2tcp-broker.service"
UNIT_DST="/etc/systemd/system/rtc2tcp-broker.service"
ENV_SRC="$(dirname "$0")/broker.env.example"
ENV_DIR="/etc/rtc2tcp"
ENV_DST="${ENV_DIR}/broker.env"
SERVICE_USER="rtc2tcp"

err() { printf 'install: %s\n' "$*" >&2; exit 1; }
msg() { printf 'install: %s\n' "$*"; }

[[ $EUID -eq 0 ]] || err "must be run as root (try: sudo $0)"
command -v systemctl >/dev/null 2>&1 || err "systemctl not found — this script targets systemd hosts"

if [[ ! -x "$BIN_SRC" ]]; then
    err "broker binary not found at ${BIN_SRC}. Build it first (make all) or set BIN_SRC=/path/to/rtc2tcp-broker"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    msg "creating service user '${SERVICE_USER}'"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    msg "service user '${SERVICE_USER}' already exists"
fi

msg "installing binary to ${BIN_DST}"
install -o root -g root -m 0755 "$BIN_SRC" "$BIN_DST"

msg "installing unit file to ${UNIT_DST}"
install -o root -g root -m 0644 "$UNIT_SRC" "$UNIT_DST"

install -d -o root -g root -m 0755 "$ENV_DIR"
if [[ ! -f "$ENV_DST" ]]; then
    msg "installing default env file to ${ENV_DST}"
    install -o root -g root -m 0644 "$ENV_SRC" "$ENV_DST"
else
    msg "${ENV_DST} already exists — leaving your edits in place"
fi

msg "reloading systemd units"
systemctl daemon-reload

msg "enabling + (re)starting rtc2tcp-broker"
systemctl enable --now rtc2tcp-broker.service
systemctl restart rtc2tcp-broker.service

sleep 1
if systemctl is-active --quiet rtc2tcp-broker.service; then
    msg "rtc2tcp-broker is active"
else
    err "rtc2tcp-broker failed to start; check: journalctl -u rtc2tcp-broker -n 50"
fi

cat <<EOF

Installed. Next steps:

  - Review the config:              sudo \${EDITOR:-nano} ${ENV_DST}
  - Apply config changes:           sudo systemctl restart rtc2tcp-broker
  - Tail logs:                      sudo journalctl -u rtc2tcp-broker -f
  - Uninstall:                      sudo $(dirname "$0")/uninstall.sh

Reverse-proxy setup:                docs/reverse-proxy.md
EOF
