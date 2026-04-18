#!/usr/bin/env bash
# Remove rtc2tcp-broker systemd service, binary, unit, and (optionally)
# its config and service user.

set -euo pipefail

BIN_DST="${BIN_DST:-/usr/local/bin/rtc2tcp-broker}"
UNIT_DST="/etc/systemd/system/rtc2tcp-broker.service"
ENV_DIR="/etc/rtc2tcp"
ENV_DST="${ENV_DIR}/broker.env"
SERVICE_USER="rtc2tcp"
PURGE="${PURGE:-0}"   # set PURGE=1 to also remove the env file and user

err() { printf 'uninstall: %s\n' "$*" >&2; exit 1; }
msg() { printf 'uninstall: %s\n' "$*"; }

[[ $EUID -eq 0 ]] || err "must be run as root (try: sudo $0)"
command -v systemctl >/dev/null 2>&1 || err "systemctl not found"

if systemctl list-unit-files rtc2tcp-broker.service >/dev/null 2>&1; then
    msg "stopping + disabling rtc2tcp-broker"
    systemctl disable --now rtc2tcp-broker.service 2>/dev/null || true
fi

if [[ -f "$UNIT_DST" ]]; then
    msg "removing unit file ${UNIT_DST}"
    rm -f "$UNIT_DST"
fi

if [[ -f "$BIN_DST" ]]; then
    msg "removing binary ${BIN_DST}"
    rm -f "$BIN_DST"
fi

systemctl daemon-reload

if [[ "$PURGE" == "1" ]]; then
    if [[ -d "$ENV_DIR" ]]; then
        msg "purging config directory ${ENV_DIR}"
        rm -rf "$ENV_DIR"
    fi
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        msg "removing service user '${SERVICE_USER}'"
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi
else
    if [[ -f "$ENV_DST" ]]; then
        msg "config preserved at ${ENV_DST} (re-run with PURGE=1 to delete)"
    fi
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        msg "service user '${SERVICE_USER}' preserved (re-run with PURGE=1 to delete)"
    fi
fi

msg "done"
