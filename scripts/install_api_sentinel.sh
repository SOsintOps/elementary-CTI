#!/bin/bash
# Install the weekly API sentinel as systemd *user* units. No sudo: linger is
# already enabled for this user (loginctl show-user $USER -p Linger).
set -eu
UNIT_DIR="$HOME/.config/systemd/user"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$UNIT_DIR"
cp "$REPO/deploy/systemd-user/api-sentinel.service" "$UNIT_DIR/"
cp "$REPO/deploy/systemd-user/api-sentinel.timer" "$UNIT_DIR/"
systemctl --user daemon-reload
systemctl --user enable --now api-sentinel.timer
systemctl --user list-timers api-sentinel.timer --no-pager
echo "Installed. Manual run: systemctl --user start api-sentinel.service"
echo "Logs:       journalctl --user -u api-sentinel.service"
