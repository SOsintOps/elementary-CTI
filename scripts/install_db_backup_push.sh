#!/bin/bash
# Install the off-device DB backup push as a systemd *user* timer. No sudo:
# linger is enabled for this user. Does not touch the root-owned local backup.
set -eu
UNIT_DIR="$HOME/.config/systemd/user"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$UNIT_DIR"
cp "$REPO/deploy/systemd-user/db-backup-push.service" "$UNIT_DIR/"
cp "$REPO/deploy/systemd-user/db-backup-push.timer" "$UNIT_DIR/"
systemctl --user daemon-reload
systemctl --user enable --now db-backup-push.timer
systemctl --user list-timers db-backup-push.timer --no-pager
echo "Installed. Manual run: systemctl --user start db-backup-push.service"
echo "Logs:       journalctl --user -u db-backup-push.service"
