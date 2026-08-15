#!/bin/bash
# Off-device DB backup → the working repo's `db-backup` branch on GitHub.
# See .planning/PLAN-DB-OFFSITE-2026-08.md.
#
# The local backup (elementarycti-backup.timer) is the primary and always runs;
# this is the off-device safety net. It force-pushes a FRESH single-commit
# history to the `db-backup` branch each run, so only the latest dump(s) are
# kept and the branch never grows — main is never touched.
#
# Auth is **SSH**, deliberately. It used to be the HTTPS remote through gh's
# credential helper, and that made every unattended run depend on an unlocked
# keyring — a fragility this file already warned about. It then went further and
# broke outright: the host's gh token expired, and from the 12th to the 15th of
# August 2026 the push failed every night. An SSH key needs no session, no
# keyring and no token refresh, and it survives a reboot.
#
# The failure was invisible for three days, which was worse than the failure.
# This script shouts and exits non-zero, but its stdout goes to the *user*
# journal, which this host does not retain, and a oneshot unit's failed state
# lives in memory and was erased by the next reboot. So the outcome now lands in
# two places that outlive both: a log file beside the local backup's, and a
# `source_health` row the platform's own pipeline page reads.
set -u
# Deployment-specific settings live outside the repository, because this file
# ships in the public distribution and the destination of somebody's database
# dump is theirs, not ours. An earlier version defaulted the remote to the
# maintainer's own private repo, which would have had every self-hoster's backup
# aiming at it.
CONFIG_FILE="${DB_BACKUP_CONFIG:-$HOME/.config/elementary-cti/db-backup.env}"
# shellcheck source=/dev/null
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

BACKUP_DIR="${SENTINEL_BACKUP_DIR:-$HOME/backups/elementary-cti}"
REMOTE="${DB_BACKUP_REMOTE:-}"
BRANCH="db-backup"
LOGFILE="${DB_BACKUP_LOG:-$BACKUP_DIR/push.log}"
DB_CONTAINER="${DB_BACKUP_APP_CONTAINER:-elementary-cti-web-1}"
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"

mkdir -p "$(dirname "$LOGFILE")"
log() { echo "$(date -Is) $*" | tee -a "$LOGFILE"; }

if [ -z "$REMOTE" ]; then
    log "no destination configured. Set DB_BACKUP_REMOTE in $CONFIG_FILE (for example DB_BACKUP_REMOTE=git@github.com:you/your-private-repo.git). Refusing to guess where a database dump should go."
    exit 5
fi

# Record the outcome where a person will see it: the platform's own health
# table, via the app container, which already holds the production database URL.
# Best effort by design — a database that cannot be reached must not turn a
# successful push into a failed run, so this never changes the exit code.
record() {
    local outcome="$1" detail="$2" size="${3:-}"
    if ! command -v docker >/dev/null 2>&1 ||
        ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${DB_CONTAINER}$"; then
        log "note: ${DB_CONTAINER} not running, outcome not recorded in source_health"
        return 0
    fi
    local args=(--record-backup-push "$outcome" --detail "$detail")
    [ -n "$size" ] && args+=(--bytes "$size")
    if ! docker exec "$DB_CONTAINER" uv run python -m pestilentia.pipeline.health \
        "${args[@]}" >>"$LOGFILE" 2>&1; then
        log "note: could not record the outcome in source_health"
    fi
}

latest_daily=$(ls -1t "$BACKUP_DIR"/daily/*.dump 2>/dev/null | head -1)
if [ -z "$latest_daily" ]; then
    log "no dump found in $BACKUP_DIR/daily — nothing to push (run the local backup first)"
    record failed "no dump found in $BACKUP_DIR/daily"
    exit 2
fi
latest_weekly=$(ls -1t "$BACKUP_DIR"/weekly/*.dump 2>/dev/null | head -1)

# Refuse to ship a corrupt dump. pg_restore is not on the host (it lives in the
# db container), so verify there: host binary if present, else pipe the dump
# into the running container, else skip with a note — the local backup already
# verified before rotating, so a skip degrades to trusting that, not to blindly
# shipping garbage.
verify_dump() {
    local dump="$1"
    if command -v pg_restore >/dev/null 2>&1; then
        pg_restore --list "$dump" >/dev/null 2>&1
        return
    fi
    # No host pg_restore; verify inside the db container. Custom-format archives
    # are not seekable over a pipe (`--list -` fails), so copy the file in,
    # list it, and clean up.
    if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^elementary-cti-db-1$'; then
        local tmp="/tmp/verify_$$.dump" rc
        docker cp "$dump" "elementary-cti-db-1:$tmp" >/dev/null 2>&1 || return 1
        docker exec elementary-cti-db-1 pg_restore --list "$tmp" >/dev/null 2>&1
        rc=$?
        docker exec elementary-cti-db-1 rm -f "$tmp" >/dev/null 2>&1
        return $rc
    fi
    log "pg_restore unavailable on host and container — trusting the local backup's own verification"
    return 0
}
if ! verify_dump "$latest_daily"; then
    log "latest dump failed pg_restore --list verification: $latest_daily — not pushing"
    record failed "dump failed pg_restore --list verification"
    exit 3
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/db-backup"
cp "$latest_daily" "$work/db-backup/"
[ -n "$latest_weekly" ] && [ "$latest_weekly" != "$latest_daily" ] && cp "$latest_weekly" "$work/db-backup/"

# A fresh single-commit history: no accumulation, branch size ~= one or two dumps.
cat > "$work/db-backup/README.md" <<EOF
# Off-device database backup

Machine-written by \`scripts/push_db_backup.sh\`. This branch is **reset on
every run** — its history is intentionally a single commit holding only the
latest PostgreSQL custom-format dump(s). Do not merge it into \`main\`.

Restore: \`pg_restore --clean --no-owner -d <target> <file>.dump\`
EOF

cd "$work" || exit 1
git init -q -b "$BRANCH"
git -c user.name="${DB_BACKUP_AUTHOR_NAME:-elementary-cti}" -c user.email="${DB_BACKUP_AUTHOR_EMAIL:-backup@localhost}" \
    add db-backup >/dev/null 2>&1
git -c user.name="${DB_BACKUP_AUTHOR_NAME:-elementary-cti}" -c user.email="${DB_BACKUP_AUTHOR_EMAIL:-backup@localhost}" \
    commit -q -m "db backup $(basename "$latest_daily")"

log "pushing $(basename "$latest_daily") ($(du -h "$latest_daily" | cut -f1)) to $BRANCH"
if git push -q --force "$REMOTE" "$BRANCH" 2>"$work/push.err"; then
    log "off-device backup pushed to $BRANCH"
    record ok "pushed $(basename "$latest_daily")" "$(stat -c %s "$latest_daily" 2>/dev/null)"
    exit 0
fi

err=$(cat "$work/push.err")
case "$err" in
    *"could not read Username"*|*"Authentication"*|*"Permission denied"*|*"publickey"*|*"denied"*)
        log "PUSH FAILED — auth. The remote is SSH: check that this host's key is still accepted (ssh -T git@github.com). The local backup is unaffected. Detail: $err"
        ;;
    *)
        log "PUSH FAILED: $err"
        ;;
esac
record failed "$err"
exit 4
