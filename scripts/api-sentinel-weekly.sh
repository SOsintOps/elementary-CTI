#!/bin/bash
# Weekly API sentinel — host wrapper (PLAN-API-SENTINEL-2026-08.md, stage 2).
#
# Stage 1 (deterministic): run the contract detector. Stage 2 (only on drift):
# ask claude, headless, to analyse the drift report against this repo — what
# changed, the impact on our code with file:line, and the minimum indispensable
# fix — written to a markdown report. Nothing is ever modified: the analyst
# runs in plan mode and its deliverable is the report.
#
# Runs as a systemd *user* service (linger is enabled), so no sudo anywhere.
# claude authenticates via the Max subscription's file-based credentials,
# which unlike gh's keyring survive an unattended reboot.
set -u
REPO="${SENTINEL_REPO:-$HOME/github/elementary-CTI}"
REPORTS="$REPO/.reports/api-drift"
ANALYSIS_TIMEOUT="${SENTINEL_ANALYSIS_TIMEOUT:-900}"
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"

cd "$REPO" || { echo "sentinel: repo not found at $REPO"; exit 2; }

echo "sentinel: contract check starting ($(date -Is))"
uv run python scripts/api_sentinel.py
status=$?

if [ "$status" -eq 0 ]; then
    echo "sentinel: all upstream contracts alive and unchanged"
    exit 0
fi
if [ "$status" -ne 3 ]; then
    echo "sentinel: detector failed with status $status (not a drift result)"
    exit "$status"
fi

report=$(ls -1t "$REPORTS"/*-drift.json 2>/dev/null | head -1)
if [ -z "$report" ]; then
    echo "sentinel: drift exit but no report found — inspect manually"
    exit 2
fi
analysis="${report%-drift.json}-analysis.md"
echo "sentinel: drift detected — $report"
echo "sentinel: asking claude for impact analysis (timeout ${ANALYSIS_TIMEOUT}s)"

if [ "${SENTINEL_SKIP_ANALYSIS:-0}" = "1" ]; then
    echo "sentinel: analysis skipped by SENTINEL_SKIP_ANALYSIS=1"
    exit 3
fi

timeout "$ANALYSIS_TIMEOUT" claude -p --permission-mode plan "$(cat <<PROMPT
You are running unattended inside the elementary-CTI repository as its weekly
API sentinel. The deterministic contract check found drift in upstream APIs.
The drift report is at: $report — read it first.

Produce an impact analysis in Italian, and nothing else. Do NOT modify any
file. Structure:

## Cosa è cambiato
Per ogni voce del report: il campo/endpoint e la natura del cambiamento
(rimosso/rinominato/tipo cambiato/irraggiungibile).

## Impatto sul nostro codice
Cerca nel repo i punti che consumano quei campi/endpoint (client, parser,
modelli, test) e cita file:riga. Distingui: rompe l'ingestione / degrada in
silenzio / nessun impatto.

## Modifica minima proposta
Il minimo indispensabile, come diff proposto o descrizione puntuale, SENZA
applicarlo. Se la risposta giusta è "aspettare" (es. outage upstream
temporaneo), dillo.

## Rischio se non si interviene
Una riga.
PROMPT
)" > "$analysis" 2>&1
claude_status=$?

if [ "$claude_status" -eq 0 ] && [ -s "$analysis" ]; then
    echo "sentinel: analysis written to $analysis"
    echo "sentinel: ---- first lines ----"
    head -15 "$analysis"
else
    echo "sentinel: analysis FAILED (status $claude_status) — drift report still at $report"
fi
exit 3
