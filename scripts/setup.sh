#!/usr/bin/env bash
# ---------------------------------------------------------------
# SentinelX — one-time setup script
# Runs automatically on first boot / after a GitHub import.
# Safe to re-run: pnpm install and db push are both idempotent.
# ---------------------------------------------------------------
set -euo pipefail

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   SentinelX — environment setup      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Install / restore node_modules ──────────────────────────
echo "▶ Installing dependencies (pnpm install)…"
pnpm install --frozen-lockfile
echo "  ✓ Dependencies ready"

# ── 2. Push database schema ────────────────────────────────────
echo "▶ Pushing database schema…"
pnpm --filter @workspace/db run push
echo "  ✓ Database schema up-to-date"

echo ""
echo "  Setup complete — starting services…"
echo ""
