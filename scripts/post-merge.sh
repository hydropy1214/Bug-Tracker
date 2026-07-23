#!/usr/bin/env bash
set -e
echo "[post-merge] Installing dependencies..."
pnpm install --frozen-lockfile
echo "[post-merge] Pushing database schema..."
pnpm --filter @workspace/db run push
echo "[post-merge] Done."
