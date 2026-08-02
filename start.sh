#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Use a venv — Render's Python blocks global pip installs (PEP 668).
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python bot.py
