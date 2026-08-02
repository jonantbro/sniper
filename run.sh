#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "Create .env from .env.example and fill in your tokens first."
  exit 1
fi

if ! command -v python3.12 >/dev/null 2>&1; then
  echo "Python 3.12 not found locally. Use Railway/Render (Docker uses 3.12.8) or install Python 3.12.8."
fi

if [[ -d .venv ]]; then
  source .venv/bin/activate
elif command -v python3.12 >/dev/null 2>&1; then
  python3.12 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
fi

set -a
source .env
set +a

exec python3 bot.py
