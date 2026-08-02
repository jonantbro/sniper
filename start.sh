#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Render sometimes skips build deps — install at startup so imports always work.
python3 -m pip install --quiet --disable-pip-version-check -r requirements.txt

exec python3 bot.py
