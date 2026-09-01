#!/usr/bin/env bash
# End-to-end demo: configure OpenBao, start three replicas, run demo.py.
# Prereqs: an OpenBao dev server (see README), BAO_ADDR + admin BAO_TOKEN set,
# and `uv` on PATH.
set -euo pipefail
cd "$(dirname "$0")"

: "${BAO_ADDR:=http://127.0.0.1:8200}"
export BAO_ADDR

eval "$(./openbao/setup.sh init | grep '^  export' )"

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

PORT=8001 uv run python server.py & pids+=($!)
PORT=8002 uv run python server.py & pids+=($!)
PORT=8003 STATE_BACKEND=transit uv run python server.py & pids+=($!)

sleep 3
uv run python demo.py
