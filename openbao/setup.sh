#!/usr/bin/env bash
# One-time OpenBao setup for the demo, plus key-ring mutation helpers.
# These helpers do not reload replicas and therefore do not by themselves
# implement zero-downtime rotation.
#
#   ./openbao/setup.sh init      enable engines, mint key ring, create AppRole
#   ./openbao/setup.sh rotate    prepend a fresh sealing key, keep old for unseal
#   ./openbao/setup.sh retire    drop retired keys, keep only the current one
#
# Requires BAO_ADDR and an admin BAO_TOKEN in the environment
# (with `bao server -dev -dev-root-token-id=demo-root`: BAO_TOKEN=demo-root).
set -euo pipefail

: "${BAO_ADDR:=http://127.0.0.1:8200}"
export BAO_ADDR

KV_MOUNT="secret"
KEY_PATH="mcp/request-state-keys"
TRANSIT_KEY="mcp-request-state"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

new_key() { openssl rand -hex 32; }

case "${1:-init}" in
  init)
    # Transit key for the "keys stay in OpenBao" codec variant.
    bao secrets enable transit 2>/dev/null || true
    bao write -f "transit/keys/${TRANSIT_KEY}" > /dev/null

    # Shared AES-GCM key ring for the SDK's built-in codec. keys[0] seals,
    # every key unseals; stored comma-joined so rotation is a string prepend.
    bao kv put "${KV_MOUNT}/${KEY_PATH}" keys="$(new_key)" > /dev/null

    # AppRole so the MCP server authenticates with a scoped, expiring token
    # instead of a root token.
    bao policy write mcp-request-state "${SCRIPT_DIR}/policy.hcl" > /dev/null
    bao auth enable approle 2>/dev/null || true
    bao write auth/approle/role/mcp-server \
      token_policies=mcp-request-state token_ttl=1h token_max_ttl=4h > /dev/null

    role_id=$(bao read -field=role_id auth/approle/role/mcp-server/role-id)
    secret_id=$(bao write -f -field=secret_id auth/approle/role/mcp-server/secret-id)

    echo "OpenBao is ready. Run the MCP server with:"
    echo
    echo "  export BAO_ADDR=${BAO_ADDR}"
    echo "  export BAO_ROLE_ID=${role_id}"
    echo "  export BAO_SECRET_ID=${secret_id}"
    ;;

  rotate)
    # This immediately publishes [new,old]. Running replicas do not see it.
    # Production fleets must first stage [old,new] and reload every replica,
    # then activate [new,old] and reload every replica.
    current=$(bao kv get -field=keys "${KV_MOUNT}/${KEY_PATH}")
    bao kv put "${KV_MOUNT}/${KEY_PATH}" keys="$(new_key),${current}" > /dev/null
    bao write -f "transit/keys/${TRANSIT_KEY}/rotate" > /dev/null
    echo "Published [new,old]. Reload coordination is external to this demo."
    ;;

  retire)
    # Only run after activation has reached every replica and one full
    # request-state TTL has elapsed. Running replicas still require reloads.
    current=$(bao kv get -field=keys "${KV_MOUNT}/${KEY_PATH}")
    bao kv put "${KV_MOUNT}/${KEY_PATH}" keys="${current%%,*}" > /dev/null
    min_version=$(bao read -field=latest_version "transit/keys/${TRANSIT_KEY}")
    bao write "transit/keys/${TRANSIT_KEY}/config" min_decryption_version="${min_version}" > /dev/null
    echo "Published [current] and retired old keys. Reload replicas separately."
    ;;

  *)
    echo "usage: $0 [init|rotate|retire]" >&2
    exit 2
    ;;
esac
