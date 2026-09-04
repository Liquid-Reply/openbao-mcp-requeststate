# Securing MCP `requestState` with OpenBao

Companion code for the article [Securing requestState for Multi-Round Trip
Requests with OpenBao](https://liquidreply.net/news/securing-requeststate-with-openbao) — a follow-up to
[Designing RequestState for Multi-Round Trip Requests](https://aaif.io/blog/designing-requeststate-for-multi-round-trip-requests).

An MCP server (`storage-janitor`, spec **2026-07-28**) exposes one destructive
tool, `purge_objects`, that spans two round trips: round 1 returns an
`InputRequiredResult` (an elicitation asking for confirmation plus a sealed
`requestState`); round 2 verifies the echoed state and purges. OpenBao supplies
the three things the SDK's built-in request-state protection cannot:

| Property | OpenBao feature | Code |
|---|---|---|
| One startup sealing key ring for all stateless replicas | KV v2 | `load_key_ring()` in [baostate.py](baostate.py) |
| AEAD keys that never enter application memory | Transit engine | `TransitCodec` in [baostate.py](baostate.py) |
| At-most-once redemption of a destructive authorization | Response wrapping | `SingleUse` in [baostate.py](baostate.py) |

Integrity, confidentiality, expiry, request binding, audience, and principal
binding are enforced by the MCP Python SDK's `RequestStateBoundary`
(`mcp==2.0.0b1`); this repo plugs OpenBao into its `RequestStateSecurity`
hook rather than reinventing the envelope.

## Run it

Prerequisites: [uv](https://docs.astral.sh/uv/) and an OpenBao dev server —
either `brew install openbao` or the container in [compose.yaml](compose.yaml):

```bash
bao server -dev -dev-root-token-id=demo-root   # or: docker compose up -d
```

Then:

```bash
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=demo-root
./run_demo.sh
```

`run_demo.sh` configures OpenBao (Transit key, key ring, AppRole with
[openbao/policy.hcl](openbao/policy.hcl)), starts three replicas —
`:8001`/`:8002` sharing the KV key ring, `:8003` on the Transit codec — and
runs [demo.py](demo.py):

```text
[1] Official MCP client, auto-driven rounds (replica :8001)
[2] Round 1 on replica A, round 2 on replica B (shared key ring)
[3] Transit-codec replica: the sealed state IS OpenBao ciphertext
[4] Attacks against one legitimately issued requestState
    tamper one byte      -> error -32602: Invalid or expired requestState
    swap args to secrets/ -> error -32602: Invalid or expired requestState
    honest confirmation  -> Purged 3 object(s): ...
    replay same state    -> REFUSED: this confirmation was already used ...
```

The demo loads its shared ring at process startup; it does not implement live
reloads or zero-downtime rotation. Production rotation must stage `[old,new]`
and reload every replica, activate `[new,old]` and reload again, wait one full
state TTL after activation completes, then retire to `[new]` and reload again.
The helpers below only mutate KV (and the Transit key); they do not coordinate
replica reloads:

```bash
./openbao/setup.sh rotate   # immediately writes [new,old]
./openbao/setup.sh retire   # drops old keys
```

## Files

- [server.py](server.py) — the MCP server and the two-round tool
- [baostate.py](baostate.py) — the three OpenBao building blocks
- [demo.py](demo.py) — happy path, cross-replica hand-off, and the attacks
- [openbao/setup.sh](openbao/setup.sh) — engines, key ring, AppRole, rotation
- [openbao/policy.hcl](openbao/policy.hcl) — least-privilege policy for the server

## Beyond the demo

The dev setup deliberately skips what production must not: TLS on
`BAO_ADDR`, durable storage and auto-unseal for OpenBao itself, an audit
device (every seal-key read, transit call, and unwrap then leaves a log
line), and secret-id delivery for AppRole. With OAuth on the MCP server, the
SDK additionally binds each `requestState` to the authenticated principal —
no extra code here.

The demo also uses one combined AppRole for convenience. Production key-ring
and Transit deployments should use separate identities and policies so a
Transit-only server cannot read the KV key ring. Likewise, response wrapping
guarantees at-most-once authorization redemption, not atomic execution: a
crash after unwrap can leave the operation incomplete while making the token
unusable. Use idempotent operations, a durable operation ledger, or
transactional coupling when stronger execution guarantees are required.
