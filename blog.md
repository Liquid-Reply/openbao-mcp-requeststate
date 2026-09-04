# Securing requestState with OpenBao

A follow-up to our article at the AAIF Blog Designing RequestState for Multi-Round Trip Requests. All code in this post is from the companion repository `openbao-mcp-requeststate` and runs against a real OpenBao and the official MCP Python SDK.

The most common question after our article on the AAIF blog was some variant of: "fine, requestState must be integrity-protected, encrypted, bound, expired, and replay-controlled, but with what?" The MCP 2026-07-28 specification is not very descriptive on infrastructure. It tells you a server MUST treat `requestState` as attacker-controlled input and MUST protect its integrity when it influences authorization, resource access, or business logic. It does not tell you where the keys live, how twelve stateless replicas agree on them, or what enforces "this confirmation can be used at most once."

This post answers that question with OpenBao. OpenBao is an open-source, community-driven secrets manager. Not because a secrets manager is the only answer, but because it turns out to be a surprisingly precise one: each of the three gaps the SDK leaves open maps onto an OpenBao feature.

Where the SDK already ends the discussion

Before adding infrastructure, I want to be clear about what the SDK already gives you. The behavior described here is that of the repository's pinned official Python SDK, `mcp==2.0.0b1`, a beta release targeting MCP 2026-07-28; later SDK versions may differ. On MCPServer, requestState protection is on by default. Your handler writes plaintext to ctx.request_state and reads plaintext back; the SDK seals the token on the way out and verifies it on the way in, so the wire only ever carries an opaque, encrypted, authenticated blob. 

The seal buys more than integrity: each token is bound to a time window (600 seconds by default, re-stamped every round), to the originating request (method, tool or prompt name, and a digest of the arguments), and, when the request carries an OAuth token the SDK validated, to the authenticated principal. Every inbound requestState on the three MRTR carriers (tools/call, prompts/get, resources/read) is checked before your handler runs, including one arriving at a handler that never mints state. Tampered, expired, replayed against a different tool, lifted from a different user, or sealed under a key this instance doesn't hold: all of it gets the same frozen -32602 "Invalid or expired requestState". One message for every cause, so the wire never says which check failed. The real reason goes to your log.

One caveat, and it's the reason the rest of this post exists: that default key is minted at process start and dies with the process. Single stdio server, fine. Two replicas behind a load balancer, or one rolling restart, and every in-flight retry gets that same -32602.

The envelope claims cover most of the checklist from my last post:

Claim

Enforces

`iat` / `exp`

expiry window (default TTL 600 s)

`m`, `t`, `a` 

binding to method, tool/resource, and a digest of the salient arguments

`aud`

audience — state minted by another service on the same keys is rejected 

`p` 

the authenticated principal, when the server runs with OAuth

Your tool never sees a token, only the plaintext it minted. The interesting question is what the envelope cannot do and all three answers are operational, not cryptographic.

It cannot distribute its own key. The SDK's default policy is RequestStateSecurity.ephemeral(): a random key generated at process start. Recall why MRTR exists at all; it externalizes resumption state so that stateless, horizontally scaled servers can run interactive flows without sticky routing. Under an ephemeral key, that promise can break: the load balancer sends round 2 to replica B, replica B has a different key and a perfectly honest client gets Invalid or expired requestState. A restart mid-conversation does the same to every in-flight round. The SDK's own docstring says it plainly: multi-instance deployments must share keys. Sharing keys is a secrets-management problem.

It cannot satisfy a key-custody mandate. The built-in codec holds AES key material in application memory. Plenty of environments are fine with that; some are not allowed to be.

It cannot make anything single-use. This is the subtle one, clearly stated in the specs: principal binding, TTL and request binding bound the replay window BUT "do not by themselves guarantee single-use." Where a requestState must be consumed at most once, one-time redemptions being the canonical case, the server MUST enforce that invariant server-side. A sealed, bound, unexpired confirmation to delete files is still a valid confirmation to delete files the second time it is presented. At-most-once is in the end a state problem and no amount of cryptography on a stateless token solves it.

The Example: one destructive tool, two round trips

The repo runs storage-janitor, an MCP server with a single tool. purge_objects(prefix) scans a bucket, comes back with an elicitation like "Purge 3 object(s) under 'logs/'?" and completes on the retry:

https://liquidreply.net/storage/media/general/mermai-blog.png#asset:25369@1:alt

Round 1 the server returns early instead of reaching back:

```json
{
 "resultType": "input_required",
 "inputRequests": {
   "confirm_purge": {
     "method": "elicitation/create",
     "params": {
       "mode": "form",
       "message": "Purge 3 object(s) under 'logs/'? logs/2026-08-01.log, …",
       "requestedSchema": { "…": "…" }
      }
    }
  },
 "requestState": "v1.XqqHE5Lx3YgnDaFdT4-fQFISc08pagH…"
}
```

That `v1.…` blob is the SDK's sealed envelope. What the tool actually put inside it is two fields: {"step": "confirm", "claim": "s.lfT6gNneH4…"}; and that second field is where OpenBao comes into play. 

This opens up three integrations, in increasing order of how opinionated they are.

1. A shared startup key ring, distributed by OpenBao

The default integration keeps the SDK's local AES-GCM sealing and moves only key management to OpenBao. Every replica fetches the same ring from KV at startup and hands it to the boundary:

```python
def load_key_ring(bao: OpenBao, path: str = "mcp/request-state-keys") -> list[bytes]:
   """Ring order matters to the SDK: keys[0] seals, all keys unseal."""
    return [bytes.fromhex(k) for k in bao.kv_get(path)["keys"].split(",")]

security = RequestStateSecurity(keys=load_key_ring(bao), ttl=120)
mcp = MCPServer("storage-janitor", request_state_security=security)
```

That is the entire fix for gap 1. Round 1 can land on replica A and round 2 on replica B; the demo shows this behavior and B completes a purge it never planned. Restarts stop invalidating in-flight rounds, because the key outlives the process.

The demo establishes shared startup keys: replicas started with the same ring can exchange in-flight state. It does not implement live key reloads or zero-downtime rotation. In production, rotation requires coordinated ring updates and replica reloads:

```bash
# 1. Stage [old, new], then reload every replica.
# 2. Activate [new, old], then reload every replica.
# 3. After the last replica stops sealing with old, wait at least one full TTL.
# 4. Retire to [new], then reload every replica.
```

Distribute the new key for unsealing first (`keys=[old, new]`) and only start sealing with it (`keys=[new, old]`) once every replica has reloaded. Otherwise a not-yet-reloaded replica rejects state minted by an already-rotated one. The repository's `setup.sh rotate` and `retire` commands only edit KV (and rotate Transit); they do not orchestrate these reloads. The TTL you chose for the envelope sets the minimum retirement delay after activation has completed.

For convenience, the demo uses one AppRole policy that can read the local-codec ring, use Transit, and wrap and unwrap. This means a compromised Transit-mode demo server could also retrieve the local-codec ring, although it still cannot export the Transit key or write the ring. A production key-custody boundary should use separate AppRoles and policies: key-ring deployments may read KV, while Transit deployments may only encrypt and decrypt with Transit. Grant wrapping permissions separately where they are needed.

2. Transit: when the key must not exist in your process at all

If policy says AEAD keys never live in application memory, invert the arrangement: leave key management and the cryptography in OpenBao. The SDK makes this a ten-line code, because `RequestStateSecurity` accepts any object with `seal`/`unseal`:

```python
class TransitCodec:
    def __init__(self, bao: OpenBao, key: str = "mcp-request-state") -> None:
        self._bao, self._key = bao, key

    def seal(self, payload: bytes) -> str:
        return self._bao.transit_encrypt(self._key, payload)

    def unseal(self, token: str) -> bytes:
        if not token.startswith("vault:"):
            raise InvalidRequestState("malformed")
        return self._bao.transit_decrypt(self._key, token)

security = RequestStateSecurity(codec=TransitCodec(bao), ttl=120)
```


The SDK still mints and verifies every claim; OpenBao only performs the AEAD. The client-visible `requestState` becomes literal Transit ciphertext `vault:v2:73oTCJZRcrTdFBTK…`, and rotation collapses into `transit/keys/<name>/rotate` plus `min_decryption_version`. When an OpenBao audit device is enabled, every seal and unseal is recorded in its audit log.

3. Response wrapping: at-most-once

Gap 3 needs server-side state with unusual properties: short-lived, redeemable at most once, tamper-evident, and auditable when an audit device is enabled. So here we are again with OpenBao and its response wrapping. Wrap a payload and OpenBao stores it server-side behind a short-lived, single-use wrapping token. A successful unwrap consumes that token; subsequent unwraps fail.

So the tool parks the destructive plan in OpenBao and puts only the claim check into `requestState`:

```python
# Round 1: plan stays server-side behind a single-use claim
claim = single_use.issue({"op": "purge", "files": doomed})   # sys/wrapping/wrap, TTL 120s
return InputRequiredResult(
   input_requests={"confirm_purge": ElicitRequest(...)},
   request_state=json.dumps({"step": "confirm", "claim": claim}),
)

# Round 2: the envelope already proved the state is ours, fresh, and
# bound to these arguments, now redeem the authorization and act
try:
    plan = single_use.redeem(claim)          # sys/wrapping/unwrap succeeds once, ever
except AlreadyRedeemed:
    return "REFUSED: this confirmation was already used or has expired. Start over."
```

In my AAIF blog where I mentioned the value-versus-reference choice: with this approach it refuses to choose. The resumption context travels by value inside the sealed envelope; the dangerous part, the authoritative list of what gets deleted, travels by reference and never crosses the trust boundary at all. The client carries a capability it cannot read (the envelope is encrypted, so the claim token never appears in client logs), cannot alter and cannot use twice. If the user declines, the tool burns the token immediately rather than letting it age out.

This is at-most-once redemption of the authorization, not atomic or exactly-once execution of the purge. Unwrap and deletion are separate operations: if the server fails after unwrap but before or during deletion, a retry is refused even though deletion may be incomplete. Stronger execution guarantees require an idempotent deletion operation, a durable operation ledger, or transactional coupling between redemption and execution.

What the attacks look like

`run_demo.sh` starts OpenBao-configured replicas and runs four moves against one legitimately issued `requestState`:

```text
tamper one byte     -> error -32602: Invalid or expired requestState
swap args to secrets/ -> error -32602: Invalid or expired requestState
honest confirmation -> Purged 3 object(s): logs/2026-08-01.log, …
replay same state   -> REFUSED: this confirmation was already used or has expired.
```

Each line is a different layer doing its job:

The tampered token dies in the codec (GCM tag)

the re-targeted one dies in the claims check (args digest; a confirmation for `logs/` is not a confirmation for `secrets/`)

the replay survives both, because it is a genuinely valid token and dies at the only layer that can kill it, the single-use redemption in OpenBao.

The SDK logs the boundary's real rejection reason server-side while the wire sees only the frozen message. When an OpenBao audit device is enabled, a failed unwrap also leaves an audit record worth alerting on. That failure alone does not distinguish a replayed token from an expired, revoked, or unknown token, so diagnosis needs the surrounding audit context.

Production notes

The demo runs OpenBao in dev mode; the distance to production is the usual checklist: TLS on `BAO_ADDR`, durable storage and auto-unseal, an audit device enabled and real secret-id delivery for AppRole. Two knobs deserve actual thought. The envelope TTL is a UX decision disguised as a security decision; it must cover honest user think time on the elicitation and 600 seconds of default generosity may be more resumption capability than a destructive tool wants; the demo runs both TTLs at 120 s. And if your server terminates OAuth, the SDK binds every envelope to the authenticated principal with zero additional code, so the cross-user replay dies in the boundary before your tool runs.

The pattern itself is small: keep the SDK's envelope; give it keys from a system whose job is keys; and put authorization that must be redeemed at most once behind a server-side redemption primitive. Couple that redemption to idempotent or durably tracked execution when the operation itself needs a stronger guarantee. `requestState` is a bearer capability handed to an untrusted party. 

Treat it with token discipline and give that discipline infrastructure.
