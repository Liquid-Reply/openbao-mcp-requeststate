"""storage-janitor: an MCP server whose destructive tool spans two round trips.

Round 1  tools/call purge_objects(prefix)
         -> scan the bucket, park the purge plan in OpenBao (single-use),
            return InputRequiredResult: an elicitation asking for
            confirmation + a requestState the SDK seals on the way out.

Round 2  tools/call purge_objects(prefix) + inputResponses + requestState
         -> the SDK boundary verifies the envelope (integrity, expiry,
            request binding, audience) before this code runs; the tool then
            redeems the single-use claim in OpenBao and purges.

Config (env): BAO_ADDR, BAO_ROLE_ID/BAO_SECRET_ID (or BAO_TOKEN),
STATE_BACKEND=keyring|transit, STATE_TTL, CONFIRM_TTL, PORT.
"""

from __future__ import annotations

import json
import os

import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.request_state import RequestStateSecurity
from mcp_types import ElicitRequest, ElicitRequestFormParams, InputRequiredResult

from baostate import AlreadyRedeemed, OpenBao, SingleUse, TransitCodec, load_key_ring

STATE_TTL = float(os.environ.get("STATE_TTL", "120"))      # sealed-envelope lifetime
CONFIRM_TTL = int(os.environ.get("CONFIRM_TTL", "120"))    # single-use claim lifetime
CONFIRM_KEY = "confirm_purge"

bao = OpenBao()
single_use = SingleUse(bao, ttl_seconds=CONFIRM_TTL)

if os.environ.get("STATE_BACKEND", "keyring") == "transit":
    # Key custody mode: OpenBao performs the AEAD, keys never reach us.
    security = RequestStateSecurity(codec=TransitCodec(bao), ttl=STATE_TTL)
else:
    # Default: SDK seals locally under the fleet-wide ring from OpenBao.
    security = RequestStateSecurity(keys=load_key_ring(bao), ttl=STATE_TTL)

mcp = MCPServer("storage-janitor", request_state_security=security)

# Stand-in for an object store; every replica starts with the same content.
BUCKET = {
    "logs/2026-08-01.log": 812,
    "logs/2026-08-02.log": 977,
    "logs/2026-08-03.log": 1204,
    "reports/q3-draft.md": 5521,
}


@mcp.tool()
async def purge_objects(prefix: str, ctx: Context) -> str | InputRequiredResult:
    """Delete every object under `prefix` after explicit user confirmation."""
    state = ctx.request_state          # None on round 1; verified plaintext on round 2
    answers = ctx.input_responses or {}

    if state is None or CONFIRM_KEY not in answers:
        # ---- Round 1: plan, park the plan in OpenBao, ask the user. ----
        doomed = sorted(k for k in BUCKET if k.startswith(prefix))
        if not doomed:
            return f"Nothing matches {prefix!r}; bucket untouched."

        # The full plan stays server-side, behind a token only we can redeem
        # — and at most once. requestState carries the claim check, nothing else.
        claim = await anyio.to_thread.run_sync(lambda: single_use.issue({"op": "purge", "files": doomed}))

        return InputRequiredResult(
            input_requests={
                CONFIRM_KEY: ElicitRequest(
                    params=ElicitRequestFormParams(
                        message=f"Purge {len(doomed)} object(s) under {prefix!r}? " + ", ".join(doomed),
                        requested_schema={
                            "type": "object",
                            "properties": {"confirm": {"type": "boolean", "description": "true to purge"}},
                            "required": ["confirm"],
                        },
                    )
                )
            },
            # The SDK boundary seals this (AEAD + expiry + binding) on the way out.
            request_state=json.dumps({"step": "confirm", "claim": claim}),
        )

    # ---- Round 2: the boundary already proved this state is ours, fresh,
    # and bound to this tool + these arguments. Redeem once, then act. The
    # unwrap and purge are not atomic; production execution needs idempotency,
    # a durable ledger, or transactional coupling for stronger guarantees. ----
    claim = json.loads(state)["claim"]
    answer = answers[CONFIRM_KEY]
    content = getattr(answer, "content", None) or {}

    if getattr(answer, "action", None) != "accept" or content.get("confirm") is not True:
        await anyio.to_thread.run_sync(lambda: single_use.burn(claim))
        return "Purge aborted; nothing deleted."

    try:
        plan = await anyio.to_thread.run_sync(lambda: single_use.redeem(claim))
    except AlreadyRedeemed:
        return "REFUSED: this confirmation was already used or has expired. Start over."

    purged = [f for f in plan["files"] if BUCKET.pop(f, None) is not None]
    return f"Purged {len(purged)} object(s): {', '.join(purged)}. {len(BUCKET)} object(s) remain."


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    backend = "transit codec" if os.environ.get("STATE_BACKEND") == "transit" else "OpenBao-distributed key ring"
    print(f"storage-janitor on 127.0.0.1:{port} (requestState via {backend})")
    mcp.run("streamable-http", host="127.0.0.1", port=port, stateless_http=True, json_response=True)
