"""Drive the storage-janitor MRTR flow and try to break it.

Expects three replicas (see run_demo.sh):
  :8001, :8002  sharing the OpenBao-distributed key ring
  :8003         using the Transit codec (AEAD inside OpenBao)

Sections 2-4 speak raw JSON-RPC on purpose, so you can see exactly what
crosses the wire — and forge the things a well-behaved SDK never would.
"""

from __future__ import annotations

import json

import anyio
import httpx
from mcp.client import Client
from mcp_types import ElicitResult

A, B, TRANSIT = 8001, 8002, 8003

# Every 2026-07-28 request carries its protocol envelope in _meta —
# there is no initialize handshake left to rely on.
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "requeststate-demo", "version": "0.1"},
    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
}
ACCEPT = {"confirm_purge": {"action": "accept", "content": {"confirm": True}}}
_ids = iter(range(1, 1000))


def call(port: int, arguments: dict, responses: dict | None = None, state: str | None = None) -> dict:
    """One raw tools/call leg. Returns the JSON-RPC response object."""
    params: dict = {"name": "purge_objects", "arguments": arguments, "_meta": META}
    if responses is not None:
        params["inputResponses"] = responses
    if state is not None:
        params["requestState"] = state
    return httpx.post(
        f"http://127.0.0.1:{port}/mcp",
        json={"jsonrpc": "2.0", "id": next(_ids), "method": "tools/call", "params": params},
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "MCP-Method": "tools/call",
            "MCP-Name": "purge_objects",
        },
    ).json()


def text(resp: dict) -> str:
    if "error" in resp:
        return f'error {resp["error"]["code"]}: {resp["error"]["message"]}'
    return resp["result"]["content"][0]["text"]


async def section_1_interop() -> None:
    print("\n[1] Official MCP client, auto-driven rounds (replica :8001)")

    async def on_elicit(context, params):
        print(f"    elicited: {params.message}")
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(f"http://127.0.0.1:{A}/mcp", elicitation_callback=on_elicit) as client:
        result = await client.call_tool("purge_objects", {"prefix": "reports/"})
        print(f"    result:   {result.content[0].text}")


def section_2_scale_out() -> None:
    print("\n[2] Round 1 on replica A, round 2 on replica B (shared key ring)")
    r1 = call(A, {"prefix": "logs/"})
    state = r1["result"]["requestState"]
    print(f"    :{A} issued requestState {state[:34]}…")
    r2 = call(B, {"prefix": "logs/"}, ACCEPT, state)
    print(f"    :{B} accepted it -> {text(r2)}")


def section_3_key_custody() -> None:
    print("\n[3] Transit-codec replica: the sealed state IS OpenBao ciphertext")
    r1 = call(TRANSIT, {"prefix": "reports/"})
    state = r1["result"]["requestState"]
    print(f"    requestState: {state[:44]}…")
    r2 = call(TRANSIT, {"prefix": "reports/"}, ACCEPT, state)
    print(f"    round 2 -> {text(r2)}")


def section_4_attacks() -> None:
    print("\n[4] Attacks against one legitimately issued requestState (replica A)")
    state = call(A, {"prefix": "logs/"})["result"]["requestState"]

    tampered = state[:-3] + ("A" if state[-3] != "A" else "B") + state[-2:]
    print(f"    tamper one byte      -> {text(call(A, {'prefix': 'logs/'}, ACCEPT, tampered))}")
    print(f"    swap args to secrets/ -> {text(call(A, {'prefix': 'secrets/'}, ACCEPT, state))}")
    print(f"    honest confirmation  -> {text(call(A, {'prefix': 'logs/'}, ACCEPT, state))}")
    print(f"    replay same state    -> {text(call(A, {'prefix': 'logs/'}, ACCEPT, state))}")


if __name__ == "__main__":
    anyio.run(section_1_interop)
    section_2_scale_out()
    section_3_key_custody()
    section_4_attacks()
    print()
