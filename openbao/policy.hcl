# Combined policy for demo convenience. It lets the server fetch the shared
# request-state key ring, use (but never read) the Transit key, and wrap/unwrap
# confirmation payloads. Production key-ring and Transit deployments should
# use separate AppRoles/policies to preserve the key-custody boundary.

# Key ring for the SDK's built-in AES-GCM codec (KV v2 read is "data/<path>").
path "secret/data/mcp/request-state-keys" {
  capabilities = ["read"]
}

# Transit mode: encrypt/decrypt with a key that never leaves OpenBao.
path "transit/encrypt/mcp-request-state" {
  capabilities = ["update"]
}
path "transit/decrypt/mcp-request-state" {
  capabilities = ["update"]
}

# Response wrapping for single-use confirmation tokens.
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}
path "sys/wrapping/unwrap" {
  capabilities = ["update"]
}
