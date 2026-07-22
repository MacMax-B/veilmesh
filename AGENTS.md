# VeilMesh repository instructions

Read `SECURITY.md`, `docs/ARCHITECTURE.md`, and `docs/CODEX-ANLEITUNG.md` before
changing protocol, crypto, transport, storage, account, or group code.

## Non-negotiable rules

- Never invent cryptographic primitives, ratchets, MLS variants, onion formats,
  proofs of replication, or anonymous credentials.
- Use audited libraries and standards behind narrow provider interfaces.
- Never claim metadata anonymity while the direct HTTP transport is in use.
- Never log payloads, route tags, capabilities, keys, contacts, or fetch lists.
- A fetch must never delete data. Deletion requires a random capability and must
  happen only after successful authenticated reconstruction.
- Enforce request, item, file, retention, queue, and ratchet-skip bounds before
  expensive work or allocation.
- Group owner/admin keys authorize membership changes; they are not master
  decryption keys. Never share an owner's private key to delegate admin rights.
- Every group authorization change must eventually be atomic with its MLS Commit.
- Node receipts only count after both classical and ML-DSA signatures verify.
- Missing availability is not by itself publicly provable misbehavior. Separate
  local reputation from network-wide evidence.
- Keep client core independent of any frontend framework.
- Preserve unrelated user changes and do not weaken a safety check to make a test pass.

## Required verification

Run formatting, all tests, race tests, and `go vet ./...`. Add negative tests for
every parser, signature, capability, authorization, and size-limit change.

Update security documentation whenever an assumption or guarantee changes.
