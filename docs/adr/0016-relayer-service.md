# ADR-0016: Relayer service design

Status: Accepted (2026-10-02)

## Context
Phase 4 delivers a permissionless relayer API, gas sponsorship, rate limiting
and self-hosting documentation. ADR-0010 already makes relayers untrusted and
fees signed; this ADR covers the service itself.

## Options considered
Transport: (1) HTTP/JSON; (2) gRPC; (3) a peer-to-peer gossip of signed
authorizations. Server: (a) async framework (axum/tokio); (b) a small
blocking HTTP server (`tiny_http`) with a fixed thread pool and one
submission worker. Payload: (i) raw QSP-1 bytes + signature; (ii) the
envelope file already used for offline signing. State: in-memory vs database.

## Decision
HTTP/JSON (1) with `POST /v1/submit`, `GET /v1/status/{id}`, `GET /v1/info`,
`GET /health` (`docs/RELAYER.md`). `tiny_http` (b): a handful of
dependencies, enough throughput for a service bounded by Solana confirmation
times, and a single worker that serializes submissions (natural ordering of
sequential nonces). Payload (ii): the same envelope as offline signing, so a
signed file can be handed to `qshield submit`, a relayer, or anything else
unchanged. In-memory state: nothing the relayer stores is needed for safety.

The worker reuses `qshield-client`'s `submit`, so the relayer applies exactly
the same local checks as the CLI (signature against the on-chain key, nonce,
token pre-checks) before spending fees. Fee policy: optional minimum fee,
payable only to the fee payer (zero recipient or the relayer's address).

## Security implications
The relayer holds only its own Ed25519 fee-payer key. Compromise of a relayer
loses that key's SOL and allows censorship, nothing else. Request ids derived
from the authorization bytes make duplicates harmless. Rate limiting by IP is
best effort; behind a proxy it must be explicitly told to trust
`X-Forwarded-For`.

## Tradeoffs
No persistence of request history; no authentication (permissionless by
design — operators who want private relayers can put one behind a proxy with
auth). The single worker limits throughput to sequential confirmation.

## Alternatives rejected
gRPC: harder for browsers. Gossip: out of scope for a research preview.
An async framework: larger dependency tree for no benefit at this scale.
