# ADR-0013: Native program, no framework, SBPF v3

Status: Accepted (2026-10-02)

## Context
The trusted program must be small and auditable and leave CU headroom beside an
≈ 828k CU verification.

## Options considered
1. Anchor. 2. Pinocchio. 3. Native with Anza's split `solana-*` crates and explicit layouts.
SBPF target: v0 (default), v1–v2, v3.

## Decision
Native program with the official split crates, hand-written fixed layouts and
explicit account checks; built with `--arch v3`.

## Security implications
Every check is visible in `processor.rs`; no macro-generated account handling.
SBPF v3 is required because Agave 4.3 includes SIMD-0500 (disables deployment of
SBPF v0–v2 when active; already active on test validators).

## Tradeoffs
More manual code than Anchor; no IDL generation (documented in `docs/PROTOCOL.md`).

## Alternatives rejected
Anchor: larger binary, macro-heavy, own serialization; Pinocchio: smaller but
less familiar to most auditors — may be revisited for CU savings.
