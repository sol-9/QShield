# ADR-0012: Cluster id bound at compile time

Status: Accepted (2026-10-02)

## Context
Signatures for devnet must not be valid on mainnet. Programs cannot read the
cluster's genesis hash at run time, and the same program id can exist on
several clusters.

## Options considered
1. Compile-time feature selecting the genesis hash. 2. A config account written
by an admin at deployment. 3. Rely on different vault addresses per cluster.

## Decision
Option 1: features `cluster-mainnet|devnet|testnet|localnet`; SBF builds fail
unless exactly one is set; authorizations must carry that cluster's genesis hash.

## Security implications
No admin-writable configuration. The build hash commits to the cluster.

## Tradeoffs
One binary per cluster; reproducible-build documentation must state the feature.

## Alternatives rejected
Config account: introduces an admin. Address-only separation: users can create
vaults at the same address on several clusters (same key, same seed).
