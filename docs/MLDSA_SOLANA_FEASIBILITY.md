# ML-DSA-44 on Solana — feasibility report

Status: **Phase 0 result — QShield Research Preview v0.1**
Date of measurements: 2026-10-02
Reproduce: see [Reproducing](#reproducing) at the end.

## Summary

| Question | Answer |
|----------|--------|
| Can ML-DSA-44 be verified directly in a Solana program? | **Yes**, with one change in *when* work happens: the public-key expansion (`ExpandA`, `NTT(t1·2^d)`, `tr`) is computed once on-chain and stored. Verification then costs **≈ 828k CU** (59 % of the 1.4M transaction cap). Recomputing the expansion on every verification costs **≈ 2.30M CU** and does **not** fit. |
| Does the signature fit in one transaction? | **Yes in a v1 transaction** (SIMD-0385, 4,096 bytes): a complete QShield withdrawal is **3,010 bytes**. **No in legacy/v0** (1,232 bytes): the 2,420-byte signature needs a buffer account and 3 upload transactions. |
| Were any cryptographic compromises needed? | **No.** Parameter set, hash functions, encodings and the verification equation are exactly FIPS 204. The verifier evaluates the same algorithm in a different order and memory layout. |
| Chosen architecture | **Architecture A — direct on-chain ML-DSA verification**, with stored key expansion; inline signatures in v1 transactions, and the Architecture B signature buffer kept as a compatibility transport for legacy/v0 clients. Architecture C (ZK proofs) is not needed. |

The rest of this document gives the measurements behind each statement, the
Solana constraints they were checked against, and what remains unverified.

## 1. Environment and sources of truth

Network access from the measurement environment was restricted (no access to
`solana.com`, `docs.anza.xyz` or public RPC endpoints), so every Solana limit
below was taken from **Agave source code and release artifacts**, which are the
ground truth for runtime behaviour:

| Item | Version / source |
|------|------------------|
| Agave validator & CLI | `v4.3.0` release tarball (`solana-cli 4.3.0 (src:825efd18; feat:c9ad34d2)`) |
| SBF toolchain | `cargo-build-sbf 4.3.0`, platform-tools `v1.57` (rustc 1.95.0-dev) |
| Target | SBPF **v3** (`--arch v3`), see §2.6 |
| In-process SVM | LiteSVM `0.17.0` (Agave 4.3 SVM crates) with `LiteSVM::mainnet_feature_set()` — a snapshot of mainnet-beta active features "sourced from the cluster on 2026-09-27" |
| Real validator | `solana-test-validator 4.3.0` on localhost, driven over JSON-RPC |
| ML-DSA test data | NIST ACVP `ML-DSA-{sigVer,sigGen,keyGen}-FIPS204` (see `tests/vectors/acvp/README.md`) |

**Must be re-verified before any devnet/mainnet deployment:** the feature
activation status on the *target* cluster (in particular `enable_tx_v1`), the
deployed Agave version, and fee parameters. See §8.

## 2. Solana constraints (verified from source)

| Constraint | Value | Source |
|------------|-------|--------|
| Max compute units per transaction | 1,400,000 | `solana-program-runtime 4.3.0`, `execution_budget.rs: MAX_COMPUTE_UNIT_LIMIT` |
| Default CU per instruction | 200,000 | `DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT` |
| Heap | 32 KiB default, requestable up to 256 KiB | `MIN_HEAP_FRAME_BYTES`, `MAX_HEAP_FRAME_BYTES` |
| Stack | 4 KiB per frame, max call depth 64 | `MAX_CALL_DEPTH`; `cargo-build-sbf` rejects frames > 4,096 bytes |
| Legacy / v0 transaction size | 1,232 bytes | `solana-packet 4.0.0: PACKET_DATA_SIZE = 1280 - 40 - 8` |
| v1 transaction size | 4,096 bytes | `solana-message 5.1.0 / 4.6.0: v1::MAX_TRANSACTION_SIZE` |
| v1 transaction feature | `enable_tx_v1` (`txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL`, "SIMD-0385: Transaction V1") | `agave-feature-set 4.3.0`; listed as active on mainnet since slot 447,120,000 in LiteSVM 0.17's mainnet snapshot; active by default on `solana-test-validator 4.3.0` |
| Account growth inside CPI | 10 KiB per instruction | runtime `MAX_PERMITTED_DATA_INCREASE` (observed: a 21,976-byte account cannot be created by CPI) |
| SBPF v0–v2 deployment | disabled by `disable_sbpf_v0_v1_v2_deployment` (SIMD-0500) | `agave-feature-set 4.3.0`; active on `solana-test-validator 4.3.0` (deploying a v0 binary fails with "Detected sbpf_version required by the executable which are not enabled"); **not** in the mainnet snapshot yet |

Conclusion of §2: QShield targets **SBPF v3**, assumes **v1 transactions** for
the single-transaction path, and keeps a **legacy-compatible** buffered path.

## 3. Implementation choice

### 3.1 Off-the-shelf implementations do not run on SBF

`fips204 0.4.6` (IntegrityChain, pure Rust, `no_std`) compiled for SBF fails the
stack checker:

```
Error: Function ... Stack offset of 4200 exceeded max offset of 4096 by 104 bytes ...
Estimated function frame size: 10880 bytes.
```

The cause is structural: verification materialises `A_hat` (16 polynomials,
16 KiB for ML-DSA-44) and several vectors of polynomials as stack values.
RustCrypto `ml-dsa 0.1.1` has the same design. Rewriting either to place every
temporary on the heap would touch most of the code.

### 3.2 `qshield-mldsa`: verify-only, streaming, FIPS 204-exact

`crates/qshield-mldsa` implements *only* `ML-DSA.Verify` (FIPS 204 Algorithm 3)
and `ML-DSA.Verify_internal` (Algorithm 8) for ML-DSA-44, following the
standard's pseudocode step by step (`pkDecode`, `sigDecode`, `HintBitUnpack`,
`ExpandA`/`RejNTTPoly`, `SampleInBall`, `NTT`, `NTT^-1`, `UseHint`,
`w1Encode`). The only difference from the textbook order is that
`w'_approx = NTT^-1(A_hat∘NTT(z) − NTT(c)∘NTT(t1·2^d))` is computed **one row at
a time**, and each row's `w1Encode` output is absorbed into the final
`H(mu ‖ w1Encode(w1'))` immediately. Scratch memory is a 7 KiB heap workspace.
SHAKE128/256 come from RustCrypto `sha3 0.10.8`.

It is new code (~600 lines) and is therefore the largest audit item. It is
tested as follows:

| Test | Result |
|------|--------|
| NIST ACVP `ML-DSA-sigVer` ML-DSA-44 (pure external, internal, external-µ groups) | 45/45 pass (positives and negatives: modified message, `z`, hint, commitment) |
| NIST ACVP `ML-DSA-sigGen` ML-DSA-44 outputs verify | 90/90 |
| NIST ACVP `ML-DSA-keyGen`: `tr = H(pk,64)` matches `sk[64..128]` | all pass |
| Differential vs `fips204` **and** RustCrypto `ml-dsa`: valid signatures from both signers, every single-bit flip of `c_tilde` and hint, 256 random mutations of signature/key/message/context, 256 random signatures, `z` norm boundary (`γ1−β` rejected, `γ1−β−1` accepted), length errors, context > 255 bytes, all-zero / all-0xFF inputs | identical accept/reject decisions |
| NTT vs schoolbook negacyclic multiplication; `Decompose` exhaustively over all `q` residues | pass |
| Expanded-key path vs compact path on every differential case | identical |

HashML-DSA is not implemented (QSP-1 uses pure ML-DSA; §6). Constant-time
behaviour is not required: verification only touches public data.

## 4. Compute-unit measurements

All figures are total CU of the transaction as reported by the runtime, with a
210-byte message and 12-byte context (QSP-1 messages are 292 bytes; the vault
measurements in §4.3 use real QSP-1 messages).

### 4.1 Cost by strategy (LiteSVM, mainnet feature snapshot)

| Strategy | n | min | median | p99 | max | Fits 1.4M? |
|----------|---|-----|--------|-----|-----|-----------|
| Compact key: recompute `tr`, `A_hat`, `NTT(t1·2^d)` every time | 20 | 2,295,140 | 2,296,339 | 2,297,563 | 2,297,563 | **No** (164 %) |
| Compact key + stored `tr` | 20 | 2,167,645 | 2,168,844 | 2,170,068 | 2,170,068 | **No** (155 %) |
| **Expanded key stored on-chain**, signature in buffer account (legacy tx) | 200 | 825,154 | 828,104 | 830,261 | 830,543 | **Yes** (59 %) |
| **Expanded key**, signature inline (v1 tx) | 200 | 824,692 | 827,642 | 829,799 | 830,081 | **Yes** (59 %) |

The spread (≈ 5k CU) comes from data-dependent loops (rejection sampling in
`SampleInBall`, hint positions). The worst case over 200 random keys and
signatures is 830,543 CU, leaving ≈ 569k CU for program logic.

### 4.2 Where the cycles go (per primitive)

| Primitive | CU | Calls per compact verify | Calls per expanded verify |
|-----------|----|--------------------------|---------------------------|
| `RejNTTPoly` (one `A_hat` entry, ~5 SHAKE128 blocks) | 74,046 | 16 | 0 |
| `tr = SHAKE256(pk)` (1,312 bytes, 10 Keccak-f) | 127,526 | 1 | 0 |
| `NTT` | 31,350 | 9 | 5 |
| `NTT^-1` | 41,978 | 4 | 4 |
| `SampleInBall` | 24,599 | 1 | 1 |
| decode one `t1` row | 10,763 | 4 | 0 |
| pointwise multiply-accumulate | 3,841 | 20 | 20 |

A Keccak-f[1600] permutation costs roughly **12–15k CU** in software on SBF.
There is no SHAKE/Keccak-f syscall (the `sol_keccak256` syscall uses Keccak-256
padding and cannot produce SHAKE output), so the 80 permutations of `ExpandA`
alone cost ≈ 1.18M CU. Precomputing the expansion removes them, plus four
NTTs and the `tr` hash, from every verification.

### 4.3 QShield vault program (`benchmarks/ml-dsa-solana/results/vault-costs.json`)

| Instruction | CU | Transactions |
|-------------|----|--------------|
| allocate + `CreateKey` | 1,129 | 1 |
| `WriteKey` (1,312-byte public key) | 2,200 total | 2 legacy (or 1 v1) |
| `FinalizeKey` (SHA-256 key id via syscall + `tr`) | 129,510 | 1 |
| `ExpandKey` polys 0–9 | 779,927 | 1 |
| `ExpandKey` polys 10–19 | 649,928 | 1 |
| `InitializeVault` | 8,443 | 1 |
| `DepositSol` | 2,937 | 1 |
| `Execute` WithdrawSol (v1, signature inline) | ≈ 830,000 | **1** |
| `CreateSigBuffer` + 3 × `WriteSigBuffer` | 4,725 + 3,341 | 4 legacy |
| `ExecuteWithBuffer` WithdrawSol (legacy) | ≈ 830,500 | 1 |
| RotateKey / Pause / Unpause | ≈ 828–830k each | 1 |

QShield logic around the signature check (decoding, account checks, lamport
moves, nonce) adds only ≈ 2–4k CU.

### 4.4 Real validator (`benchmarks/ml-dsa-solana/results/validator-report.json`)

Against `solana-test-validator 4.3.0` over RPC, three random keys:

| Path | Transactions | CU (verify tx) | Fees (lamports, no priority fee) | Latency, submit → confirmed (local) |
|------|--------------|----------------|-----------------------------------|-------------------------------------|
| v1, signature inline (2,874-byte tx) | 1 | 825,991 – 827,887 | 5,000 | ≈ 505 ms |
| legacy, buffer (create + 3 chunks + verify) | 5 | 826,453 – 828,349 | 30,000 (incl. a second signer on create) | ≈ 2,525 ms (sequential sends) |

The RPC node accepted the 2,874-byte v1 transaction, and a modified-message
transaction was rejected on-chain (`ChallengeMismatch`).

## 5. Memory, stack, binary size, accounts

| Resource | Measured | Limit | Notes |
|----------|----------|-------|-------|
| Heap high-water mark (bench program, instrumented allocator) | 7,424 bytes | 32 KiB default | No `RequestHeapFrame` needed. The vault's misaligned-data fallback path would use ≈ 28 KiB, still within the default. |
| Largest stack frame (SBPF v0 build, static analysis of `r10` offsets) | 1,504 bytes | 4,096 bytes | `scripts/sbf-stack-report.py`; for v3 builds the toolchain's own frame check applies and passes. |
| Benchmark program binary (SBPF v3) | 58,488 bytes | — | |
| Vault program binary (SBPF v3) | 88,968 bytes | — | Upgradeable-loader program account rent scales with size. |
| Key account (pk + tr + A_hat + t1_hat + header) | 21,976 bytes | 10 MiB | **Cannot be created via CPI** (10 KiB growth limit): it is a client-allocated keypair account initialised by the program. |
| Vault account | 256 bytes | | PDA |
| Signature buffer | 2,508 bytes | | PDA, closed after use |

## 6. Transaction transport

| Layout | Size | Fits legacy (1,232)? | Fits v1 (4,096)? |
|--------|------|----------------------|------------------|
| public key + signature + message inline | 4,153 (v1) / 4,166 (legacy) | no | **no** |
| signature + message inline, key in account (bench) | 2,874 (v1) / 2,887 (legacy) | no | yes |
| **QShield `Execute` WithdrawSol** | **3,010 (v1)** | no | **yes** |
| QShield `ExecuteWithBuffer` WithdrawSol | 637 (legacy) | yes | yes |
| Buffer write chunk | ≤ 1,024 bytes payload per legacy tx | | |

Consequences:

* The public key can never travel with the signature, even in v1: keys must be
  registered (they are, as part of the expansion).
* With v1 transactions a withdrawal is a **single transaction**.
* Without v1 (legacy/v0 clients or clusters where `enable_tx_v1` is inactive), a
  withdrawal takes **1 create + 3 write + 1 execute = 5 transactions**; the buffer
  is closed in the execute transaction and its rent (0.0183 SOL) refunded.
  The buffer is bound to one vault and one creator, writable only by that
  creator, immutable once finalized and consumed on use (tested in
  `programs/qshield-vault/tests/adversarial.rs`).

## 7. Cost estimates

Base fee is 5,000 lamports per signature. Priority fees are market-dependent and
charged per *requested* CU (`price × CU limit`), so the 830k-CU verification is
the relevant multiplier.

| Item | Amount |
|------|--------|
| Withdrawal, v1 inline | 1 signature: 5,000 lamports + priority fee on ≈ 840k CU |
| Withdrawal, legacy buffered | 5 transactions: ≥ 25,000–30,000 lamports + priority fees; buffer rent 18,346,560 lamports refunded |
| Key setup (one-time per key) | 6 legacy transactions (allocate+create, 2 writes, finalize, 2 expands) + 1 `InitializeVault`; 1,559,365 CU across finalize + 2 expand txs |
| Key account rent (refundable on rotation/close) | 153,843,840 lamports (≈ 0.154 SOL) |
| Vault account rent (remains as tombstone after close) | 2,672,640 lamports (≈ 0.0027 SOL) |

Latency on mainnet will be dominated by inclusion and confirmation of one (v1)
or five (legacy) transactions. Mainnet slot time is being reduced (the snapshot
lists `reduce_slot_time_to_250ms` as active); local measurements above include
confirmation on a default test validator and are only indicative.

## 8. Security assessment of the feasibility result

* **No weakening.** ML-DSA-44 (NIST security category 2), pure mode, FIPS 204
  context string, unmodified hash functions and encodings.
* **New code risk.** `qshield-mldsa` is a new implementation. Mitigations:
  ACVP vectors, two independent differential oracles, property tests. Residual
  risk: bugs in rarely exercised paths (e.g. malformed-hint edge cases beyond
  those tested) — an external cryptographic review is required before
  production.
* **Stored expansion.** `A_hat`, `NTT(t1·2^d)` and `tr` are public functions
  of the public key. They are written only by the program, only from the
  uploaded key bytes, only after the key bytes are checked against the key id,
  and are immutable once `Ready`. A wrong expansion would make verification
  meaningless, so this invariant is part of the audit scope (see
  `docs/SECURITY_MODEL.md`).
* **Assumptions still to verify on the target cluster**: `enable_tx_v1`
  activation (only the legacy path is safe to assume otherwise), deployed Agave
  version and SBPF v3 support, CU pricing.

## 9. Decision

**Architecture A — direct on-chain ML-DSA-44 verification** with a one-time,
on-chain key expansion, inline signatures in v1 transactions, and the
signature-buffer transport retained for legacy/v0 compatibility. Recorded in
[ADR-0004](adr/0004-direct-verification-with-stored-key-expansion.md) and
[ADR-0005](adr/0005-signature-transport.md).

Architecture C (succinct proofs of ML-DSA validity) was not pursued: direct
verification fits with a 40 % CU margin, and a proof system would add a
trusted-setup or large-proof trade-off, a prover service, and far more code to
audit.

Possible optimisations, **not needed** for feasibility and deliberately not done
yet (simplicity first): lazy modular reduction in the NTT (≈ 30 % of
verification CU is NTT), packing the stored expansion at 23 bits/coefficient
(−29 % key-account rent at ≈ +160k CU per verification), a hand-scheduled
Keccak-f for SBF.

## Reproducing

```bash
# toolchain: Agave 4.3.0 release (cargo-build-sbf, solana-test-validator) on PATH
cargo build-sbf --arch v3 --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
cargo run --release -p mldsa-bench-harness            # LiteSVM report (200 keys)
scripts/bench-validator.sh                             # real validator report
cargo build-sbf --arch v0 --sbf-out-dir target/deploy-v0 \
  --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
scripts/sbf-stack-report.py target/deploy-v0/mldsa_bench_program.so

cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml
QSHIELD_COSTS_OUT=benchmarks/ml-dsa-solana/results/vault-costs.json \
  cargo test --release -p qshield-vault --test costs -- --nocapture
```

Raw results: `benchmarks/ml-dsa-solana/results/`.
