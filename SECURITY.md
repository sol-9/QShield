# Security policy

QShield is **experimental, unaudited** cryptographic infrastructure. No
production deployment exists. Do not use it with meaningful funds.

## Reporting a vulnerability

Please report vulnerabilities **privately**:

* Use GitHub's private vulnerability reporting: repository **Security** tab →
  **Report a vulnerability** (creates a private security advisory visible only to
  maintainers). Maintainers: make sure *Private vulnerability reporting* is
  enabled in the repository settings.

Please do **not** open public issues, pull requests or discussions for
vulnerabilities, and do not disclose or exploit a live vulnerability before
maintainers have had a reasonable opportunity to mitigate it (we aim to
acknowledge within 3 business days and agree on a disclosure timeline, normally
≤ 90 days).

Include: affected component and commit, impact, reproduction steps (a failing
test is ideal), and any suggested fix.

## Scope

In scope: `crates/qshield-mldsa`, `crates/qshield-protocol`,
`programs/qshield-vault`, QSP-1 (`docs/QSP-1.md`), and any documentation that
makes a security claim. Particularly valuable: ways to move vault funds without
a valid ML-DSA-44 signature over the intended authorization; signature
verification discrepancies with FIPS 204; replay across vaults, clusters,
programs or nonces; key-account or buffer integrity issues.

Out of scope: the limitations listed in `docs/LIMITATIONS.md` and the
"not protected against" items in `THREAT_MODEL.md` (unless you show they are
worse than documented).

## Handling

Every confirmed vulnerability gets a regression test in
`programs/qshield-vault/tests/adversarial.rs` (or the relevant crate) and an
entry in the release notes once disclosed.
