# NIST ACVP ML-DSA-44 vectors

Filtered copies of the NIST Automated Cryptographic Validation Protocol
(ACVP) FIPS 204 test vectors, restricted to the `ML-DSA-44` test groups.

| File | Upstream path |
|------|---------------|
| `ML-DSA-44-sigVer.json` | `usnistgov/ACVP-Server: gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` |
| `ML-DSA-44-sigGen.json` | `usnistgov/ACVP-Server: gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json` |
| `ML-DSA-44-keyGen.json` | `usnistgov/ACVP-Server: gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` |

Fetched from the `master` branch on 2026-10-02. SHA-256 of the unfiltered
upstream files at fetch time:

```
47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437  ML-DSA-sigVer-FIPS204/internalProjection.json
72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22  ML-DSA-sigGen-FIPS204/internalProjection.json
e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf  ML-DSA-keyGen-FIPS204/internalProjection.json
```

Filtering keeps every field of the retained groups unchanged (only groups for
ML-DSA-65/87 are dropped). Secret keys in these files are public NIST test
data, not real keys.

These vectors are produced by NIST and are not subject to copyright in the
United States (works of the U.S. Government).

How they are used: `crates/qshield-mldsa/tests/acvp.rs`.
