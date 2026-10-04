//! Minimal chain access.
//!
//! [`Rpc`] is the only interface the client needs from a Solana node, so it can
//! be implemented over JSON-RPC ([`JsonRpc`]), an in-process SVM in tests, or a
//! relayer later. The JSON-RPC implementation deliberately uses a handful of
//! standard methods and no Solana client framework.

use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::Error;

/// An account as returned by the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountData {
    /// Balance.
    pub lamports: u64,
    /// Owner program.
    pub owner: Pubkey,
    /// Data.
    pub data: Vec<u8>,
}

/// Chain access used by [`crate::QShieldClient`].
pub trait Rpc {
    /// Fetches an account (`None` if it does not exist).
    fn get_account(&self, address: &Pubkey) -> Result<Option<AccountData>, Error>;
    /// Latest blockhash.
    fn latest_blockhash(&self) -> Result<Hash, Error>;
    /// Rent-exempt minimum for `len` bytes of data.
    fn minimum_balance_for_rent_exemption(&self, len: usize) -> Result<u64, Error>;
    /// Sends a transaction and waits until it is confirmed (or failed).
    fn send_and_confirm(&self, tx: &VersionedTransaction) -> Result<Signature, Error>;
    /// The cluster's genesis hash.
    fn genesis_hash(&self) -> Result<[u8; 32], Error>;
    /// Accounts of `token_program` whose token owner is `owner`
    /// (`getTokenAccountsByOwner`). Optional: the default reports it as unsupported.
    fn get_token_accounts_by_owner(
        &self,
        _owner: &Pubkey,
        _token_program: &Pubkey,
    ) -> Result<Vec<(Pubkey, AccountData)>, Error> {
        Err(Error::Rpc(
            "getTokenAccountsByOwner not supported by this backend".into(),
        ))
    }
}

/// Serializes a transaction in wire format.
pub fn serialize_tx(tx: &VersionedTransaction) -> Result<Vec<u8>, Error> {
    wincode::serialize(tx).map_err(|_| Error::Transaction("serialization failed".into()))
}

#[cfg(feature = "http")]
pub use http::JsonRpc;

#[cfg(feature = "http")]
mod http {
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    use base64::Engine;
    use serde_json::{json, Value};

    use super::*;

    /// Attempts per RPC call when the endpoint answers 429 or 5xx (about 30 s).
    const RPC_ATTEMPTS: u32 = 7;

    /// Solana JSON-RPC client (HTTP), commitment `confirmed`.
    pub struct JsonRpc {
        url: String,
        timeout: Duration,
    }

    impl JsonRpc {
        /// Creates a client for `url`.
        pub fn new(url: impl Into<String>) -> Self {
            Self {
                url: url.into(),
                timeout: Duration::from_secs(90),
            }
        }

        fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            // Public RPC endpoints rate-limit (429) and occasionally fail (5xx):
            // retry with exponential backoff. Resending is safe, also for
            // sendTransaction: the same signed transaction has the same
            // signature and cannot execute twice.
            let mut delay = Duration::from_millis(500);
            let mut attempt = 0;
            let mut resp = loop {
                attempt += 1;
                match ureq::post(&self.url).send_json(&body) {
                    Ok(r) => break r,
                    Err(ureq::Error::StatusCode(code))
                        if (code == 429 || code >= 500) && attempt < RPC_ATTEMPTS =>
                    {
                        std::thread::sleep(delay);
                        delay = (delay * 2).min(Duration::from_secs(8));
                    }
                    Err(e) => return Err(Error::Rpc(format!("{method}: {e}"))),
                }
            };
            let v: Value = resp
                .body_mut()
                .read_json()
                .map_err(|e| Error::Rpc(format!("{method}: {e}")))?;
            if let Some(err) = v.get("error") {
                let mut msg = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
                    .to_string();
                if let Some(logs) = err.pointer("/data/logs").and_then(Value::as_array) {
                    for l in logs.iter().filter_map(Value::as_str) {
                        msg.push_str("\n  ");
                        msg.push_str(l);
                    }
                }
                return Err(Error::Rpc(format!("{method}: {msg}")));
            }
            v.get("result")
                .cloned()
                .ok_or_else(|| Error::Rpc(format!("{method}: missing result")))
        }

        /// Compute units consumed by a confirmed transaction, if reported.
        pub fn compute_units(&self, sig: &Signature) -> Result<Option<u64>, Error> {
            let r = self.call(
                "getTransaction",
                json!([sig.to_string(), {"encoding": "base64", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}]),
            )?;
            Ok(r.pointer("/meta/computeUnitsConsumed")
                .and_then(Value::as_u64))
        }
    }

    impl Rpc for JsonRpc {
        fn get_account(&self, address: &Pubkey) -> Result<Option<AccountData>, Error> {
            let r = self.call(
                "getAccountInfo",
                json!([address.to_string(), {"encoding": "base64", "commitment": "confirmed"}]),
            )?;
            let v = &r["value"];
            if v.is_null() {
                return Ok(None);
            }
            let data = v["data"][0]
                .as_str()
                .ok_or_else(|| Error::Rpc("account data".into()))?;
            Ok(Some(AccountData {
                lamports: v["lamports"]
                    .as_u64()
                    .ok_or_else(|| Error::Rpc("lamports".into()))?,
                owner: Pubkey::from_str(v["owner"].as_str().unwrap_or_default())
                    .map_err(|_| Error::Rpc("owner".into()))?,
                data: base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| Error::Rpc("account data base64".into()))?,
            }))
        }

        fn latest_blockhash(&self) -> Result<Hash, Error> {
            let r = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
            Hash::from_str(r["value"]["blockhash"].as_str().unwrap_or_default())
                .map_err(|_| Error::Rpc("blockhash".into()))
        }

        fn minimum_balance_for_rent_exemption(&self, len: usize) -> Result<u64, Error> {
            self.call("getMinimumBalanceForRentExemption", json!([len]))?
                .as_u64()
                .ok_or_else(|| Error::Rpc("rent".into()))
        }

        fn send_and_confirm(&self, tx: &VersionedTransaction) -> Result<Signature, Error> {
            let wire = base64::engine::general_purpose::STANDARD.encode(serialize_tx(tx)?);
            let r = self.call(
                "sendTransaction",
                json!([wire, {"encoding": "base64", "preflightCommitment": "confirmed"}]),
            )?;
            let sig = Signature::from_str(r.as_str().unwrap_or_default())
                .map_err(|_| Error::Rpc("signature".into()))?;
            let start = Instant::now();
            while start.elapsed() < self.timeout {
                let s = self.call("getSignatureStatuses", json!([[sig.to_string()]]))?;
                let st = &s["value"][0];
                if !st.is_null() {
                    if !st["err"].is_null() {
                        return Err(Error::Transaction(format!("{sig} failed: {}", st["err"])));
                    }
                    if matches!(
                        st["confirmationStatus"].as_str(),
                        Some("confirmed" | "finalized")
                    ) {
                        return Ok(sig);
                    }
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            Err(Error::Transaction(format!(
                "{sig} not confirmed within {:?}",
                self.timeout
            )))
        }

        fn get_token_accounts_by_owner(
            &self,
            owner: &Pubkey,
            token_program: &Pubkey,
        ) -> Result<Vec<(Pubkey, AccountData)>, Error> {
            let r = self.call(
                "getTokenAccountsByOwner",
                json!([owner.to_string(), {"programId": token_program.to_string()}, {"encoding": "base64", "commitment": "confirmed"}]),
            )?;
            let mut out = vec![];
            for item in r["value"].as_array().cloned().unwrap_or_default() {
                let address = Pubkey::from_str(item["pubkey"].as_str().unwrap_or_default())
                    .map_err(|_| Error::Rpc("token account address".into()))?;
                let a = &item["account"];
                let data = base64::engine::general_purpose::STANDARD
                    .decode(a["data"][0].as_str().unwrap_or_default())
                    .map_err(|_| Error::Rpc("token account data".into()))?;
                out.push((
                    address,
                    AccountData {
                        lamports: a["lamports"].as_u64().unwrap_or(0),
                        owner: Pubkey::from_str(a["owner"].as_str().unwrap_or_default())
                            .map_err(|_| Error::Rpc("token account owner".into()))?,
                        data,
                    },
                ));
            }
            Ok(out)
        }

        fn genesis_hash(&self) -> Result<[u8; 32], Error> {
            let r = self.call("getGenesisHash", json!([]))?;
            bs58::decode(r.as_str().unwrap_or_default())
                .into_vec()
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| Error::Rpc("genesis hash".into()))
        }
    }
}
