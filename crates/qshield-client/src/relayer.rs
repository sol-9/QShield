//! Client for a QShield relayer's HTTP API (`docs/RELAYER.md`).
//!
//! Only public data is sent: the signed envelope (authorization bytes,
//! signature, public key, hints). A relayer can refuse or delay a request but
//! cannot change what it authorizes.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{Envelope, Error, Transport};

/// Final outcome of a relayed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Confirmed; transaction signatures in order.
    Confirmed(Vec<String>),
    /// Refused or failed (nothing changed in the vault).
    Failed(String),
}

/// HTTP client for one relayer.
pub struct RelayerClient {
    base: String,
    agent: ureq::Agent,
}

impl RelayerClient {
    /// `base` like `https://relayer.example`.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(30)))
                .build()
                .into(),
        }
    }

    fn json(
        &self,
        mut r: ureq::http::Response<ureq::Body>,
        what: &str,
    ) -> Result<(u16, Value), Error> {
        let code = r.status().as_u16();
        let v: Value = r
            .body_mut()
            .read_json()
            .map_err(|e| Error::Rpc(format!("relayer {what}: {e}")))?;
        Ok((code, v))
    }

    /// `GET /v1/info`.
    pub fn info(&self) -> Result<Value, Error> {
        let r = self
            .agent
            .get(format!("{}/v1/info", self.base))
            .call()
            .map_err(|e| Error::Rpc(format!("relayer info: {e}")))?;
        Ok(self.json(r, "info")?.1)
    }

    /// `POST /v1/submit`; returns the request id.
    pub fn submit(&self, env: &Envelope, transport: Transport) -> Result<String, Error> {
        if env.signature_hex.is_none() {
            return Err(Error::InvalidInput("envelope is not signed".into()));
        }
        let envelope: Value =
            serde_json::from_str(&env.to_json()).map_err(|_| Error::Envelope("serialize"))?;
        let body = json!({
            "envelope": envelope,
            "transport": match transport { Transport::Inline => "inline", Transport::Buffered => "buffered" },
        });
        let r = self
            .agent
            .post(format!("{}/v1/submit", self.base))
            .send_json(&body)
            .map_err(|e| Error::Rpc(format!("relayer submit: {e}")))?;
        let (code, v) = self.json(r, "submit")?;
        match (code, v["request_id"].as_str()) {
            (200 | 202, Some(id)) => Ok(id.to_string()),
            _ => Err(Error::Rpc(format!(
                "relayer refused ({code}): {}",
                v["error"].as_str().unwrap_or("unknown error")
            ))),
        }
    }

    /// `GET /v1/status/{id}`.
    pub fn status(&self, id: &str) -> Result<Value, Error> {
        let r = self
            .agent
            .get(format!("{}/v1/status/{id}", self.base))
            .call()
            .map_err(|e| Error::Rpc(format!("relayer status: {e}")))?;
        let (code, v) = self.json(r, "status")?;
        if code != 200 {
            return Err(Error::Rpc(format!("relayer status ({code}): {v}")));
        }
        Ok(v)
    }

    /// Polls until the request is confirmed or failed, or `timeout` passes.
    pub fn wait(&self, id: &str, timeout: Duration) -> Result<RelayOutcome, Error> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let v = self.status(id)?;
            match v["status"].as_str() {
                Some("confirmed") => {
                    return Ok(RelayOutcome::Confirmed(
                        v["signatures"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|s| s.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    ))
                }
                Some("failed") => {
                    return Ok(RelayOutcome::Failed(
                        v["error"].as_str().unwrap_or("failed").to_string(),
                    ))
                }
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
        Err(Error::Rpc(format!(
            "relayer request {id} not finished after {timeout:?}"
        )))
    }
}
