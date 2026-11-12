//! Hetzner Cloud DNS (api.hetzner.cloud/v1), which replaced the legacy
//! dns.hetzner.com API in 2025. Records are managed as RRSets addressed by
//! relative name + type.
// verify: endpoints, bodies, and the add_records/remove_records semantics
// below against https://docs.hetzner.cloud/reference/cloud#dns before release.

use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::json;

use super::{RecordRef, TTL, ensure_success, quote_txt, relative_name};

const API: &str = "https://api.hetzner.cloud/v1";
const ACTION_POLL: Duration = Duration::from_secs(1);
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct ActionResponse {
    action: Option<Action>,
}

#[derive(Deserialize)]
struct Action {
    id: u64,
    status: String,
    error: Option<ActionError>,
}

#[derive(Deserialize)]
struct ActionError {
    message: String,
}

impl Action {
    fn pending_id(&self) -> anyhow::Result<Option<u64>> {
        match self.status.as_str() {
            "success" => Ok(None),
            "running" => Ok(Some(self.id)),
            "error" => bail!(
                "Hetzner action {} failed: {}",
                self.id,
                self.error.as_ref().map(|e| e.message.as_str()).unwrap_or("no error message")
            ),
            status => bail!("Hetzner action {} has unknown status {status}", self.id),
        }
    }
}

fn parse_action(body: &[u8]) -> anyhow::Result<Option<Action>> {
    // Some successful mutations return no body or no action.
    if body.is_empty() {
        return Ok(None);
    }
    let response: ActionResponse = serde_json::from_slice(body).context("parsing Hetzner action response")?;
    Ok(response.action)
}

pub struct Hetzner {
    http: reqwest::Client,
    token: String,
    zone: String,
}

impl Hetzner {
    pub fn new(http: reqwest::Client, token: String, zone: String) -> Self {
        Self { http, token, zone }
    }

    /// Zones are addressable by name in the path, so no id lookup is needed.
    // verify: `/zones/{id_or_name}` accepts the zone name.
    fn rrset_url(&self, name: &str, rtype: &str) -> String {
        format!("{API}/zones/{}/rrsets/{name}/{rtype}", self.zone)
    }

    async fn send(&self, req: reqwest::RequestBuilder, what: &str) -> anyhow::Result<()> {
        let resp = req.bearer_auth(&self.token).send().await.with_context(|| format!("Hetzner {what}"))?;
        let resp = ensure_success(resp, &format!("Hetzner {what}")).await?;
        let Some(action) = parse_action(&resp.bytes().await?)? else { return Ok(()) };
        let Some(id) = action.pending_id()? else { return Ok(()) };
        tokio::time::timeout(ACTION_TIMEOUT, async {
            loop {
                tokio::time::sleep(ACTION_POLL).await;
                let resp = self
                    .http
                    .get(format!("{API}/actions/{id}"))
                    .bearer_auth(&self.token)
                    .send()
                    .await
                    .context("Hetzner action lookup")?;
                let resp = ensure_success(resp, "Hetzner action lookup").await?;
                let action = parse_action(&resp.bytes().await?)?.context("Hetzner action lookup returned no action")?;
                if action.pending_id()?.is_none() {
                    return Ok(());
                }
            }
        })
        .await
        .with_context(|| format!("Hetzner action {id} did not finish within {}s", ACTION_TIMEOUT.as_secs()))?
    }

    fn value_for(rtype: &str, value: &str) -> String {
        if rtype == "TXT" { quote_txt(value) } else { value.to_string() }
    }

    pub async fn upsert(&self, fqdn: &str, rtype: &str, value: &str) -> anyhow::Result<()> {
        let name = relative_name(fqdn, &self.zone)?;
        let records = json!([{ "value": Self::value_for(rtype, value) }]);
        let existing = self
            .http
            .get(self.rrset_url(&name, rtype))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("Hetzner RRSet lookup")?;
        if existing.status() == reqwest::StatusCode::NOT_FOUND {
            let body = json!({ "name": name, "type": rtype, "ttl": TTL, "records": records });
            self.send(self.http.post(format!("{API}/zones/{}/rrsets", self.zone)).json(&body), "RRSet create").await?;
        } else {
            ensure_success(existing, "Hetzner RRSet lookup").await?;
            // Replaces every record in the set, dropping stale addresses.
            let url = format!("{}/actions/set_records", self.rrset_url(&name, rtype));
            self.send(self.http.post(url).json(&json!({ "records": records })), "RRSet set_records").await?;
        }
        Ok(())
    }

    pub async fn create_txt(&self, fqdn: &str, value: &str) -> anyhow::Result<RecordRef> {
        let name = relative_name(fqdn, &self.zone)?;
        // add_records creates the RRSet when absent and keeps any other values.
        // verify: add_records creates a missing RRSet (else fall back to POST /rrsets on 404).
        let url = format!("{}/actions/add_records", self.rrset_url(&name, "TXT"));
        let body = json!({ "ttl": TTL, "records": [{ "value": quote_txt(value) }] });
        self.send(self.http.post(url).json(&body), "TXT add_records").await?;
        Ok(RecordRef { name: fqdn.to_string(), rtype: "TXT".into(), value: value.to_string(), id: None })
    }

    pub async fn delete(&self, rec: &RecordRef) -> anyhow::Result<()> {
        let name = relative_name(&rec.name, &self.zone)?;
        // Remove only our value; the RRSet goes away once empty.
        // verify: remove_records deletes the RRSet when its last record is removed.
        let url = format!("{}/actions/remove_records", self.rrset_url(&name, &rec.rtype));
        let body = json!({ "records": [{ "value": Self::value_for(&rec.rtype, &rec.value) }] });
        self.send(self.http.post(url).json(&body), "remove_records").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_responses_without_actions_keep_current_behavior() {
        for body in [b"".as_slice(), b"{}", b"{\"action\":null}", b"{\"rrset\":{}}"] {
            assert!(parse_action(body).unwrap().is_none());
        }
    }

    #[test]
    fn action_status_decides_whether_to_poll() {
        for (status, expected) in [("running", Some(42)), ("success", None)] {
            let body = json!({ "action": { "id": 42, "status": status } }).to_string();
            assert_eq!(parse_action(body.as_bytes()).unwrap().unwrap().pending_id().unwrap(), expected);
        }
    }

    #[test]
    fn action_error_reports_provider_message() {
        let body = json!({ "action": { "id": 42, "status": "error", "error": { "message": "record is locked" } } });
        let action = parse_action(body.to_string().as_bytes()).unwrap().unwrap();
        assert_eq!(action.pending_id().unwrap_err().to_string(), "Hetzner action 42 failed: record is locked");
    }

    #[test]
    fn invalid_action_responses_fail() {
        assert!(parse_action(b"not JSON").is_err());
        assert!(parse_action(b"{\"action\":{\"status\":\"running\"}}").is_err());
        let body = json!({ "action": { "id": 42, "status": "unknown" } }).to_string();
        assert!(parse_action(body.as_bytes()).unwrap().unwrap().pending_id().is_err());
    }
}
