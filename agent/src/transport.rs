use std::fs;
use std::time::Duration;

use chrono::Utc;
use reqwest::{Certificate, Client, StatusCode};
use sha2::{Digest, Sha256};

use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::models::{
    AgentPolicy, CommandAckRequest, CommandAckResponse, EnrollmentRequest, EnrollmentResponse,
    HeartbeatRequest, HeartbeatResponse, TelemetryBatchRequest, TelemetryBatchResponse,
    TelemetryEventIn,
};

#[derive(Clone)]
pub struct BackendClient {
    http: Client,
    base_url: String,
}

impl BackendClient {
    pub fn new(cfg: &AgentConfig) -> Result<Self, AgentError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5));

        if let Some(ca_path) = &cfg.ca_cert_path {
            let pem = fs::read(ca_path)?;
            let cert = Certificate::from_pem(&pem)?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder.build()?;
        Ok(Self {
            http,
            base_url: cfg.backend_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn enroll(&self, req: &EnrollmentRequest) -> Result<EnrollmentResponse, AgentError> {
        let url = format!("{}/api/v1/agent/enroll", self.base_url);
        let res = self.http.post(url).json(req).send().await?;
        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AgentError::Backend {
                status: status.as_u16(),
                body,
            });
        }
        Ok(res.json::<EnrollmentResponse>().await?)
    }

    pub async fn heartbeat(
        &self,
        endpoint_id: &str,
        agent_token: &str,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, AgentError> {
        let url = format!("{}/api/v1/agent/heartbeat", self.base_url);
        let res = self
            .http
            .post(url)
            .bearer_auth(agent_token)
            .header("X-Endpoint-ID", endpoint_id)
            .json(req)
            .send()
            .await?;
        let status = res.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(AgentError::Auth("agent token rejected on heartbeat".into()));
        }
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AgentError::Backend {
                status: status.as_u16(),
                body,
            });
        }
        Ok(res.json::<HeartbeatResponse>().await?)
    }

    pub async fn fetch_policy(
        &self,
        endpoint_id: &str,
        agent_token: &str,
    ) -> Result<AgentPolicy, AgentError> {
        let url = format!("{}/api/v1/agent/policy", self.base_url);
        let res = self
            .http
            .get(url)
            .bearer_auth(agent_token)
            .header("X-Endpoint-ID", endpoint_id)
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AgentError::Backend {
                status: status.as_u16(),
                body,
            });
        }
        Ok(res.json::<AgentPolicy>().await?)
    }

    pub async fn send_batch(
        &self,
        endpoint_id: &str,
        agent_token: &str,
        batch_id: &str,
        events: Vec<TelemetryEventIn>,
    ) -> Result<Result<TelemetryBatchResponse, Option<Duration>>, AgentError> {
        let url = format!("{}/api/v1/agent/telemetry", self.base_url);
        let payload = TelemetryBatchRequest {
            batch_id: batch_id.to_string(),
            endpoint_id: endpoint_id.to_string(),
            sent_at: Utc::now().to_rfc3339(),
            events,
        };
        let raw_json = serde_json::to_vec(&payload)?;
        let digest = hex::encode(Sha256::digest(&raw_json));

        let res = self
            .http
            .post(url)
            .bearer_auth(agent_token)
            .header("X-Endpoint-ID", endpoint_id)
            .header("X-Agent-Timestamp", Utc::now().to_rfc3339())
            .header("X-Payload-SHA256", digest)
            .header("Content-Type", "application/json")
            .body(raw_json)
            .send()
            .await?;

        let status = res.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE {
            let retry_after = res
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);
            return Ok(Err(retry_after));
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(AgentError::Auth(
                "agent token rejected on telemetry upload".into(),
            ));
        }
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AgentError::Backend {
                status: status.as_u16(),
                body,
            });
        }
        Ok(Ok(res.json::<TelemetryBatchResponse>().await?))
    }

    pub async fn ack_command(
        &self,
        endpoint_id: &str,
        agent_token: &str,
        action_id: &str,
        ack: &CommandAckRequest,
    ) -> Result<CommandAckResponse, AgentError> {
        let url = format!("{}/api/v1/agent/commands/{action_id}/ack", self.base_url);
        let res = self
            .http
            .post(url)
            .bearer_auth(agent_token)
            .header("X-Endpoint-ID", endpoint_id)
            .json(ack)
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AgentError::Backend {
                status: status.as_u16(),
                body,
            });
        }
        Ok(res.json::<CommandAckResponse>().await?)
    }
}

pub fn backoff_delay(attempt: u32, hint: Option<Duration>) -> Duration {
    if let Some(d) = hint {
        return d.min(Duration::from_secs(60));
    }
    let exp = 2u64.saturating_pow(attempt.min(6));
    Duration::from_secs(exp.min(60))
}
