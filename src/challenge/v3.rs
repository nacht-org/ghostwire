//! Cloudflare v3 JavaScript-VM challenge detection and solving.

use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

use super::*;
use crate::error::{FlaregunError, Result};

static RE_CF_CTX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)window\._cf_chl_ctx\s*=\s*(\{.*?\});").unwrap());

static RE_CF_OPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)window\._cf_chl_opt\s*=\s*(\{.*?\});").unwrap());

static RE_FORM_ACTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)<form[^>]*id="challenge-form"[^>]*action="([^"]+)""#).unwrap());

static RE_INPUT_FIELDS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<input[^>]*name="([^"]+)"[^>]*value="([^"]*)""#).unwrap());

static RE_R_TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"name="r" value="([^"]+)""#).unwrap());

/// Handles Cloudflare v3 JavaScript-VM challenges.
pub struct CloudflareV3;

impl CloudflareV3 {
    pub fn is_v3_challenge(status: u16, server: &str, body: &str) -> bool {
        matches!(status, 403 | 429 | 503)
            && is_cloudflare_server(server)
            && (RE_V3_PLATFORM.is_match(body)
                || RE_V3_CTX.is_match(body)
                || RE_V3_FORM.is_match(body))
    }

    /// Extract all challenge context/option data from the page.
    pub fn extract_challenge_data(body: &str) -> V3ChallengeData {
        let ctx = RE_CF_CTX
            .captures(body)
            .and_then(|c| serde_json::from_str(c.get(1).unwrap().as_str()).ok())
            .unwrap_or_default();

        let opt = RE_CF_OPT
            .captures(body)
            .and_then(|c| serde_json::from_str(c.get(1).unwrap().as_str()).ok())
            .unwrap_or_default();

        let form_action = RE_FORM_ACTION
            .captures(body)
            .map(|c| c.get(1).unwrap().as_str().to_string());

        V3ChallengeData {
            ctx,
            opt,
            form_action,
        }
    }

    /// Generate a fallback (non-JS) answer from available challenge metadata.
    pub fn generate_fallback_answer(data: &V3ChallengeData) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        if let Some(page_data) = data.opt.get("chlPageData").and_then(|v| v.as_str()) {
            let mut h = DefaultHasher::new();
            page_data.hash(&mut h);
            return (h.finish() % 1_000_000).to_string();
        }
        if let Some(cv_id) = data.ctx.get("cvId").and_then(|v| v.as_str()) {
            let mut h = DefaultHasher::new();
            cv_id.hash(&mut h);
            return (h.finish() % 1_000_000).to_string();
        }
        // Last resort.
        rand::random::<u32>().to_string()
    }

    /// Build the POST payload for a v3 challenge submission.
    pub fn build_payload(body: &str, answer: &str) -> Result<Vec<(String, String)>> {
        let r = RE_R_TOKEN
            .captures(body)
            .ok_or_else(|| FlaregunError::ChallengeError("Cannot find r token".into()))?
            .get(1)
            .unwrap()
            .as_str()
            .to_string();

        let mut payload = vec![
            ("r".to_string(), r),
            ("jschl_answer".to_string(), answer.to_string()),
        ];

        // Collect all other input fields from the form.
        for cap in RE_INPUT_FIELDS.captures_iter(body) {
            let name = cap.get(1).unwrap().as_str().to_string();
            let value = cap.get(2).unwrap().as_str().to_string();
            if name != "r" && name != "jschl_answer" {
                payload.push((name, value));
            }
        }

        Ok(payload)
    }

    /// Resolve form action to absolute URL.
    pub fn resolve_url(page_url: &str, action: &str) -> Result<String> {
        if action.starts_with("http") {
            return Ok(action.to_string());
        }
        let base = Url::parse(page_url)?;
        Ok(format!(
            "{}://{}{}",
            base.scheme(),
            base.host_str().unwrap_or(""),
            action
        ))
    }
}

#[derive(Debug, Default)]
pub struct V3ChallengeData {
    pub ctx: serde_json::Value,
    pub opt: serde_json::Value,
    pub form_action: Option<String>,
}
