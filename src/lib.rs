//! # cloudscraper-rs
//!
//! A Rust library to bypass Cloudflare's anti-bot protections.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use cloudscraper::CloudScraper;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut scraper = CloudScraper::new()?;
//!     let resp = scraper.get("https://example.com").await?;
//!     println!("Status: {}", resp.status());
//!     Ok(())
//! }
//! ```
//!
//! ## With captcha solver
//!
//! ```rust,no_run
//! use cloudscraper::{CloudScraper, captcha::CaptchaConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let captcha = CaptchaConfig {
//!         provider: "2captcha".into(),
//!         api_key: Some("your_api_key".into()),
//!         ..Default::default()
//!     };
//!
//!     let mut scraper = CloudScraper::builder()
//!         .captcha(captcha)
//!         .debug(true)
//!         .build()?;
//!
//!     let resp = scraper.get("https://protected.example.com").await?;
//!     println!("{}", resp.text().await?);
//!     Ok(())
//! }
//! ```

pub mod captcha;
pub mod challenge;
pub mod client;
pub mod error;
pub mod proxy_manager;
pub mod stealth;
pub mod user_agent;

// Top-level re-exports.
pub use captcha::{CaptchaConfig, CaptchaKind};
pub use client::{CloudScraper, CloudScraperBuilder, RequestOptions};
pub use error::{CloudscraperError, Result};
pub use proxy_manager::{ProxyManager, RotationStrategy};
pub use stealth::StealthConfig;
pub use user_agent::{Browser, UserAgent, UserAgentOptions};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
