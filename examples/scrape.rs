//! # flaregun — Comprehensive Usage Example
//!
//! This example walks through the major features of the library:
//!
//!   1. Basic usage (no config)
//!   2. Custom browser / user-agent selection
//!   3. Stealth mode tuning
//!   4. Proxy rotation
//!   5. Captcha provider integration (2captcha / AntiCaptcha / CapSolver)
//!   6. Selectively disabling challenge handlers
//!   7. POST requests with a form body
//!   8. Debug mode
//!   9. Reading response metadata (status, headers, cookies)
//!
//! Run a specific example with:
//!
//!   cargo run --example scrape -- <section>
//!
//! e.g.
//!
//!   cargo run --example scrape -- basic
//!   cargo run --example scrape -- stealth
//!   cargo run --example scrape -- proxy
//!   cargo run --example scrape -- captcha
//!   cargo run --example scrape -- post
//!   cargo run --example scrape -- debug
//!   cargo run --example scrape -- all

use std::env;
use std::time::Instant;

use flaregun::{
    CloudScraper, CloudScraperBuilder, RequestOptions, StealthConfig,
    captcha::CaptchaConfig,
    proxy_manager::RotationStrategy,
    user_agent::{Browser, UserAgentOptions},
};

// ── Target URLs ───────────────────────────────────────────────────────────────
//
// These are publicly accessible endpoints that are either unprotected or use
// lightweight Cloudflare rules — safe to use in examples and CI.
//
// Swap in your own target URL when testing against a real CF-protected site.

const BASIC_URL: &str = "https://httpbin.org/get";
const POST_URL: &str = "https://httpbin.org/post";
const HEADERS_URL: &str = "https://httpbin.org/headers";
const STATUS_URL: &str = "https://httpbin.org/status/200";
const COOKIES_URL: &str = "https://httpbin.org/cookies/set?session=flaregun&theme=dark";

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Initialise structured tracing — set RUST_LOG=flaregun=debug for verbose output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("flaregun=info")),
        )
        .with_target(false)
        .init();

    let section = env::args().nth(1).unwrap_or_else(|| "all".to_string());

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║           flaregun  —  examples              ║");
    println!("╚══════════════════════════════════════════════╝\n");

    match section.as_str() {
        "basic" => example_basic().await,
        "stealth" => example_stealth().await,
        "proxy" => example_proxy().await,
        "captcha" => example_captcha().await,
        "post" => example_post().await,
        "debug" => example_debug().await,
        "all" => {
            example_basic().await;
            example_stealth().await;
            example_proxy().await;
            example_post().await;
            example_debug().await;
            // Captcha example is skipped in "all" because it requires real API
            // credentials and makes paid external API calls.
            println!("ℹ  Skipping captcha example in 'all' mode.");
            println!("   Run `cargo run --example scrape -- captcha` separately");
            println!("   after setting CAPTCHA_API_KEY in your environment.\n");
        }
        other => {
            eprintln!(
                "Unknown section '{other}'. Valid options: basic stealth proxy captcha post debug all"
            );
            std::process::exit(1);
        }
    }
}

// ── 1. Basic usage ────────────────────────────────────────────────────────────

async fn example_basic() {
    print_header("1 · Basic Usage");

    // `CloudScraper::new()` picks a random realistic browser fingerprint,
    // enables stealth mode with sensible defaults, and mounts the Cloudflare
    // challenge handlers automatically.
    let mut scraper = CloudScraper::new().expect("Failed to create scraper");

    let start = Instant::now();

    match scraper.get(BASIC_URL).await {
        Ok(resp) => {
            let elapsed = start.elapsed();
            println!("  ✓  Status  : {}", resp.status());
            println!("  ✓  Elapsed : {elapsed:.2?}");

            // Parse the JSON body returned by httpbin.
            match resp.json::<serde_json::Value>().await {
                Ok(json) => {
                    let ua = json["headers"]["User-Agent"]
                        .as_str()
                        .unwrap_or("<unknown>");
                    println!("  ✓  UA sent : {ua}");
                }
                Err(e) => println!("  ✗  JSON parse error: {e}"),
            }
        }
        Err(e) => println!("  ✗  Request failed: {e}"),
    }

    println!();
}

// ── 2. Stealth mode ───────────────────────────────────────────────────────────

async fn example_stealth() {
    print_header("2 · Stealth Mode");

    // Fine-tune the stealth behaviour: tighter delays, all quirks on.
    let stealth = StealthConfig {
        enabled: true,
        human_like_delays: true,
        randomize_headers: true,
        browser_quirks: true,
        // Keep the window small for the example so it doesn't drag.
        min_delay_secs: 0.3,
        max_delay_secs: 0.8,
    };

    // Force Chrome on Windows desktop for a deterministic fingerprint.
    let ua_opts = UserAgentOptions {
        browser: Some(Browser::Chrome),
        platform: Some("windows".to_string()),
        desktop: true,
        mobile: false,
        allow_brotli: true,
        custom: None,
    };

    let mut scraper = CloudScraperBuilder::new()
        .stealth(stealth)
        .user_agent_opts(ua_opts)
        .min_request_interval_secs(0.5)
        .build()
        .expect("Failed to create stealth scraper");

    // Make two back-to-back requests — the throttle and human-like delay
    // between them are applied transparently.
    for i in 1..=2u8 {
        let start = Instant::now();
        match scraper.get(HEADERS_URL).await {
            Ok(resp) => {
                let elapsed = start.elapsed();
                println!("  ✓  Request {i} — {} in {elapsed:.2?}", resp.status());

                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    // httpbin echoes back every header it received.
                    let headers = &json["headers"];

                    // Chrome stealth mode should inject these:
                    let interesting = ["Sec-Ch-Ua", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Dnt"];
                    for h in interesting {
                        if let Some(val) = headers[h].as_str() {
                            println!("       {h}: {val}");
                        }
                    }
                }
            }
            Err(e) => println!("  ✗  Request {i} failed: {e}"),
        }
    }

    println!();
}

// ── 3. Proxy rotation ─────────────────────────────────────────────────────────

async fn example_proxy() {
    print_header("3 · Proxy Rotation");

    // In a real scenario these would be working proxy URLs. Here we pass dummy
    // addresses to show the configuration API; the request will fail at the
    // network level, which we handle gracefully.
    let proxies = vec![
        "http://proxy1.example.com:8080".to_string(),
        "http://proxy2.example.com:8080".to_string(),
        "http://proxy3.example.com:8080".to_string(),
    ];

    println!(
        "  Configured {} proxies with Smart rotation strategy",
        proxies.len()
    );

    let mut scraper = CloudScraperBuilder::new()
        .proxies(proxies)
        .proxy_rotation(RotationStrategy::Smart)
        // How long (seconds) a proxy stays banned after a failure.
        .proxy_ban_secs(60)
        .build()
        .expect("Failed to create proxy scraper");

    // NOTE: Because the proxies are fake, the request will fail with a
    // connection error — that's expected in this example.
    match scraper.get(BASIC_URL).await {
        Ok(resp) => println!("  ✓  {} (proxy was reachable)", resp.status()),
        Err(e) => println!("  ℹ  Expected network error (fake proxies): {e}"),
    }

    // Demonstrate building a scraper without proxies (direct connection).
    println!("\n  Falling back to direct connection…");
    let mut direct = CloudScraper::new().expect("Failed to create direct scraper");
    match direct.get(STATUS_URL).await {
        Ok(resp) => println!("  ✓  Direct connection: {}", resp.status()),
        Err(e) => println!("  ✗  {e}"),
    }

    println!();
}

// ── 4. Captcha provider ───────────────────────────────────────────────────────

async fn example_captcha() {
    print_header("4 · Captcha Provider (2captcha / AntiCaptcha / CapSolver)");

    // Read the API key from the environment so it never ends up in source code.
    let api_key = match env::var("CAPTCHA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            println!("  ℹ  CAPTCHA_API_KEY not set — skipping live captcha test.");
            println!("     Export the variable and re-run to enable this section:");
            println!("       export CAPTCHA_API_KEY=your_key_here");
            println!("       cargo run --example scrape -- captcha\n");
            return;
        }
    };

    // Choose provider via CAPTCHA_PROVIDER env var; default to 2captcha.
    let provider = env::var("CAPTCHA_PROVIDER").unwrap_or_else(|_| "2captcha".to_string());

    println!("  Provider : {provider}");
    println!(
        "  API key  : {}…{}",
        &api_key[..4.min(api_key.len())],
        &api_key[api_key.len().saturating_sub(4)..]
    );

    let captcha_cfg = CaptchaConfig {
        provider: provider.clone(),
        // 2captcha and CapSolver use `api_key`; AntiCaptcha uses `client_key`.
        api_key: if provider != "anticaptcha" {
            Some(api_key.clone())
        } else {
            None
        },
        client_key: if provider == "anticaptcha" {
            Some(api_key)
        } else {
            None
        },
        // Forward the scraper's own proxy to the captcha service so the
        // solved token is valid from the same IP (set no_proxy=true to skip).
        proxy: None,
        no_proxy: true,
    };

    let mut scraper = CloudScraperBuilder::new()
        .captcha(captcha_cfg)
        // Enable all challenge handlers — the captcha provider will be invoked
        // automatically whenever a Turnstile or hCaptcha page is detected.
        .disable_v1(false)
        .disable_v2(false)
        .disable_v3(false)
        .disable_turnstile(false)
        .debug(true)
        .build()
        .expect("Failed to create captcha scraper");

    // Replace this URL with a real Turnstile/hCaptcha-protected page to test.
    let target =
        env::var("CAPTCHA_TARGET_URL").unwrap_or_else(|_| "https://httpbin.org/get".to_string());

    println!("  Target   : {target}");

    match scraper.get(&target).await {
        Ok(resp) => {
            println!("  ✓  Status : {}", resp.status());
            let preview = resp.text().await.unwrap_or_default();
            let preview = if preview.len() > 200 {
                format!("{}…", &preview[..200])
            } else {
                preview
            };
            println!("  ✓  Body   : {preview}");
        }
        Err(e) => println!("  ✗  {e}"),
    }

    println!();
}

// ── 5. POST with form body ────────────────────────────────────────────────────

async fn example_post() {
    print_header("5 · POST Request with Form Body");

    let mut scraper = CloudScraper::new().expect("Failed to create scraper");

    let form_fields = vec![
        ("username".to_string(), "flaregun".to_string()),
        ("language".to_string(), "rust".to_string()),
        ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
    ];

    println!("  Sending form fields:");
    for (k, v) in &form_fields {
        println!("    {k} = {v}");
    }

    match scraper.post_form(POST_URL, form_fields).await {
        Ok(resp) => {
            println!("  ✓  Status: {}", resp.status());

            if let Ok(json) = resp.json::<serde_json::Value>().await {
                // httpbin echoes the form fields back under "form".
                if let Some(form) = json["form"].as_object() {
                    println!("  ✓  Echo'd form data:");
                    for (k, v) in form {
                        println!("       {k}: {}", v.as_str().unwrap_or("?"));
                    }
                }
            }
        }
        Err(e) => println!("  ✗  {e}"),
    }

    println!();
}

// ── 6. Debug mode + response metadata ────────────────────────────────────────

async fn example_debug() {
    print_header("6 · Debug Mode & Response Metadata");

    let mut scraper = CloudScraperBuilder::new()
        // Debug mode wires up the tracing subscriber at debug level.
        // Set RUST_LOG=flaregun=debug to see span events in the terminal.
        .debug(true)
        // Demonstrate disabling specific challenge types.
        .disable_v1(false)
        .disable_v2(false)
        .disable_v3(false)
        .disable_turnstile(false)
        // Prevent infinite retry loops in examples.
        .max_403_retries(1)
        .solve_depth(2)
        .build()
        .expect("Failed to create debug scraper");

    // Hit an endpoint that sets cookies so we can demonstrate cookie access.
    match scraper.get(COOKIES_URL).await {
        Ok(resp) => {
            println!("  ✓  Status : {}", resp.status());

            println!("  ✓  Response headers:");
            for (name, value) in resp.headers() {
                if let Ok(v) = value.to_str() {
                    println!("       {name}: {v}");
                }
            }

            // The actual cookie jar lives on the scraper client; the redirect
            // from /cookies/set has been followed automatically by reqwest.
            println!("  ✓  Final URL: {}", resp.url());
        }
        Err(e) => println!("  ✗  {e}"),
    }

    // Demonstrate a raw bytes POST body (non-form).
    let json_body = serde_json::json!({
        "library": "flaregun",
        "language": "Rust",
        "async": true,
    });
    let body_bytes = bytes::Bytes::from(serde_json::to_vec(&json_body).unwrap());

    let opts = RequestOptions {
        body_bytes: Some(body_bytes),
        headers: {
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );
            Some(h)
        },
        ..Default::default()
    };

    match scraper.request(reqwest::Method::POST, POST_URL, opts).await {
        Ok(resp) => {
            println!("\n  ✓  Raw JSON POST status: {}", resp.status());
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(data) = json["data"].as_str() {
                    println!("  ✓  Echo'd body: {data}");
                }
            }
        }
        Err(e) => println!("  ✗  {e}"),
    }

    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn print_header(title: &str) {
    let bar = "─".repeat(title.len() + 4);
    println!("┌{bar}┐");
    println!("│  {title}  │");
    println!("└{bar}┘");
}
