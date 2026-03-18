//! Integration tests for cloudscraper-rs.
//!
//! These tests use `wiremock` to simulate Cloudflare challenge pages locally
//! without making real network requests.

use cloudscraper::{
    CloudScraper, CloudScraperBuilder,
    challenge::{
        turnstile::CloudflareTurnstile,
        v1::{CloudflareV1, V1ChallengeKind},
        v2::CloudflareV2,
        v3::CloudflareV3,
    },
    proxy_manager::{ProxyManager, RotationStrategy},
    stealth::{StealthConfig, StealthState},
    user_agent::{Browser, UserAgent, UserAgentOptions},
};

// ── User-Agent tests ──────────────────────────────────────────────────────────

#[test]
fn ua_chrome_desktop() {
    let opts = UserAgentOptions {
        browser: Some(Browser::Chrome),
        desktop: true,
        mobile: false,
        ..Default::default()
    };
    let ua = UserAgent::new(&opts).expect("Should build Chrome UA");
    assert!(
        ua.user_agent_string.contains("Chrome") || ua.user_agent_string.contains("Chromium"),
        "UA string should mention Chrome: {}",
        ua.user_agent_string
    );
    assert!(!ua.cipher_suite.is_empty(), "Should have cipher suites");
}

#[test]
fn ua_firefox_desktop() {
    let opts = UserAgentOptions {
        browser: Some(Browser::Firefox),
        desktop: true,
        mobile: false,
        ..Default::default()
    };
    let ua = UserAgent::new(&opts).expect("Should build Firefox UA");
    assert!(
        ua.user_agent_string.contains("Firefox"),
        "UA string should mention Firefox: {}",
        ua.user_agent_string
    );
}

#[test]
fn ua_custom_string() {
    let custom = "MyCustomBot/1.0".to_string();
    let opts = UserAgentOptions {
        custom: Some(custom.clone()),
        desktop: true,
        mobile: true,
        ..Default::default()
    };
    let ua = UserAgent::new(&opts).expect("Should build custom UA");
    assert_eq!(ua.user_agent_string, custom);
}

#[test]
fn ua_no_brotli_stripped() {
    let opts = UserAgentOptions {
        browser: Some(Browser::Chrome),
        desktop: true,
        mobile: false,
        allow_brotli: false,
        ..Default::default()
    };
    let ua = UserAgent::new(&opts).expect("Should build UA");
    assert!(
        !ua.headers.accept_encoding.contains("br"),
        "Accept-Encoding should not contain 'br' when allow_brotli=false: {}",
        ua.headers.accept_encoding
    );
}

#[test]
fn ua_brotli_kept_when_allowed() {
    let opts = UserAgentOptions {
        browser: Some(Browser::Chrome),
        desktop: true,
        mobile: false,
        allow_brotli: true,
        ..Default::default()
    };
    let ua = UserAgent::new(&opts).expect("Should build UA");
    assert!(
        ua.headers.accept_encoding.contains("br"),
        "Accept-Encoding should contain 'br' when allow_brotli=true: {}",
        ua.headers.accept_encoding
    );
}

// ── Proxy Manager tests ───────────────────────────────────────────────────────

#[test]
fn proxy_manager_sequential() {
    let mut pm = ProxyManager::new(
        vec![
            "http://proxy1:8080".to_string(),
            "http://proxy2:8080".to_string(),
            "http://proxy3:8080".to_string(),
        ],
        RotationStrategy::Sequential,
        300,
    );

    let p1 = pm.next_proxy().unwrap();
    let p2 = pm.next_proxy().unwrap();
    let _p3 = pm.next_proxy().unwrap();
    let p4 = pm.next_proxy().unwrap(); // wraps around

    assert_ne!(p1, p2);
    assert_eq!(p1, p4); // wrapped back to first
}

#[test]
fn proxy_manager_ban_and_recover() {
    let mut pm = ProxyManager::new(
        vec!["http://proxy1:8080".to_string()],
        RotationStrategy::Sequential,
        0, // ban duration 0 secs = effectively instant recovery
    );

    pm.report_failure("http://proxy1:8080");
    // With ban_secs=0 the proxy should be available immediately.
    let proxy = pm.next_proxy();
    assert!(
        proxy.is_some(),
        "Should recover immediately with 0 ban duration"
    );
}

#[test]
fn proxy_manager_empty() {
    let mut pm = ProxyManager::new(vec![], RotationStrategy::Sequential, 300);
    assert!(!pm.has_proxies());
    assert!(pm.next_proxy().is_none());
}

#[test]
fn proxy_format_roundtrip() {
    let proxy = ProxyManager::format_proxy("http://user:pass@host:8080");
    assert!(proxy.is_ok());
}

// ── Challenge detection tests ─────────────────────────────────────────────────

const CLOUDFLARE_SERVER: &str = "cloudflare";

fn cf_iuam_body() -> &'static str {
    r#"
    <html>
    <body>
    <img src="/cdn-cgi/images/trace/jsch/transparent.gif"/>
    <form id="challenge-form" action="/abc123/__cf_chl_f_tk=token456">
    <input name="r" value="token"/>
    <input name="jschl_vc" value="vc"/>
    <input name="pass" value="pass"/>
    </form>
    <script>
    setTimeout(function(){
    document.getElementById('challenge-form').submit();
    }, 4000);
    </script>
    </body>
    </html>
    "#
}

fn cf_captcha_body() -> &'static str {
    r#"
    <html>
    <body>
    <img src="/cdn-cgi/images/trace/captcha/transparent.gif"/>
    <form id="challenge-form" action="/abc123/__cf_chl_f_tk=token456">
    <input name="r" value="rtoken"/>
    <div class="h-captcha" data-sitekey="abc123def456ghi789jkl0123456789mnop4567"></div>
    </form>
    </body>
    </html>
    "#
}

fn cf_turnstile_body() -> &'static str {
    r#"
    <html>
    <body>
    <div class="cf-turnstile" data-sitekey="0x4AAAAAAADnPIDROrmt1Wwj"></div>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
    </body>
    </html>
    "#
}

fn cf_firewall_body() -> &'static str {
    r#"
    <html><body>
    <span class="cf-error-code">1020</span>
    </body></html>
    "#
}

#[test]
fn detect_iuam_challenge() {
    assert!(CloudflareV1::is_iuam_challenge(
        503,
        CLOUDFLARE_SERVER,
        cf_iuam_body()
    ));
    assert!(!CloudflareV1::is_iuam_challenge(
        200,
        CLOUDFLARE_SERVER,
        "<html></html>"
    ));
    assert!(!CloudflareV1::is_iuam_challenge(
        503,
        "nginx",
        cf_iuam_body()
    ));
}

#[test]
fn detect_captcha_challenge() {
    assert!(CloudflareV1::is_captcha_challenge(
        403,
        CLOUDFLARE_SERVER,
        cf_captcha_body()
    ));
    assert!(!CloudflareV1::is_captcha_challenge(
        200,
        CLOUDFLARE_SERVER,
        "<html></html>"
    ));
}

#[test]
fn detect_firewall_blocked() {
    assert!(CloudflareV1::is_firewall_blocked(
        403,
        CLOUDFLARE_SERVER,
        cf_firewall_body()
    ));
    assert!(!CloudflareV1::is_firewall_blocked(
        200,
        CLOUDFLARE_SERVER,
        "<html></html>"
    ));
}

#[test]
fn classify_returns_firewall_first() {
    let kind = CloudflareV1::classify(403, CLOUDFLARE_SERVER, cf_firewall_body());
    assert_eq!(kind, Some(V1ChallengeKind::Firewall1020));
}

#[test]
fn classify_returns_none_for_clean_page() {
    let kind = CloudflareV1::classify(200, "nginx", "<html><body>Hello</body></html>");
    assert!(kind.is_none());
}

#[test]
fn detect_turnstile_challenge() {
    assert!(CloudflareTurnstile::is_turnstile_challenge(
        403,
        CLOUDFLARE_SERVER,
        cf_turnstile_body()
    ));
    assert!(!CloudflareTurnstile::is_turnstile_challenge(
        200,
        "nginx",
        "<html></html>"
    ));
}

#[test]
fn extract_turnstile_site_key() {
    let key = CloudflareTurnstile::extract_site_key(cf_turnstile_body()).unwrap();
    assert_eq!(key, "0x4AAAAAAADnPIDROrmt1Wwj");
}

#[test]
fn extract_iuam_delay() {
    let delay = CloudflareV1::extract_delay(cf_iuam_body());
    assert_eq!(delay, Some(4.0));
}

#[test]
fn v2_detection() {
    let body = r#"cpo.src = '/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1?ray=abc';"#;
    assert!(CloudflareV2::is_v2_js_challenge(
        503,
        CLOUDFLARE_SERVER,
        body
    ));
}

#[test]
fn v3_detection() {
    let body = r#"window._cf_chl_ctx = {"cvId": "abc"};"#;
    assert!(CloudflareV3::is_v3_challenge(503, CLOUDFLARE_SERVER, body));
}

// ── Builder / scraper construction tests ─────────────────────────────────────

#[test]
fn build_default_scraper() {
    let scraper = CloudScraper::new();
    assert!(scraper.is_ok(), "Default scraper should build successfully");
}

#[test]
fn build_with_custom_ua() {
    let opts = UserAgentOptions {
        custom: Some("TestBot/1.0".to_string()),
        desktop: true,
        mobile: true,
        ..Default::default()
    };
    let scraper = CloudScraperBuilder::new().user_agent_opts(opts).build();
    assert!(scraper.is_ok());
}

#[test]
fn build_with_stealth_disabled() {
    let stealth = StealthConfig {
        enabled: false,
        ..Default::default()
    };
    let scraper = CloudScraperBuilder::new().stealth(stealth).build();
    assert!(scraper.is_ok());
}

// ── Stealth mode tests ────────────────────────────────────────────────────────

#[test]
fn stealth_adds_chrome_quirk_headers() {
    use reqwest::header::HeaderMap;
    let config = StealthConfig {
        enabled: true,
        browser_quirks: true,
        ..Default::default()
    };
    let state = StealthState::new(config);
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0";
    let mut headers = HeaderMap::new();
    state.apply_to_headers(&mut headers, ua);
    assert!(
        headers.contains_key("sec-ch-ua"),
        "Should inject sec-ch-ua for Chrome UA"
    );
}

#[test]
fn stealth_adds_firefox_quirk_headers() {
    use reqwest::header::HeaderMap;
    let config = StealthConfig {
        enabled: true,
        browser_quirks: true,
        ..Default::default()
    };
    let state = StealthState::new(config);
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
    let mut headers = HeaderMap::new();
    state.apply_to_headers(&mut headers, ua);
    assert!(
        headers.contains_key("upgrade-insecure-requests"),
        "Should inject Upgrade-Insecure-Requests for Firefox UA"
    );
}

#[test]
fn stealth_disabled_no_headers_added() {
    use reqwest::header::HeaderMap;
    let config = StealthConfig {
        enabled: false,
        ..Default::default()
    };
    let state = StealthState::new(config);
    let mut headers = HeaderMap::new();
    state.apply_to_headers(&mut headers, "SomeBot/1.0");
    assert!(
        headers.is_empty(),
        "Disabled stealth should not add any headers"
    );
}
