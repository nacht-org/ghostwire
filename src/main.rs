//! Command-line interface for flaregun.

use std::process;

use clap::{Arg, ArgAction, Command};
use flaregun::{captcha::CaptchaConfig, CloudScraperBuilder, StealthConfig};

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("flaregun")
        .version(flaregun::VERSION)
        .about("Bypass Cloudflare anti-bot protection from the command line")
        .arg(Arg::new("url").required(true).help("URL to fetch"))
        .arg(
            Arg::new("captcha-provider")
                .long("captcha-provider")
                .help("Captcha provider (2captcha | anticaptcha | capsolver)"),
        )
        .arg(
            Arg::new("api-key")
                .long("api-key")
                .help("API key for the captcha provider"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Enable debug logging"),
        )
        .arg(
            Arg::new("proxy")
                .short('p')
                .long("proxy")
                .help("Proxy URL (e.g. http://user:pass@host:port)"),
        )
        .arg(
            Arg::new("no-stealth")
                .long("no-stealth")
                .action(ArgAction::SetTrue)
                .help("Disable stealth mode"),
        )
        .arg(
            Arg::new("method")
                .short('X')
                .long("method")
                .default_value("GET")
                .help("HTTP method"),
        )
        .get_matches();

    let url = matches.get_one::<String>("url").unwrap();
    let debug = matches.get_flag("debug");

    // ── Captcha ───────────────────────────────────────────────────────────────
    let captcha = match (
        matches.get_one::<String>("captcha-provider"),
        matches.get_one::<String>("api-key"),
    ) {
        (Some(provider), Some(key)) => Some(CaptchaConfig {
            provider: provider.clone(),
            api_key: Some(key.clone()),
            ..Default::default()
        }),
        _ => None,
    };

    // ── Stealth ───────────────────────────────────────────────────────────────
    let stealth = StealthConfig {
        enabled: !matches.get_flag("no-stealth"),
        ..Default::default()
    };

    // ── Build scraper ─────────────────────────────────────────────────────────
    let mut builder = CloudScraperBuilder::new().debug(debug).stealth(stealth);

    if let Some(cap) = captcha {
        builder = builder.captcha(cap);
    }
    if let Some(proxy) = matches.get_one::<String>("proxy") {
        builder = builder.add_proxy(proxy.clone());
    }

    let mut scraper = match builder.build() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error creating scraper: {e}");
            process::exit(1);
        }
    };

    // ── Request ───────────────────────────────────────────────────────────────
    let method_str = matches.get_one::<String>("method").unwrap().to_uppercase();
    let method = match method_str.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        _ => {
            eprintln!("Unsupported method: {method_str}");
            process::exit(1);
        }
    };

    match scraper
        .request(method, url, flaregun::RequestOptions::default())
        .await
    {
        Ok(resp) => {
            eprintln!("Status: {}", resp.status());
            match resp.text().await {
                Ok(body) => println!("{body}"),
                Err(e) => {
                    eprintln!("Error reading body: {e}");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
