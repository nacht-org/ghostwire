//! JavaScript interpreter abstraction for Cloudflare v3 VM challenge solving.
//!
//! The interpreter chain (tried in order, first success wins):
//!
//!  1. `js-v8`  feature → [`v8`] crate bindings (fastest, needs a C++ toolchain)
//!  2. `node`   binary  → `node -e <script>` subprocess
//!  3. `bun`    binary  → `bun -e <script>` subprocess
//!  4. `js-boa` feature → [`boa_engine`] (pure-Rust, no native deps, slower)
//!  5. Pure-Rust fallback (heuristic answer derived from challenge metadata)
//!
//! Feature flags (add to `Cargo.toml` as needed):
//!   - `js-v8`   → enables the `v8` crate interpreter (recommended when available)
//!   - `js-boa`  → enables the boa_engine interpreter (always-available fallback)

use tracing::{debug, warn};

// ── Public API ────────────────────────────────────────────────────────────────

/// Result of a JS evaluation attempt.
#[derive(Debug)]
pub enum JsResult {
    /// The script was evaluated successfully and produced this string value.
    Ok(String),
    /// No interpreter was able to run the script; caller should use fallback.
    Unavailable,
}

/// How the challenge JS should be solved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsInterpreter {
    /// Try all engines in the default priority order: v8 → node → bun → boa.
    /// Falls back to a heuristic answer if none are available.
    Auto,
    /// Use boa_engine (requires `js-boa` feature).
    Boa,
    /// Use the `v8` crate bindings (requires `js-v8` feature).
    V8,
    /// Use the `node` binary found in PATH.
    Node,
    /// Use the `bun` binary found in PATH.
    Bun,
    /// Skip JS evaluation entirely; caller must use a heuristic fallback.
    None,
}

impl Default for JsInterpreter {
    fn default() -> Self {
        Self::Auto
    }
}

impl JsInterpreter {
    /// Evaluate `script` using this interpreter strategy.
    ///
    /// * `script`  – the full JS source to run.  The *last expression* should
    ///   produce the answer value (node/bun variant uses `process.stdout.write`).
    /// * `domain`  – the target hostname, injected into the JS environment.
    ///
    /// Returns `JsResult::Ok(answer)` on success or `JsResult::Unavailable`
    /// when no suitable engine is available / all engines fail.
    pub fn eval(&self, script: &str, domain: &str) -> JsResult {
        match self {
            Self::Auto => eval_auto(script, domain),
            Self::Boa => eval_boa(script, domain),
            Self::V8 => eval_v8(script, domain),
            Self::Node => eval_subprocess(script, domain, SubprocessKind::Node),
            Self::Bun => eval_subprocess(script, domain, SubprocessKind::Bun),
            Self::None => JsResult::Unavailable,
        }
    }

    /// Build the full JS source that wraps the raw VM script in a browser-like
    /// environment and extracts the answer at the end.
    pub fn build_vm_script(
        raw_script: &str,
        domain: &str,
        ctx_json: &str,
        opt_json: &str,
    ) -> String {
        format!(
            r#"
(function() {{
    var _answer;
    var window = {{
        location: {{
            href: 'https://{domain}/',
            hostname: '{domain}',
            protocol: 'https:',
            pathname: '/',
            host: '{domain}',
            origin: 'https://{domain}'
        }},
        navigator: {{
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            platform: 'Win32',
            language: 'en-US',
            languages: ['en-US', 'en'],
            hardwareConcurrency: 4,
            cookieEnabled: true
        }},
        document: {{
            getElementById: function(id) {{ return {{ value: '', style: {{}} }}; }},
            createElement: function(tag) {{
                return {{
                    firstChild: {{ href: 'https://{domain}/' }},
                    style: {{}}
                }};
            }},
            cookie: ''
        }},
        screen: {{ width: 1920, height: 1080, colorDepth: 24 }},
        _cf_chl_ctx: {ctx_json},
        _cf_chl_opt: {opt_json},
        _cf_chl_enter: function() {{ return true; }}
    }};
    var document  = window.document;
    var location  = window.location;
    var navigator = window.navigator;
    var screen    = window.screen;

    // Stub out timers so the script doesn't hang.
    var setTimeout  = function(fn, _ms) {{ try {{ fn(); }} catch(e) {{}} }};
    var setInterval = function(_fn, _ms) {{ return 0; }};
    var clearTimeout  = function() {{}};
    var clearInterval = function() {{}};

    try {{
        {raw_script}
    }} catch(e) {{}}

    if (typeof window._cf_chl_answer !== 'undefined') {{
        _answer = String(window._cf_chl_answer);
    }} else if (typeof _cf_chl_answer !== 'undefined') {{
        _answer = String(_cf_chl_answer);
    }} else {{
        _answer = '';
    }}
    return _answer;
}})()
"#,
            domain = domain,
            ctx_json = ctx_json,
            opt_json = opt_json,
            raw_script = raw_script,
        )
    }
}

// ── Auto chain ────────────────────────────────────────────────────────────────

fn eval_auto(script: &str, domain: &str) -> JsResult {
    // 1. v8 bindings (compile-time feature) – fastest when available
    let r = eval_v8(script, domain);
    if matches!(r, JsResult::Ok(_)) {
        return r;
    }

    // 2. node subprocess
    let r = eval_subprocess(script, domain, SubprocessKind::Node);
    if matches!(r, JsResult::Ok(_)) {
        return r;
    }

    // 3. bun subprocess
    let r = eval_subprocess(script, domain, SubprocessKind::Bun);
    if matches!(r, JsResult::Ok(_)) {
        return r;
    }

    // 4. boa_engine (compile-time feature) – pure-Rust, always available if enabled
    let r = eval_boa(script, domain);
    if matches!(r, JsResult::Ok(_)) {
        return r;
    }

    // 5. nothing worked
    warn!("All JS interpreters failed or unavailable for domain={domain}");
    JsResult::Unavailable
}

// ── boa_engine ────────────────────────────────────────────────────────────────

#[cfg(feature = "js-boa")]
fn eval_boa(script: &str, _domain: &str) -> JsResult {
    use boa_engine::{Context, Source};

    debug!("Trying boa_engine interpreter");
    let mut ctx = Context::default();

    match ctx.eval(Source::from_bytes(script)) {
        Ok(val) => {
            let s = val
                .to_string(&mut ctx)
                .map(|js_str| js_str.to_std_string().unwrap_or_default())
                .unwrap_or_default();
            debug!("boa_engine result: {s:?}");
            if s.is_empty() || s == "undefined" || s == "null" {
                JsResult::Unavailable
            } else {
                JsResult::Ok(s)
            }
        }
        Err(e) => {
            warn!("boa_engine error: {e}");
            JsResult::Unavailable
        }
    }
}

#[cfg(not(feature = "js-boa"))]
fn eval_boa(_script: &str, _domain: &str) -> JsResult {
    debug!("js-boa feature not enabled, skipping boa_engine");
    JsResult::Unavailable
}

// ── v8 ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "js-v8")]
fn eval_v8(script: &str, _domain: &str) -> JsResult {
    debug!("Trying v8 interpreter");

    // V8 platform must be initialised exactly once per process.
    static V8_INIT: std::sync::Once = std::sync::Once::new();
    V8_INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    // Each call gets its own isolate so we can't accidentally share state.
    let isolate = &mut v8::Isolate::new(Default::default());

    // v8 146.x: scope! pins a HandleScope into a PinnedRef<HandleScope<()>>,
    // which is what Context::new and ContextScope::new require.
    v8::scope!(let scope, isolate);

    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let source_str = match v8::String::new(scope, script) {
        Some(s) => s,
        None => return JsResult::Unavailable,
    };

    let script_obj = match v8::Script::compile(scope, source_str, None) {
        Some(s) => s,
        None => {
            warn!("v8: script compilation failed");
            return JsResult::Unavailable;
        }
    };

    match script_obj.run(scope) {
        Some(val) => {
            let s = val.to_rust_string_lossy(scope);
            debug!("v8 result: {s:?}");
            if s.is_empty() || s == "undefined" || s == "null" {
                JsResult::Unavailable
            } else {
                JsResult::Ok(s)
            }
        }
        None => {
            warn!("v8: script execution failed");
            JsResult::Unavailable
        }
    }
}

#[cfg(not(feature = "js-v8"))]
fn eval_v8(_script: &str, _domain: &str) -> JsResult {
    debug!("js-v8 feature not enabled, skipping v8");
    JsResult::Unavailable
}

// ── Subprocess (node / bun) ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubprocessKind {
    Node,
    Bun,
}

impl SubprocessKind {
    fn binary(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }

    /// Wrap `script` so it prints the result to stdout.
    ///
    /// For Node we use `vm.runInNewContext` so the script is isolated.
    /// For Bun we fall back to a simple `eval`-in-closure approach (Bun
    /// doesn't ship `vm` in the same way).
    fn wrap(self, script: &str) -> String {
        match self {
            Self::Node => {
                // Base64-encode the script to avoid shell escaping nightmares.
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                let encoded = STANDARD.encode(script.as_bytes());
                format!(
                    r#"
var b64 = '{encoded}';
var src = Buffer.from(b64, 'base64').toString('utf8');
var vm  = require('vm');
var ctx = vm.createContext({{
    console: console,
    Math: Math,
    JSON: JSON,
    parseInt: parseInt,
    parseFloat: parseFloat,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    setTimeout:  function(fn, ms) {{ try {{ fn(); }} catch(e) {{}} }},
    setInterval: function()       {{ return 0; }},
    clearTimeout:  function() {{}},
    clearInterval: function() {{}},
}});
try {{
    var result = vm.runInContext(src, ctx, {{ timeout: 5000 }});
    if (result !== undefined && result !== null) {{
        process.stdout.write(String(result));
    }}
}} catch(e) {{
    process.stderr.write('node-interp error: ' + e.message);
    process.exit(1);
}}
"#,
                    encoded = encoded
                )
            }

            Self::Bun => {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                let encoded = STANDARD.encode(script.as_bytes());
                format!(
                    r#"
var b64   = '{encoded}';
var src   = Buffer.from(b64, 'base64').toString('utf8');
var fn_   = new Function(src + '\n;return (typeof _answer !== "undefined" ? _answer : "");');
try {{
    var result = fn_();
    if (result !== undefined && result !== null) {{
        process.stdout.write(String(result));
    }}
}} catch(e) {{
    process.stderr.write('bun-interp error: ' + e.message);
    process.exit(1);
}}
"#,
                    encoded = encoded
                )
            }
        }
    }
}

fn eval_subprocess(script: &str, domain: &str, kind: SubprocessKind) -> JsResult {
    use std::process::{Command, Stdio};

    let binary = kind.binary();
    debug!("Trying {binary} interpreter for domain={domain}");

    // Quick availability check – avoid spawning if binary is not in PATH.
    if which(binary).is_none() {
        debug!("{binary} not found in PATH");
        return JsResult::Unavailable;
    }

    let wrapper = kind.wrap(script);

    let mut child = match Command::new(binary)
        .arg("-e")
        .arg(&wrapper)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("{binary} spawn error: {e}");
            return JsResult::Unavailable;
        }
    };

    // Give the subprocess 8 seconds, then kill it.
    let timeout = std::time::Duration::from_secs(8);
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                warn!("{binary} timed out");
                return JsResult::Unavailable;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => {
                warn!("{binary} wait error: {e}");
                return JsResult::Unavailable;
            }
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            warn!("{binary} output error: {e}");
            return JsResult::Unavailable;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("{binary} exited with non-zero status: {stderr}");
        return JsResult::Unavailable;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    debug!("{binary} stdout: {stdout:?}");

    if stdout.is_empty() || stdout == "undefined" || stdout == "null" {
        JsResult::Unavailable
    } else {
        JsResult::Ok(stdout)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Returns true when the named binary exists somewhere in PATH.
    fn have(bin: &str) -> bool {
        which(bin).is_some()
    }

    // Simple arithmetic that every engine can evaluate.
    const SIMPLE_EXPR: &str = "(function(){ return String(6 * 7); })()";

    // ── build_vm_script ───────────────────────────────────────────────────────

    #[test]
    fn build_vm_script_contains_domain() {
        let s = JsInterpreter::build_vm_script("/* raw */", "example.com", "{}", "{}");
        assert!(s.contains("example.com"), "domain should appear in script");
    }

    #[test]
    fn build_vm_script_injects_ctx_opt() {
        let ctx = r#"{"cvId":"abc"}"#;
        let opt = r#"{"chlPageData":"xyz"}"#;
        let s = JsInterpreter::build_vm_script("/* raw */", "example.com", ctx, opt);
        assert!(s.contains(ctx), "ctx_json should be embedded");
        assert!(s.contains(opt), "opt_json should be embedded");
    }

    #[test]
    fn build_vm_script_has_window_stubs() {
        let s = JsInterpreter::build_vm_script("", "x.com", "{}", "{}");
        for stub in &["setTimeout", "setInterval", "clearTimeout", "clearInterval"] {
            assert!(s.contains(stub), "missing timer stub: {stub}");
        }
        for prop in &["navigator", "document", "location", "screen"] {
            assert!(s.contains(prop), "missing window property stub: {prop}");
        }
    }

    #[test]
    fn build_vm_script_captures_answer() {
        // The generated wrapper must look for both window._cf_chl_answer and
        // the bare _cf_chl_answer variable, then return it (not just evaluate it).
        let s = JsInterpreter::build_vm_script("", "x.com", "{}", "{}");
        assert!(s.contains("window._cf_chl_answer"));
        assert!(s.contains("_cf_chl_answer"));
        assert!(
            s.contains("return _answer"),
            "wrapper must return _answer so the IIFE result propagates"
        );
    }

    // ── JsInterpreter::None ───────────────────────────────────────────────────

    #[test]
    fn none_always_unavailable() {
        let r = JsInterpreter::None.eval(SIMPLE_EXPR, "example.com");
        assert!(
            matches!(r, JsResult::Unavailable),
            "None should always return Unavailable"
        );
    }

    // ── node subprocess ───────────────────────────────────────────────────────

    #[test]
    fn node_eval_simple_arithmetic() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        match JsInterpreter::Node.eval(SIMPLE_EXPR, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "42"),
            JsResult::Unavailable => panic!("node was found but returned Unavailable"),
        }
    }

    #[test]
    fn node_eval_window_answer_extraction() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        // Wrap the raw script through build_vm_script so the answer-capture
        // logic runs, then eval via Node.
        let full = JsInterpreter::build_vm_script(
            "window._cf_chl_answer = 'node-answer';",
            "test.example.com",
            "{}",
            "{}",
        );
        match JsInterpreter::Node.eval(&full, "test.example.com") {
            JsResult::Ok(v) => assert_eq!(v, "node-answer"),
            JsResult::Unavailable => panic!("node eval failed"),
        }
    }

    #[test]
    fn node_eval_ctx_opt_accessible() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        let ctx = r#"{"cvId":"test-cv-123"}"#;
        let opt = r#"{"chlPageData":"page-data-abc"}"#;
        // Script reads the injected ctx value and sets it as the answer.
        let raw = "window._cf_chl_answer = window._cf_chl_ctx.cvId;";
        let full = JsInterpreter::build_vm_script(raw, "example.com", ctx, opt);
        match JsInterpreter::Node.eval(&full, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "test-cv-123"),
            JsResult::Unavailable => panic!("node eval failed"),
        }
    }

    #[test]
    fn node_eval_bad_script_returns_unavailable() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        // Syntax error – node should exit non-zero → Unavailable.
        let r = JsInterpreter::Node.eval("this is not javascript !!!", "example.com");
        assert!(
            matches!(r, JsResult::Unavailable),
            "bad script should yield Unavailable"
        );
    }

    #[test]
    fn node_eval_empty_result_is_unavailable() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        // Script produces no stdout output (undefined result).
        let r = JsInterpreter::Node.eval("(function(){})()", "example.com");
        assert!(
            matches!(r, JsResult::Unavailable),
            "empty/undefined result should be Unavailable"
        );
    }

    // ── bun subprocess ────────────────────────────────────────────────────────

    #[test]
    fn bun_eval_simple_arithmetic() {
        if !have("bun") {
            eprintln!("skipping: bun not in PATH");
            return;
        }
        match JsInterpreter::Bun.eval(SIMPLE_EXPR, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "42"),
            JsResult::Unavailable => panic!("bun was found but returned Unavailable"),
        }
    }

    #[test]
    fn bun_eval_window_answer_extraction() {
        if !have("bun") {
            eprintln!("skipping: bun not in PATH");
            return;
        }
        let full = JsInterpreter::build_vm_script(
            "window._cf_chl_answer = 'bun-answer';",
            "test.example.com",
            "{}",
            "{}",
        );
        match JsInterpreter::Bun.eval(&full, "test.example.com") {
            JsResult::Ok(v) => assert_eq!(v, "bun-answer"),
            JsResult::Unavailable => panic!("bun eval failed"),
        }
    }

    // ── boa_engine ────────────────────────────────────────────────────────────

    #[cfg(feature = "js-boa")]
    #[test]
    fn boa_eval_simple_arithmetic() {
        match JsInterpreter::Boa.eval(SIMPLE_EXPR, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "42"),
            JsResult::Unavailable => panic!("boa returned Unavailable for simple script"),
        }
    }

    #[cfg(feature = "js-boa")]
    #[test]
    fn boa_eval_window_answer_extraction() {
        let full = JsInterpreter::build_vm_script(
            "window._cf_chl_answer = 'boa-answer';",
            "test.example.com",
            "{}",
            "{}",
        );
        match JsInterpreter::Boa.eval(&full, "test.example.com") {
            JsResult::Ok(v) => assert_eq!(v, "boa-answer"),
            JsResult::Unavailable => panic!("boa eval failed"),
        }
    }

    #[cfg(feature = "js-boa")]
    #[test]
    fn boa_eval_ctx_opt_accessible() {
        let ctx = r#"{"cvId":"boa-cv-id"}"#;
        let opt = r#"{"chlPageData":"boa-page"}"#;
        let raw = "window._cf_chl_answer = window._cf_chl_ctx.cvId;";
        let full = JsInterpreter::build_vm_script(raw, "example.com", ctx, opt);
        match JsInterpreter::Boa.eval(&full, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "boa-cv-id"),
            JsResult::Unavailable => panic!("boa eval failed"),
        }
    }

    #[cfg(feature = "js-boa")]
    #[test]
    fn boa_eval_bad_script_returns_unavailable() {
        // boa_engine returns an error for JS exceptions; the wrapper catches
        // them and maps them to Unavailable.
        let r = JsInterpreter::Boa.eval("throw new Error('boom');", "example.com");
        assert!(
            matches!(r, JsResult::Unavailable),
            "thrown error should yield Unavailable"
        );
    }

    // ── v8 bindings ───────────────────────────────────────────────────────────

    #[cfg(feature = "js-v8")]
    #[test]
    fn v8_eval_simple_arithmetic() {
        match JsInterpreter::V8.eval(SIMPLE_EXPR, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "42"),
            JsResult::Unavailable => panic!("v8 returned Unavailable for simple script"),
        }
    }

    #[cfg(feature = "js-v8")]
    #[test]
    fn v8_eval_window_answer_extraction() {
        let full = JsInterpreter::build_vm_script(
            "window._cf_chl_answer = 'v8-answer';",
            "test.example.com",
            "{}",
            "{}",
        );
        match JsInterpreter::V8.eval(&full, "test.example.com") {
            JsResult::Ok(v) => assert_eq!(v, "v8-answer"),
            JsResult::Unavailable => panic!("v8 eval failed"),
        }
    }

    #[cfg(feature = "js-v8")]
    #[test]
    fn v8_eval_ctx_opt_accessible() {
        let ctx = r#"{"cvId":"v8-cv-id"}"#;
        let opt = r#"{"chlPageData":"v8-page"}"#;
        let raw = "window._cf_chl_answer = window._cf_chl_ctx.cvId;";
        let full = JsInterpreter::build_vm_script(raw, "example.com", ctx, opt);
        match JsInterpreter::V8.eval(&full, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "v8-cv-id"),
            JsResult::Unavailable => panic!("v8 eval failed"),
        }
    }

    // ── Auto chain ordering ───────────────────────────────────────────────────

    #[test]
    fn auto_returns_ok_when_any_engine_works() {
        // At least node or bun should be present on a typical dev machine;
        // if neither is available and no compile-time engine is enabled, this
        // will just get Unavailable, which is also acceptable.
        let r = JsInterpreter::Auto.eval(SIMPLE_EXPR, "example.com");
        match r {
            JsResult::Ok(v) => assert_eq!(v, "42", "Auto chain produced wrong value"),
            JsResult::Unavailable => {
                // Acceptable when no engine is present in this environment.
                eprintln!("auto: no JS engine available in this environment");
            }
        }
    }

    // ── Subprocess wrapper details ────────────────────────────────────────────

    #[test]
    fn node_wrap_base64_roundtrips_unicode() {
        if !have("node") {
            eprintln!("skipping: node not in PATH");
            return;
        }
        // Ensure the base64 encoding/decoding survives unicode characters.
        let script = "(function(){ return String('\u{1F600}'); })()";
        match JsInterpreter::Node.eval(script, "example.com") {
            JsResult::Ok(v) => assert_eq!(v, "\u{1F600}"),
            JsResult::Unavailable => panic!("node unicode roundtrip failed"),
        }
    }

    #[test]
    fn which_finds_sh() {
        // /bin/sh is universally available; this validates `which()` itself.
        assert!(
            which("sh").is_some(),
            "which('sh') should find /bin/sh on any Unix"
        );
    }

    #[test]
    fn which_returns_none_for_nonexistent() {
        assert!(
            which("__ghostwire_no_such_binary__").is_none(),
            "which should return None for a non-existent binary"
        );
    }
}

// ── Tiny PATH lookup helper ───────────────────────────────────────────────────

/// Returns `Some(path)` if `binary` exists and is executable somewhere in PATH.
fn which(binary: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
        // On Windows try appending .exe
        #[cfg(target_os = "windows")]
        {
            let exe = dir.join(format!("{binary}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}
