//! php-verdict v5 — multi-signal PHP malware verdict engine.
//!
//! Rust port of php-verdict.py v4, rule-for-rule identical on the first release so the
//! port itself can be proven against the labelled corpus before any new detection lands.
//!
//! Why Rust: the scanner shelled out to `python3 php-verdict.py <file>` once PER FILE, so
//! every one of ~40k files paid a fresh interpreter start (measured 204 files in 5s ≈ 41
//! files/s → ~16 min a sweep). This binary starts once, reads paths from argv or stdin,
//! and scans them across all cores. It also swaps Python's backtracking `re` for the
//! `regex` crate, which is linear-time — no catastrophic backtracking is possible on a
//! hostile file, which matters when the input is attacker-authored by definition.
//!
//! Porting notes (the regex crate has no lookaround, deliberately — that is what buys the
//! linear-time guarantee), so four Python patterns became code:
//!   * HIDDEN_PHP_NAME's `(?!php-cs-fixer|...)`  -> `hidden_php_name()`
//!   * the `goto` triple-lookahead label test    -> `goto_obfuscation()`
//!   * the two SPAM `(?<![\w$>-])mail(` lookbehinds -> a leading `(?:^|[^\w$>-])` class
//! Bounded gaps like `[\s\S]{0,4000}?` compile to enormous programs. The two widest
//! (EtherHiding's 4000 and Family-K's 400+1400) are two-stage searches via `near()`;
//! the rest keep their pattern and are built through `rx()` with a raised size limit.
//!
//! Usage:  php-verdict FILE...            one line per finding: LEVEL score file :: reasons
//!         php-verdict --json FILE...
//!         php-verdict --all FILE...      include CLEAN files
//!         php-verdict --stdin            read NUL- or newline-separated paths from stdin
//!         php-verdict --threads N        cap worker threads (default: all cores)

use flate2::write::ZlibEncoder;
use flate2::Compression;
use rayon::prelude::*;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::io::{Read, Write};
use std::sync::LazyLock;

// ---------------------------------------------------------------- regex helpers

/// Build a regex with limits generous enough for the bounded gaps the rules use
/// (`[\s\S]{0,4000}?` expands to a large program; the default 10MiB limit rejects it).
fn rx(pat: &str) -> Regex {
    RegexBuilder::new(pat)
        .size_limit(64 << 20)
        .dfa_size_limit(32 << 20)
        .build()
        .unwrap_or_else(|e| panic!("bad regex {pat:?}: {e}"))
}

/// Python's `A[\s\S]{0,N}?B` as a two-stage search: find A, then look for B in the next
/// N characters. A bounded repeat that wide compiles to a huge program - the single
/// `[\s\S]{0,4000}?` in the EtherHiding rule was most of a 126 ms process start, which
/// made a per-file invocation slower than the Python it replaced. Two small regexes
/// compile in microseconds and run faster.
fn near(text: &str, a: &Regex, b: &Regex, window: usize) -> bool {
    for m in a.find_iter(text) {
        let rest = &text[m.end()..];
        // + slack so B, which may itself be long, is not clipped at the boundary
        let hay = match rest.char_indices().nth(window + 512) {
            Some((i, _)) => &rest[..i],
            None => rest,
        };
        if b.is_match(hay) {
            return true;
        }
    }
    false
}

fn rxset(pats: &[&str]) -> RegexSet {
    RegexSetBuilder::new(pats)
        .size_limit(64 << 20)
        .dfa_size_limit(32 << 20)
        .build()
        .unwrap_or_else(|e| panic!("bad regex set: {e}"))
}

// ---------------------------------------------------------------- path exclusions
// Each of these clears a whole class of statistical false positive (measured).
static EXCLUDE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"/wp-content/uploads/honeypot\.php$",              // OUR sensor on ~1545 sites
        r"|/_ir-scan\.php$|^/opt/honeypot/",                // our IR tooling
        r"|/vendor(_prefixed)?/symfony/polyfill-[^/]+/Resources/", // Unicode tables
        r"|/voku/portable-ascii/[^/]*/data/",
        r"|/jwhennessey/phpinsight/",
        r"|/wp-content/wflogs/",                            // Wordfence config = 1.6MB base64 blob
        r"|/wp-includes/ID3/",                              // the only WP-core hex-escape FPs
        r"|/wp-includes/sodium_compat/",                    // lowest-IC WP-core files
        r"|/tcpdf/fonts/",                                  // 1.1M-char single lines
        // Security plugins ship malware SIGNATURES as data. NinjaScanner base64-encodes its
        // signature file BY DESIGN (its changelog says: to stop hosts flagging it) and
        // GOTMLS pulls definitions from GOTMLS.NET - both decode to text dense with
        // `eval(`, `$_POST[` and `shell_exec`, which would convict them on the decoded layer.
        r"|/plugins/(wordfence|sucuri-scanner|wp-security|better-wp-security|all-in-one-wp-security",
        r"|ninjascanner|ninjafirewall|gotmls|anti-malware|quttera|wp-cerber|malcare|wpvividbackups)[^/]*/",
        r"|/vendor(_prefixed)?/paragonie/sodium_compat/", // Composer copy; the entry above covers only wp-includes/
        // Freemius: the licensing SDK vendored into a great many WordPress plugins. It
        // deliberately splits function names ('base64' . '_decode', 'requir' . 'e_once') to
        // get past WordPress.org's plugin review, which is exactly the shape B6 convicts.
        // Measured: the ONLY new-rule false positive in a 60,000-file real-WordPress sweep
        // (6 hits, all Freemius). The research corpus was phpMyAdmin + Composer and could
        // not see this class - its own report flagged that gap. webshell-content-scan.sh
        // already excludes /freemius/ for the same reason.
        r"|/freemius/",
        // Commercially obfuscated vendor code, cleared by analysts against the fleet:
        // themify-builder (16 CRITICALs, all the builder's own packed classes) and
        // nextgen-gallery (6). Both ship identical bytes to hundreds of sites.
        r"|/plugins/themify-builder/|/plugins/nextgen-gallery/",
        // Any Wordfence copy, including the backup directories listed above - its
        // signature database IS attack code as data.
        r"|/wordfence[^/]*/(?:lib|waf|vendor|views|modules|crypto)/",
        r"|/iocs\.json$|/quarantine-inventory\.txt$",     // our own IOC stores hold these literals
        r"|/administrator/components/com_htprotect/",       // Joomla security ext = signature DB
        r"|/tmp/install_[0-9a-f]+/",                        // Joomla installer temp
        r"|/wflogs/",                                       // Wordfence WAF log/ruleset dir = attack sigs as data
        // PHPUnit tests bundled into WP-Optimize / Perfmatters that ini_set() disable_functions /
        // open_basedir as part of their own assertions - not a sandbox escape.
        r"|/vendor/(?:matthiasmullie/minify|rosell-dk/exec-with-fallback)/[Tt]ests?/",
        r"|/symfony/var-dumper/Caster/FFICaster\.php$",     // Symfony debug caster legitimately references FFI::cdef/load/scope
        r"|/vendor/voku/portable-(ascii|utf8)/",            // UTF-8/ASCII char-data tables (all \x00.. escapes) trip first-line-hex
        r"|/joomla/string/src/phputf8/",                    // Joomla UTF-8 string lib (chr/ord data), same hex-escape FP
        r"|/plugins/antihacker/scan/",                      // Bill Minozzi Anti Hacker scanner = its detection sigs are data
        r"|/paragonie/constant_time_encoding/tests/",       // base64/hex round-trip test vectors, high-entropy by design
        r"|/composer/ca-bundle/",                           // bundled CA certificate store = high-entropy cert data
    ))
});

// ---------------------------------------------------------------- deterministic fingerprints
// Order matters: only the FIRST match scores (mirrors the Python `break`).
// Python applied re.I only to patterns containing `\b`; those two carry an inline (?i).
static FINGERPRINT_PATS: &[(&str, &str)] = &[
    // --- what has actually been found on this server ---
    (r"'username'\s*=>\s*'(?:fbi|kacang)'", "FBI/kacang shell config header"),
    (r"Generated By Fbi Shell|Coded By Fbi Shell", "Fbi Shell marker"),
    (r"FBI_UPLOADER|fbicgiapi|cgifbi|fbisymlink", "Fbi Shell CGI toolkit"),
    (r"H3K ~ Tiny File Manager", "Tiny File Manager"),
    // ga.php loader (korat 2026-10-31, after a stolen DirectAdmin login): registers its own
    // stream wrapper and includes a "file" from it, so the decoded payload never touches disk
    // and every statistical signal scores it CLEAN. Legit wrappers (vfsStream etc.) are not
    // followed by a literal include of their own scheme in the same file.
    (r"stream_wrapper_register\(\s*'[a-z]+'[\s\S]{0,600}?\b(?:include|require)(?:_once)?\s*\(?\s*'[a-z]+://", "self-registered stream-wrapper include loader (ga.php family)"),
    (r"RAJATOGEL", "RAJATOGEL gambling defacement page"),
    // WLH Recovery Channel: a self-documenting mu-plugin dropper. Plain readable PHP with
    // no obfuscation, so every statistical signal scores it CLEAN - it needs a fingerprint.
    (r"WLH_Recovery|WLH_REC_(SALT|SLUG|THROTTLE)|Recovery Channel \(must-use\)", "WLH Recovery Channel dropper"),
    // PBN / link-injection family (Family B). Fake vendor "wpninjas.ch", dropped into
    // mu-plugins so it never shows in the Plugins UI; scores CLEAN on every statistic.
    (r"wpninjas\.ch|WpDevNinjas", "PBN link-injection mu-plugin (fake wpninjas.ch vendor)"),
    (r"x0rg Web Hosting Bypass", "x0rg phpshell"),
    (r"hunterEncryptDecrypt", "hunter webshell"),
    // --- named public shells (word-bounded: bare "WSO" matches WSOD/white-screen) ---
    (r"(?i)\b(?:FilesMan|c99shell|r57shell|b374k|MainShell|webrShell|FaTaLisTiCz_Fx|0byt3m1n1|smevk|IndoXploit|indoxploit|gel4y|priv8|p0wny@shell)\b", "named public shell"),
    (r"(?i)\bWSO\s+(?:Shell|version|VERSION)\b|\bwso_(?:version|cmd|auth)\b", "WSO shell"),
    (r"b374k shell|\$b374k\(", "b374k shell"),
    (r"__ALFA__|__ALFA_DATA_FOLDER__|alfaEx\(", "ALFA TEaM shell"),
    // --- modern China Chopper successors ---
    (r"e45e329feb5d925b", "Behinder/IceScorpion default key"),
    (r"3c6e0b8a9c15224a", "Godzilla default key"),
    (r"cf710203400b8c466e6dfcafcf36a411", "EncystPHP hard-coded gate hash"),
    (r"\[\$i\+1&15\];", "Behinder XOR loop"),
    (r#"@eval\s*\(\s*\$_(?:POST|REQUEST)\s*\[\s*['"]\w{1,3}['"]\s*\]\s*\)"#, "China Chopper one-liner"),
    (r#"\$k="[0-9a-f]{8}";\$kh="[0-9a-f]{12}";\$kf="[0-9a-f]{12}";"#, "Weevely agent header"),
    (r"\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);", "Weevely create_function launcher"),
    (r"\\160\\x68\\141\\x72\\72\\57\\57", "Weevely phar obfuscator stub"),
    // --- obfuscator families (0 FP, from PHP-Antimalware-Scanner) ---
    (r"\$_F=__FILE__;\$_X='", "ByteRun obfuscator"),
    (r"\$[O0]+=urldecode\('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64'\)", "Lockit/ALFA obfuscator"),
    (r"Obfuscation provided by FOPO", "FOPO obfuscator"),
    (r#"sg_load\s*\(\s*['"][A-Za-z0-9+/]{150,}"#, "SourceGuardian loader"),
    // --- sandbox escape / persistence ---
    // ini_get() of these is legitimate (WP core probes safe_mode/open_basedir); only a
    // WRITE is an escape attempt. Restricting to set/restore cleared 3 WP-core FPs.
    (r#"ini_(?:set|restore)\s*\(\s*['"](?:safe_mode|open_basedir|disable_functions|allow_url_include)"#, "ini tampering with protections"),
    (r#"putenv\s*\(\s*['"]LD_PRELOAD"#, "LD_PRELOAD injection"),
    (r"(?:file_put_contents|fwrite)[^;]{0,120}authorized_keys", "writes SSH authorized_keys"),
    (r"(?:file_put_contents|fwrite)[^;]{0,120}(?:crontab|cron\.d)", "writes cron"),
    (r#"(?:exec|system|passthru|shell_exec)\s*\(\s*['"](?:nc|ncat|netcat)\s+-[elp]"#, "netcat reverse shell"),
    (r#"(?:exec|system)\s*\(\s*['"]bash\s+-i\s*>&\s*/dev/tcp/"#, "bash reverse shell"),
    // --- password-gated shell login (FP 0/14874, one of the best single indicators) ---
    (r#"(?:md5|sha1|hash)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)[^)]{0,60}\)\s*===?\s*['"][0-9a-f]{32,}"#, "hash-gated shell login"),
    (r#"\$(?:s_pass|auth_pass)\s*=\s*['"][0-9a-f]{32}['"]"#, "md5 shell password constant"),
];
static FINGERPRINTS: LazyLock<RegexSet> =
    LazyLock::new(|| rxset(&FINGERPRINT_PATS.iter().map(|(p, _)| *p).collect::<Vec<_>>()));

// ---------------------------------------------------------------- tainted source -> sink
// php-malware-finder $execution / $execution2 / $execution3. FP 0/14874.
static TAINT: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:eval|assert|passthru|exec|include|include_once|require|require_once|system|pcntl_exec",
        r"|shell_exec|popen|proc_open|array_map|ob_start|call_user_func|call_user_func_array)",
        r"\s*\(\s*(?:base64_decode|php://input|str_rot13|gzinflate|gzuncompress|gzdecode|getenv|pack",
        r"|hex2bin|convert_uudecode|\$_(?:GET|REQUEST|POST|COOKIE|SERVER))",
    ))
});
static TAINT_CB: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:array_filter|array_reduce|array_walk_recursive|array_walk|assert_options|uasort|uksort",
        r"|usort|preg_replace_callback|iterator_apply|register_shutdown_function|register_tick_function",
        r"|set_error_handler|spl_autoload_register)\s*\(\s*[^,]{0,80},\s*(?:base64_decode|php://input",
        r"|str_rot13|gzinflate|gzuncompress|getenv|pack|\$_(?:GET|REQUEST|POST|COOKIE|SERVER))",
    ))
});

// Superglobal invoked as a function: $_GET['x']('id'). Pathognomonic, FP 0/14874.
static SUPERGLOBAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]]*\]\s*\("));

// A byte-safe window around [start,end) padded by `pad`, snapped to char boundaries.
fn win_around(t: &str, start: usize, end: usize, pad: usize) -> &str {
    let mut s = start.saturating_sub(pad);
    let mut e = (end + pad).min(t.len());
    while s > 0 && !t.is_char_boundary(s) { s -= 1; }
    while e < t.len() && !t.is_char_boundary(e) { e += 1; }
    &t[s..e]
}

// SUPERGLOBAL_CALL as a REAL call, not a match inside a comment / string / interpolation.
// The bare regex ($_GET['x']( ) fired on SMF / phpBB / Yii2 / Symfony / phpThumb doc-comments
// and on echoed JS ("pagesLike_$_POST[id]()") - 21 FPs on the real fleet that the research
// corpus (phpMyAdmin + Composer) never contained. All real invocations survive these guards.
fn superglobal_call(t: &str) -> bool {
    for m in SUPERGLOBAL_CALL.find_iter(t) {
        let start = m.start();
        // string interpolation: $_ preceded by an identifier char (e.g. pagesLike_$_POST)
        if let Some(c) = t[..start].chars().next_back() {
            if c.is_ascii_alphanumeric() || c == '_' {
                continue;
            }
        }
        let ls = t[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let before = &t[ls..start];
        let trimmed = before.trim_start();
        // doc-block / line comment
        if trimmed.starts_with('*')
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || before.contains("//")
            || before.contains('#')
        {
            continue;
        }
        // inside an open block comment (last /* is after the last */ before the match)
        if let Some(open) = t[..start].rfind("/*") {
            if Some(open) > t[..start].rfind("*/") {
                continue;
            }
        }
        // inside a quoted string on this line (odd unescaped quote count before the match)
        if before.matches('"').count() % 2 == 1 || before.matches('\'').count() % 2 == 1 {
            continue;
        }
        // bareword array key ($_SERVER[HTTP_HOST]) = interpolation / old-style, never a real call;
        // a real dynamic call quotes the key ($_GET['x']) or uses a variable ($_GET[$x]).
        let matched = m.as_str();
        if let (Some(lb), Some(rb)) = (matched.find('['), matched.find(']')) {
            if let Some(first) = matched[lb + 1..rb].trim().chars().next() {
                if first.is_ascii_alphabetic() {
                    continue;
                }
            }
        }
        return true;
    }
    false
}

// tempnam() staging is a Family-K signal ONLY when attacker input AND an execution sink sit in
// the same neighbourhood as the tempnam call - a real dropper reads input, writes it to the
// temp file, then include()s it right there. Securimage's audio tempnam (L3084) and Iptanus
// WFU's @tempnam(sys_get_temp_dir(),'wfu') have neither nearby; requiring co-location within
// 600 bytes cleared 7 vendor FPs while keeping every Family-K dropper (they co-locate tightly).
fn tempnam_dropper(t: &str) -> bool {
    for m in TEMPNAM_STAGING.find_iter(t) {
        let win = win_around(t, m.start(), m.end(), 600);
        if TEMPNAM_TAINT.is_match(win) && EXEC_SINK.is_match(win) {
            return true;
        }
    }
    false
}
// Nested decode wrappers, FP 0/14874.
static NESTED_DECODE: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:eval|assert|create_function|include|require|preg_replace|call_user_func)\s*\(\s*",
        r"(?:gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|strrev|convert_uudecode|hex2bin",
        r"|pack|bzdecompress)\s*\(",
    ))
});
static DOUBLE_DECODE: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(\s*",
        r"(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(|base64_decode\s*\(\s*base64_decode",
    ))
});

// Family-K injector: keyed on the invariant staging step, anchored to the top of the file.
// Python held this as one regex with {0,400} and {0,1400} gaps; split into stages so the
// program stays small (see `near`). Semantics preserved: <?php at the very start, an
// `if (` within the first 400 chars, and a staging call within 1400 chars after it.
static FK_HEAD: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)\A<\?php"));
static FK_IF: LazyLock<Regex> = LazyLock::new(|| rx(r"if\s*\("));
static FK_STAGE: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)hex2bin\s*\(\s*\$_(?:POST|REQUEST|GET|COOKIE)\s*\[",
        r"|array_filter\s*\(\s*\[[^\]]{0,400}?(?:sys_get_temp_dir|session_save_path|upload_tmp_dir|dev/shm)",
        r"|tempnam\s*\([^;]{0,200}?(?:session_save_path|sys_get_temp_dir|upload_tmp_dir)",
    ))
});
fn family_k(t: &str) -> bool {
    if !FK_HEAD.is_match(t) {
        return false;
    }
    let head400 = head(t, 400 + 8); // + the "<?php" the gap is measured from
    for m in FK_IF.find_iter(head400) {
        let rest = &t[m.end()..];
        let hay = match rest.char_indices().nth(1400 + 512) {
            Some((i, _)) => &rest[..i],
            None => rest,
        };
        if FK_STAGE.is_match(hay) {
            return true;
        }
    }
    false
}

// Bare prepended eval:  <?php  eval($_REQUEST['bOWpmn']);  /* real file */
static BARE_EVAL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?i)\A<\?php\s*@?\s*eval\s*\(\s*\$_(?:REQUEST|POST|GET|COOKIE)\s*\["));

// tempnam() staging into a writable temp dir, in a file ALSO driven by a request
// superglobal. WordPress core's PHPMailer tempnam()s into a temp dir too but never off
// $_COOKIE/$_POST, so requiring a superglobal alongside cleared that false positive.
static TEMPNAM_STAGING: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"(?i)tempnam\s*\([\s\S]{0,120}?(?:session_save_path|sys_get_temp_dir|upload_tmp_dir)\s*\(")
});
// Only the attacker-controllable superglobals, NOT $_SERVER.
static TEMPNAM_TAINT: LazyLock<Regex> = LazyLock::new(|| rx(r"\$_(?:COOKIE|POST|GET|REQUEST)\s*\["));

// 2026-08-10: temp-dir staging ALONE is not a verdict. nsoc.p4's own migrate_photos.php -
// a login+is_admin() gated tool that curl-downloads photos into tempnam(sys_get_temp_dir())
// and rename()s them into the upload dir - matched the tempnam alternative and was reported
// CRITICAL twice. Every real Family-K dropper also EXECUTES what it stages. Requiring the
// sink kept all 100 CRITICAL verdicts across the 138 quarantined Family-K shells.
// NOTE on near-misses: \b keeps curl_exec() out, and bin2hex() is deliberately absent -
// only hex2bin() (the decode direction) is a dropper signal.
static FAMILY_K_STRONG: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)hex2bin\s*\(\s*\$_(?:POST|REQUEST|GET|COOKIE)\s*\[",
        r"|array_filter\s*\(\s*\[[^\]]{0,400}?(?:sys_get_temp_dir|session_save_path|upload_tmp_dir|dev/shm)",
    ))
});
// 2026-08-10 (second pass): EXECUTION sinks only. The first version of this guard also
// accepted a bare decoder (base64_decode/gzinflate/...), which was still too loose: the
// Elementor accessibility plugin's `create_tmp_file_from_png_base64()` - `if (!defined
// ('ABSPATH'))` + base64_decode(data-URI) + tempnam(sys_get_temp_dir()) - matched on
// **340 sites**. Decoding is not executing. A real Family-K dropper hands the staged
// bytes to an execution sink, and the decode-from-a-superglobal path it also uses is
// already covered separately by FAMILY_K_STRONG (hex2bin($_POST[..])).
// Re-measured after tightening: the 138-shell corpus keeps every CRITICAL.
static EXEC_SINK: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\(",
        r"|\b(?:system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
        r"|\bexec\s*\(\s*\$",
        r"|\b(?:include|require)(?:_once)?\s*\(?\s*\$",
    ))
});

// Cookie index written as arithmetic: $_COOKIE[-59+59]. No legitimate use.
static COOKIE_ARITH: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$_COOKIE\s*\[\s*-?\d+\s*[+-]\s*-?\d+\s*\]"));

// A file that opens with a random-token HTML comment immediately before its PHP,
// e.g. <!--2K7HbjE3--><?php. Required at the very start, so a mid-file comment is fine.
static MARKER_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?i)\A(?:\s*<!--\s*[A-Za-z0-9]{6,12}\s*-->\s*){1,}<\?php"));

// A filename that is a homoglyph of a common WordPress file: lndex.php (L-ndex),
// singIe.php (capital-I for l). They score clean on content; the name is the tell.
static HOMOGLYPH_NAME: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?i)/(?:lndex|1ndex|indéx|slngle|singIe|sing1e|lndeх)\.php$"));

// EtherHiding: a PHP plugin printing a JS stub that decodes itself with
// atob -> XOR -> new Function(new TextDecoder().decode(..)), then reads the current C2
// domain out of a Polygon smart contract. The domain is never in the file (it lives
// on-chain), so match the decoder stub, not the domain.
// Split at the 4000-char gap (see `near`): `atob(` … within 4000 … `charCodeAt(` … ^
static EH_ATOB: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)atob\s*\("));
static EH_XOR: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)charCodeAt\s*\([\s\S]{0,200}?\^"));
static ETHERHIDING_TEXTDECODER: LazyLock<Regex> = LazyLock::new(|| {
    rx(r#"(?i)new\s+Function\s*\(\s*new\s+TextDecoder\s*\(\s*\)\s*\[?['"]?decode"#)
});
fn etherhiding_stub(t: &str) -> bool {
    ETHERHIDING_TEXTDECODER.is_match(t) || near(t, &EH_ATOB, &EH_XOR, 4000)
}
// The "litspeed-beta" variant carries no base64: a plain numeric array XOR-decoded with
// String.fromCharCode. Key on the pair "decode bytes with a XOR" + "hand to new Function()".
static JS_XOR_DECODE: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r#"(?i)(?:String\s*(?:\[\s*['"]fromCharCode['"]\s*\]|\.\s*fromCharCode)"#,
        r"|charCodeAt\s*\()[\s\S]{0,200}?\^",
    ))
});
static JS_DYNAMIC_EXEC: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)new\s+Function\s*\("));
// Second, independent signal: the on-chain lookup itself.
static ETHERHIDING_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)eth_call[\s\S]{0,600}?0x[0-9a-f]{40}",
        r"|(?:polygon|bsc)[a-z0-9.-]*\.(?:publicnode|blastapi|nodies|drpc|tenderly)\.",
        r"|rpc\.ankr\.com/(?:polygon|bsc)",
        r"|1rpc\.io/(?:matic|bnb)",
    ))
});

// Plugins impersonating a security vendor. The real Wordfence ships exactly two slugs.
static FAKE_SECURITY_PLUGIN: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)Plugin\s*Name:\s*[^\r\n]*Wordfence[\s\S]{0,400}?Author:\s*Wordfence",
        r"|Author:\s*Wordfence[\s\S]{0,400}?Plugin\s*Name:\s*[^\r\n]*Wordfence",
    ))
});
// 2026-08-11: the original pattern demanded the CANONICAL path, so every BACKUP copy of
// Wordfence - updraft/plugins-old/wordfence/, plugins.backup/wordfence/, plugins_old/,
// plugins-old/, and one site's "pluginspppppp/" - was convicted of impersonating itself.
// 23 CRITICALs in one sweep, all the vendor's own code sitting in a backup directory.
// Match the plugin directory wherever it lives; a real impostor uses a DIFFERENT slug.
static REAL_WF_PATH: LazyLock<Regex> =
    LazyLock::new(|| rx(r"/wordfence(?:-login-security)?(?:\.old[^/]*|-old[^/]*)?/"));

// Code that returns early for administrators. Scored CRITICAL on its own once and produced
// 520 false positives in a single sweep (EmbedPress settings 349, Olympus Google Fonts 95,
// Jetpack, WooCommerce, Cookie Law Info, Themify): plenty of honest code skips itself in
// wp-admin. Supporting signal only - strong corroboration, worthless alone.
static ADMIN_BLIND_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)if\s*\([^{;]{0,400}?\bis_admin\s*\(\s*\)[^{;]{0,400}?",
        r#"current_user_can\s*\(\s*['"]manage_options['"]\s*\)[^{;]{0,80}?\)\s*\{?\s*return\s*;"#,
    ))
});

static MISC_CRITICAL_PATS: &[(&str, &str)] = &[
    // create_function: legacy themes still carry it, and PHP 8 removed it so it is inert.
    (r#"\bcreate_function\s*\(\s*['"]{2}"#, "create_function with empty args (obfuscator)"),
    (r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)", "extract() of a superglobal"),
    (r#"(?:preg_replace|mb_ereg_replace|preg_filter)\s*\([^)]{0,100}(?:/|\\x2f)[imsxADSUXju]{0,11}e['"]"#,
     "preg_replace /e code execution"),
    (r"(?:convert\.iconv\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\|){3,}", "php filter chain (Synacktiv RCE)"),
    // v4's mixed-case+digit goto entry was DELETED in v5: B11 (goto_packer) strictly
    // supersedes it, and leaving both let a packed file stack 70 + 60 = 130 -> false CRITICAL.
    (r"\bnew\s+\$_(?:GET|POST|REQUEST|COOKIE)", "class name from user input"),
    (r#"ReflectionFunction\s*\(\s*['"]?(?:eval|assert|system|exec)"#, "ReflectionFunction on exec sink"),
    // NOTE: Wordfence's own WAF writes auto_prepend_file by design (wfConfig.php,
    // wordfence-waf.php); those paths are cleared by EXCLUDE_PATH/REAL_WF_PATH, so this
    // stays a signal for everything else.
    (r"auto_(?:prepend|append)_file", "auto_prepend_file persistence"),
    (r"(?:eval|assert)\s*\(\s*[^)]{0,60}get_option\s*\(", "eval of a wp_options value"),
];
static MISC_CRITICAL: LazyLock<RegexSet> =
    LazyLock::new(|| rxset(&MISC_CRITICAL_PATS.iter().map(|(p, _)| *p).collect::<Vec<_>>()));

// ---------------------------------------------------------------- spam mailer
// NOTE the leading class: a bare `mail\s*(` matches is_email( and hits 44 WP-core files.
// Python used a lookbehind; the regex crate has none, so the char is consumed instead.
static SPAM_PATS: &[(&str, &str)] = &[
    (r"(?:^|[^\w$>\-])mail\s*\(\s*\$_(?:POST|GET|REQUEST)", "mail() straight from user input"),
    (r"(?:^|[^\w$>\-])(?:mail|mb_send_mail)\s*\([^)]{0,120}\bbase64_decode\s*\(", "mail() with encoded args"),
    (r"Leaf PHP Mailer|leafmailer\.pw|leafMailCheck|UTS Priv8 Mail3R|TJMailerConfig", "known bulk-mailer kit"),
    (r"\[-emailuser-\]|\[-emaildomain-\]|\[-randomletters-\]|\[-randomstring-\]", "mailer-kit placeholder tokens"),
    (r#"name="(?:emailList|messageLetter|senderEmail)""#, "bulk-mailer web form"),
    (r"X-Mailer:\s*(?:AnonMailer|Anonymous Mailer|Ninja Mailer|Leaf ?Mailer|Alfa ?Mailer|phplist v2\.10\.17)",
     "spoofed/known bulk X-Mailer"),
];
static SPAM: LazyLock<RegexSet> =
    LazyLock::new(|| rxset(&SPAM_PATS.iter().map(|(p, _)| *p).collect::<Vec<_>>()));

static DECODERS: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|convert_uudecode)\s*\("));
static SUPERGLOBAL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b"));
static PHP_GATE: LazyLock<Regex> = LazyLock::new(|| rx(r"<\?php|<\?=|<\?[^x]"));
static GUARDED_DATA: LazyLock<Regex> =
    LazyLock::new(|| rx(r"^\s*<\?php\s*(?:die|exit|__halt_compiler)\s*[(;?]"));
static B64_RUN: LazyLock<Regex> = LazyLock::new(|| rx(r"[A-Za-z0-9+/=]{24,}"));
static HEX_ESCAPE: LazyLock<Regex> = LazyLock::new(|| rx(r"\\x[0-9a-fA-F]{2}"));
static DECODER_ON_INPUT: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?:base64_decode|gzinflate|hex2bin)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)"));
static DROPPER_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"(?i)(?:include|require)(?:_once)?\s*[\(\s]\s*\$\w+\s*\)?\s*;\s*@?\s*unlink\s*\(\s*\$\w+\s*\)\s*;\s*(?:exit|die)\b")
});
static WRITE_CALL: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:file_put_contents|fwrite)\s*\("));
static INCLUDE_KW: LazyLock<Regex> = LazyLock::new(|| rx(r"\b(?:include|require)(?:_once)?\b"));
static UNLINK_CALL: LazyLock<Regex> = LazyLock::new(|| rx(r"\bunlink\s*\("));
static TEMP_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    rx(r#"sys_get_temp_dir|session_save_path|upload_tmp_dir|/dev/shm|['"]/tmp['"]|['"]/var/tmp['"]"#)
});

/// Python's `HIDDEN_PHP_NAME` used a negative lookahead. A PHP file whose own name starts
/// with a dot has no honest use in a web root, but the fleet has 4,775 of them and almost
/// all are tool artifacts - .php-cs-fixer.dist.php (305), .phpstorm.meta.php (211), and the
/// `._name.php` AppleDouble forks macOS leaves when someone uploads from a Mac.
/// Supporting signal, never a verdict on its own.
fn hidden_php_name(path: &str) -> bool {
    let base = match path.rsplit('/').next() {
        Some(b) => b,
        None => return false,
    };
    let rest = match base.strip_prefix('.') {
        Some(r) => r,
        None => return false,
    };
    // Byte-wise throughout: a filename may hold non-ASCII, and slicing a String by a
    // fixed byte offset would panic mid-character.
    let low = rest.to_ascii_lowercase();
    let b = low.as_bytes();
    let starts = |p: &str| b.starts_with(p.as_bytes());
    let php_cs_fixer = b.len() > 11
        && starts("php")
        && (b[3] == b'-' || b[3] == b'_')
        && &b[4..6] == b"cs"
        && (b[6] == b'-' || b[6] == b'_')
        && &b[7..12] == b"fixer";
    let allowed = starts("_")                    // macOS ._resource forks
        || starts("phpstorm.meta")
        || starts("user.ini")
        || starts("htaccess")
        || php_cs_fixer;
    if allowed {
        return false;
    }
    [".php", ".phtml", ".inc", ".phar"].iter().any(|e| low.ends_with(e))
}


// ================================================================ v5 signals (2026-08-10)
// Merged from a 5-lane research sweep (67 agents, 61 candidates, 54 surviving adversarial
// review) and its reference implementation. Every rule below was measured by the reviewers
// against a 2,313-file Composer/phpMyAdmin corpus at 0 false positives.
//
// NOT ported deliberately:
//   * D5 "hot-path gate" (skip the taint rules unless decoders/superglobals are present).
//     Its premise is false: SRC also matches php://input, getenv and pack, none of which
//     features() counts - so the gate would blind `include('php://input')`. It was a Python
//     speed workaround; this engine scans 11k files/s without it.
//   * B16 VARFUNC_SUPERGLOBAL - the plan itself says HOLD until measured on a WordPress
//     corpus ($fn = 'sanitize_text_field'; $fn($_POST['x']) is honest plugin code).
//   * The per-rule `if 'FFI' in t` pre-gates: the regex crate already builds literal
//     prefilters (memchr/Aho-Corasick), which is what those hand-written gates emulate.
//
// Lookbehind `(?<![\w$>\-])` has no equivalent here, so it is written as a consumed
// `(?:^|[^\w$>\-])` class - same effect for is_match, and still blocks `$db->exec(...)`.

const NOTPFX: &str = r"(?:^|[^\w$>\-])";
// Separator: whitespace and PHP comments between a callee and its "(". `\#(?!\[)` in the
// original keeps PHP 8 attributes #[Attr] from being eaten as a comment.
const SEP: &str = r"(?:[ \t\r\n]|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|//[^\n]*|\#(?:[^\[\n][^\n]*)?)*";
// Optional PHP 8 named argument, e.g. system(command: $_GET['c']).
const NAMEDARG: &str = r"(?:[A-Za-z_]\w{0,15}[ \t]*:[ \t]*)?";
// Tainted sources.
// 2026-08-14: $_SERVER is NOT tainted as a whole. `include($_SERVER['DOCUMENT_ROOT'] .
// "/header.html")` is the standard legacy-PHP include base - the server sets that value,
// an attacker cannot - and it convicted 20 files on one old DLE site alone. Only the keys
// a request can actually steer count: the HTTP_* headers, the query string, the URI/path.
const SRC: &str = concat!(
    r"(?:base64_decode|php://input|str_rot13|gzinflate|gzuncompress|gzdecode|getenv|pack",
    r"|hex2bin|convert_uudecode|\$_(?:GET|REQUEST|POST|COOKIE)",
    r#"|\$_SERVER\s*\[\s*['"]?(?:HTTP_|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF|argv))"#
);

fn build(parts: &[&str]) -> Regex {
    rx(&parts.concat())
}

// A1 - separator- and named-argument-tolerant. v4 missed `system /*x*/ ($_GET["c"])`,
// `system\n// c\n(...)`, `system(command: $_GET["c"])` - all valid PHP, all free to write.
static V5_TAINT: LazyLock<Regex> = LazyLock::new(|| {
    build(&[r"(?i)", NOTPFX,
        r"(?:eval|assert|passthru|exec|include|include_once|require|require_once|system",
        r"|pcntl_exec|shell_exec|popen|proc_open|array_map|ob_start|call_user_func|call_user_func_array)",
        SEP, r"\(", SEP, NAMEDARG, SRC])
});
// B1 - the four sinks below take their callback as argument ONE, so v4's TAINT_CB, which
// requires `[^,]{0,80},` before the taint, could never fire on them. Verified dead in v4:
// register_shutdown_function($_GET['x']) scored nothing.
static V5_TAINT_CB_FIRST: LazyLock<Regex> = LazyLock::new(|| {
    build(&[r"(?i)", NOTPFX,
        r"(?:register_shutdown_function|register_tick_function|set_error_handler",
        r"|set_exception_handler|spl_autoload_register|session_set_save_handler|stream_filter_register",
        r"|header_register_callback|forward_static_call|forward_static_call_array)",
        SEP, r"\(", SEP, NAMEDARG, SRC])
});
// B2 - genuinely second-position callbacks only. sqlite_create_function dropped (gone since PHP 5.4).
static V5_TAINT_CB: LazyLock<Regex> = LazyLock::new(|| {
    build(&[r"(?i)", NOTPFX,
        r"(?:array_filter|array_reduce|array_walk_recursive|array_walk|assert_options",
        r"|uasort|uksort|usort|preg_replace_callback|preg_replace_callback_array|iterator_apply",
        r"|mb_ereg_replace_callback)",
        SEP, r"\(\s*[^,]{0,80},\s*", NAMEDARG, SRC])
});
// B3 - eval() as the first statement of an __invoke/nvoke method: the Behinder and Godzilla
// loader shape. `\w{0,10}nvoke` covers both spellings.
static V5_INVOKE_EVAL: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"class\s+\w+\s*\{\s*(?:(?:public|private|protected|static|final|abstract)\s+)*",
        r"function\s+\w{0,10}nvoke\s*\(\s*&?\s*\$\w+\s*\)\s*\{\s*@?\s*eval\s*\("
    ))
});
// B7 - hand-rolled XOR keystream. BOTH halves are required: a ring buffer has the masked
// index without the XOR assign, a generic XOR cipher has the assign without the mask.
// This is what convicts a REKEYED Behinder/Godzilla, which v4 scores CLEAN 0 - v4's literal
// `[$i+1&15];` misses a renamed loop var, added spaces, &0xF or an offset of +3.
static V5_KEYSTREAM_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"\$\w+\s*\[\s*\$\w+\s*[+\-]\s*\d{1,3}\s*&\s*(?:\d{1,3}|0x[0-9a-fA-F]{1,2})\s*\]")
});
static V5_XOR_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$\w+\s*\[\s*\$\w+\s*\]\s*=\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\^"));
// B8 - FFI in a web tree is a disable_functions bypass. Default ffi.enable=preload makes it
// throw in the web SAPI, so treat it as a strong IoC rather than proven RCE.
static V5_FFI: LazyLock<Regex> = LazyLock::new(|| {
    build(&[NOTPFX, r"FFI\s*::\s*(?:cdef|load|scope)\s*\("])
});
// B9 - request body decrypted then executed. File-level co-occurrence on purpose: in the
// real Behinder source php://input is read into a variable on an earlier line, so requiring
// it inside the openssl_decrypt() call misses the actual sample. call_user_func and
// preg_replace are excluded from HARD_SINK - too common in honest router code.
static V5_CRYPTO: LazyLock<Regex> = LazyLock::new(|| {
    build(&[r"(?i)", NOTPFX, r"(?:openssl_decrypt|mcrypt_decrypt|mcrypt_generic)\s*\("])
});
static V5_RAW_BODY: LazyLock<Regex> = LazyLock::new(|| rx(r"php://input|HTTP_RAW_POST_DATA"));
static V5_HARD_SINK: LazyLock<Regex> = LazyLock::new(|| {
    build(&[r"(?i)", NOTPFX,
        r"(?:eval|assert|create_function|system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\("])
});
// A2 - whitespace-binary steganography. The artefact is the MAPPING of two whitespace
// tokens onto the characters '1' and '0'; it is not the ubiquitous tab/CR/LF stripping
// idiom and not bindec() subnet maths.
static V5_WS_BINARY_MAP: LazyLock<Regex> = LazyLock::new(|| {
    const WS: &str = r#"(?:chr\s*\(\s*(?:9|32)\s*\)|"(?:\\t|\t| )"|'(?:\\t|\t| )')"#;
    const BIT: &str = r#"(?:"[01]"|'[01]')"#;
    build(&[r"(?i)(?:str_replace|strtr)\s*\(\s*(?:array\s*\(|\[)\s*", WS, r"\s*,\s*", WS,
        r"\s*(?:\)|\])\s*,\s*(?:array\s*\(|\[)\s*", BIT, r"\s*,\s*", BIT,
        r"|strtr\s*\([^,;]{0,60},\s*(?:array\s*\(|\[)\s*", WS, r"\s*=>\s*", BIT])
});
static V5_CHR_BINDEC: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)chr\s*\(\s*bindec\s*\("));
static V5_WS_RUN: LazyLock<Regex> = LazyLock::new(|| rx(r"[ \t]{200,}"));
// B10 - a carrier run must be MIXED. Indentation and ASCII art are all-space or all-tab; a
// tab=1/space=0 payload interleaves ~50/50. The carrier never scores alone.
fn ws_mixed_run(text: &str) -> usize {
    let mut best = 0usize;
    for m in V5_WS_RUN.find_iter(text) {
        let r = m.as_str();
        let tabs = r.bytes().filter(|&b| b == b'\t').count();
        let len = r.len();
        let minority = tabs.min(len - tabs);
        if minority * 5 >= len && len > best {
            best = len;
        }
    }
    best
}
// B6 - reassemble a sink name split across string literals: 'sys'.'tem'. Exact match
// against the known-sink set is what keeps this at 0 FP, not the number of pieces.
static V5_CONCAT_RUN: LazyLock<Regex> = LazyLock::new(|| {
    rx("(?:(['\"])([^'\"\n\\\\]{0,16})['\"]\\s*\\.\\s*){1,}(['\"])([^'\"\n\\\\]{0,16})['\"]")
});
static V5_PIECE: LazyLock<Regex> = LazyLock::new(|| rx("['\"]([^'\"\n\\\\]{0,16})['\"]"));
const V5_SINK_NAMES: &[&str] = &[
    "eval", "assert", "system", "exec", "shell_exec", "passthru", "popen", "proc_open",
    "pcntl_exec", "base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13",
    "hex2bin", "convert_uudecode", "bzdecompress", "create_function", "call_user_func",
    "call_user_func_array", "preg_replace", "file_put_contents", "move_uploaded_file",
    "assert_options", "ffi",
];
fn reassembled_sink(text: &str) -> Option<String> {
    if !(text.contains("'.") || text.contains("\".") || text.contains("' .") || text.contains("\" .")) {
        return None;
    }
    for m in V5_CONCAT_RUN.find_iter(text) {
        let name: String = V5_PIECE
            .captures_iter(m.as_str())
            .map(|c| c[1].to_string())
            .collect::<Vec<_>>()
            .concat();
        let trimmed = name.trim_matches('\\');
        if V5_SINK_NAMES.contains(&trimmed.to_ascii_lowercase().as_str()) {
            return Some(trimmed.to_string());
        }
    }
    None
}
// B11 - goto packer. Counting DISTINCT targets is the discriminator: honest code jumps many
// sites to few labels (corpus-wide legit max = 2 distinct), packers pair them 1:1. Labels are
// matched unanchored because yakpro-po's default strip_indentation emits the file on one line.
// Scored +60, not CRITICAL: commercial source protection produces this too, and this fleet
// has a history of nulled premium plugins. Review queue, not a 3am page.
static V5_GOTO_TARGET: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)\bgoto\s+([A-Za-z_]\w*)\s*;"));
static V5_GOTO_LABEL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?:\A|[;{}:>])\s*([A-Za-z_]\w*)\s*:([^:=]|$)"));
fn goto_packer(text: &str) -> Option<usize> {
    if !text.contains("goto") {
        return None;
    }
    let targets: std::collections::HashSet<&str> =
        V5_GOTO_TARGET.captures_iter(text).map(|c| c.get(1).unwrap().as_str()).collect();
    if targets.len() < 8 {
        return None;
    }
    let labels: std::collections::HashSet<&str> =
        V5_GOTO_LABEL.captures_iter(text).map(|c| c.get(1).unwrap().as_str()).collect();
    let paired = targets.intersection(&labels).count();
    if paired >= 8 { Some(paired) } else { None }
}
// B12 - identifiers drawn from the letter/digit-lookalike alphabet, e.g. $lO01l_. Requires
// MIXING a letter-lookalike with a digit-lookalike (the bare [Ol1I0_]{4,} form was the only
// measured level transition on the whole corpus).
static V5_CONFUSABLE: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$([OlI01_]{4,})(?:[^A-Za-z0-9_]|$)"));
fn confusable_vars(text: &str) -> usize {
    let mut set = std::collections::HashSet::new();
    for c in V5_CONFUSABLE.captures_iter(text) {
        let v = c.get(1).unwrap().as_str();
        if v.bytes().any(|b| b"OlI".contains(&b)) && v.bytes().any(|b| b"01".contains(&b)) {
            set.insert(v);
        }
    }
    set.len()
}
// B13 - javascript-obfuscator/obfuscator.io naming carried into PHP ($_0x1a2b3c).
// Explicitly NOT an AntSword signature, whatever the blog posts say.
static V5_HEX_IDENT: LazyLock<Regex> =
    LazyLock::new(|| rx(r"\$_0[xX]([0-9a-fA-F]{4,})(?:[^A-Za-z0-9_]|$)"));
fn hex_idents(text: &str) -> usize {
    if !text.contains("_0x") && !text.contains("_0X") {
        return 0;
    }
    let set: std::collections::HashSet<String> = V5_HEX_IDENT
        .captures_iter(text)
        .map(|c| c[1].to_ascii_lowercase())
        .collect();
    set.len()
}
// B14 - first-class callable created from an execution sink: system(...). Supporting only -
// FCC creates a Closure, it does not execute. eval(...) is dropped: it is a parse error.
static V5_FCC_SINK: LazyLock<Regex> = LazyLock::new(|| {
    build(&[NOTPFX,
        r"(?:system|exec|shell_exec|passthru|proc_open|popen|assert",
        r"|call_user_func|call_user_func_array|array_map)", SEP, r"\(\s*\.\.\.\s*\)"])
});
// A3 - invisible/bidi Unicode in the FILENAME (upload masquerade). Applied to the path only,
// never to content. Written as escapes on purpose: literal invisibles do not survive review.
static V5_BIDI_NAME: LazyLock<Regex> = LazyLock::new(|| {
    rx("[\u{200b}-\u{200f}\u{202a}-\u{202e}\u{2066}-\u{2069}\u{061c}\u{00ad}\u{feff}\u{2060}-\u{2064}]")
});

// ---------------------------------------------------------------- features

struct Features {
    size: usize,
    entropy: f64,
    ic: f64,
    compress: f64,
    longest_line: usize,
    first_line: usize,
    longest_word: usize,
    longest_b64: usize,
    nonalnum: f64,
    hex_escapes: usize,
    decoders: usize,
    superglobals: usize,
}

fn features(raw: &[u8], text: &str, want_compress: bool) -> Features {
    let n = raw.len();

    // Shannon entropy over the raw bytes.
    let mut freq = [0usize; 256];
    for &b in raw {
        freq[b as usize] += 1;
    }
    let nf = n as f64;
    let entropy = -freq
        .iter()
        .filter(|&&v| v > 0)
        .map(|&v| {
            let p = v as f64 / nf;
            p * p.log2()
        })
        .sum::<f64>();

    // Index of coincidence over the LETTER alphabet only. English prose ~0.0667, uniform
    // random ~0.0385. Legit PHP median 0.0673 / min 0.0541; obfuscated shells median 0.0399.
    let mut lf = [0usize; 26];
    let mut nletters: usize = 0;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            lf[(ch.to_ascii_lowercase() as u8 - b'a') as usize] += 1;
            nletters += 1;
        }
    }
    let ic = if nletters > 1 {
        let l = nletters as f64;
        lf.iter().map(|&v| (v * v.saturating_sub(1)) as f64).sum::<f64>() / (l * (l - 1.0))
    } else {
        1.0
    };

    // Only --json ever shows this; NO scoring rule reads it. Deflating every file was
    // the single biggest cost of a sweep, so it is computed on demand.
    let compress = if want_compress {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(6));
        match enc.write_all(raw).and_then(|_| enc.finish()) {
            Ok(out) => out.len() as f64 / nf,
            Err(_) => 1.0,
        }
    } else {
        0.0
    };

    let mut longest_line = 0usize;
    let mut first_line = 0usize;
    for (i, line) in text.split('\n').enumerate() {
        let l = line.chars().count();
        if i == 0 {
            first_line = l;
        }
        if l > longest_line {
            longest_line = l;
        }
    }

    let longest_word = text.split_whitespace().map(|w| w.chars().count()).max().unwrap_or(0);
    let longest_b64 = B64_RUN.find_iter(text).map(|m| m.as_str().chars().count()).max().unwrap_or(0);

    let mut nchars = 0usize;
    let mut nalnum = 0usize;
    for ch in text.chars() {
        nchars += 1;
        if ch.is_alphanumeric() {
            nalnum += 1;
        }
    }
    let nonalnum = 1.0 - (nalnum as f64 / nchars.max(1) as f64);

    Features {
        size: n,
        entropy,
        ic,
        compress,
        longest_line,
        first_line,
        longest_word,
        longest_b64,
        nonalnum,
        hex_escapes: HEX_ESCAPE.find_iter(text).count(),
        decoders: DECODERS.find_iter(text).count(),
        superglobals: SUPERGLOBAL.find_iter(text).count(),
    }
}

// ---------------------------------------------------------------- verdict

struct Verdict {
    file: String,
    level: &'static str,
    score: i64,
    reasons: Vec<String>,
    metrics: serde_json::Value,
}

fn level_of(score: i64) -> &'static str {
    if score >= 100 {
        "CRITICAL"
    } else if score >= 60 {
        "SUSPECT"
    } else if score >= 30 {
        "WARN"
    } else {
        "CLEAN"
    }
}

/// First N chars of a str, without splitting a UTF-8 boundary.
fn head(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}
/// Last N chars of a str.
fn tail(s: &str, n: usize) -> &str {
    let total = s.chars().count();
    if total <= n {
        return s;
    }
    match s.char_indices().nth(total - n) {
        Some((i, _)) => &s[i..],
        None => s,
    }
}

fn verdict(path: &str, want_metrics: bool) -> Option<Verdict> {
    if EXCLUDE_PATH.is_match(path) {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    if raw.len() > 5_000_000 {
        // PMF's ceiling
        return None;
    }
    // NOTE: no lower size floor for signature checks. The shortest real shell we care about
    // is a 27-byte China Chopper one-liner. A 60-byte floor (NeoPI's) silently missed it.
    // The floor applies to the STATISTICAL block only.

    // Cow: borrows the bytes outright when the file is valid UTF-8 (the common case),
    // instead of allocating a second copy of every file scanned.
    let text = String::from_utf8_lossy(&raw);
    let t: &str = &text;
    let f = features(&raw, t, want_metrics);

    if !PHP_GATE.is_match(head(t, 4096)) && !PHP_GATE.is_match(tail(t, 2048)) {
        return None; // not PHP at all
    }

    // Guarded data files: frameworks store JSON/serialised data/error logs in .php behind a
    // first-statement guard so the content can never execute. MRBS caches are "<?php exit?>",
    // Joomla caches "<?php die('Access Denied'); ?>", AIOS "<?php __halt_compiler();".
    // An error log is the worst case - it quotes the attacker payloads that were logged.
    if GUARDED_DATA.is_match(head(t, 60)) {
        return None;
    }

    let mut score: i64 = 0;
    let mut reasons: Vec<String> = Vec::new();
    macro_rules! add {
        ($pts:expr, $why:expr) => {{
            score += $pts;
            reasons.push(format!("{} (+{})", $why, $pts));
        }};
    }

    // -- deterministic: conclusive on their own -----------------------------------
    // Only the first fingerprint in list order scores (mirrors Python's `break`).
    if let Some(i) = FINGERPRINTS.matches(t).iter().min() {
        add!(100, FINGERPRINT_PATS[i].1);
    }

    if family_k(t) {
        if FAMILY_K_STRONG.is_match(t) || EXEC_SINK.is_match(t) {
            add!(100, "Family-K prepended injector (temp-dir staging)");
        }
    } else if tempnam_dropper(t) {
        add!(100, "tempnam() staging into a temp dir off a superglobal (Family-K)");
    }

    if COOKIE_ARITH.is_match(t) {
        add!(100, "cookie index written as arithmetic (obfuscated shell trigger)");
    }
    if MARKER_PREFIX.is_match(t) {
        add!(60, "file opens with a random-token HTML comment marker");
    }
    if HOMOGLYPH_NAME.is_match(path) {
        add!(100, "filename is a homoglyph of a WordPress core file");
    }
    if BARE_EVAL.is_match(t) {
        add!(100, "bare eval($_REQUEST[..]) prepended to the file");
    }

    if etherhiding_stub(t) {
        add!(100, "EtherHiding JS stub (atob -> XOR -> new Function/TextDecoder)");
    } else if JS_XOR_DECODE.is_match(t) && JS_DYNAMIC_EXEC.is_match(t) {
        add!(100, "XOR-decoded JS handed to new Function() (EtherHiding variant)");
    } else if ETHERHIDING_CHAIN.is_match(t) {
        add!(100, "blockchain C2 lookup (eth_call to a Polygon/BSC RPC)");
    }

    if FAKE_SECURITY_PLUGIN.is_match(t) && !REAL_WF_PATH.is_match(path) {
        add!(100, "plugin impersonating Wordfence outside the real plugin path");
    }
    if ADMIN_BLIND_RETURN.is_match(t) {
        add!(40, "returns early for administrators (supporting signal only)");
    }
    if hidden_php_name(path) {
        add!(40, "hidden filename for an executable file (supporting signal only)");
    }

    // The dropper's tail is the same in every variant regardless of how it decodes the
    // payload: write the decoded bytes out, include the file, unlink it, exit.
    if DROPPER_TAIL.is_match(t) {
        add!(100, "dropper tail: include -> unlink -> exit");
    }

    if raw.starts_with(b"GIF89a")
        || raw.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'])
        || raw.starts_with(&[0xff, 0xd8, 0xff])
    {
        add!(100, "image magic bytes on an executable file");
    }

    // D4: three-way chain. TAINT_CB_FIRSTARG sits between them because the four sinks it
    // owns (register_shutdown_function, register_tick_function, set_error_handler,
    // spl_autoload_register) were listed in v4's TAINT_CB but could never match its shape.
    if V5_TAINT.is_match(t) {
        add!(100, "user input flows straight into an execution sink");
    } else if V5_TAINT_CB_FIRST.is_match(t) {
        add!(90, "user input flows into a first-argument callback sink");
    } else if V5_TAINT_CB.is_match(t) {
        add!(90, "user input flows into a callback sink");
    }
    if superglobal_call(t) {
        add!(100, "superglobal invoked as a function");
    }
    if NESTED_DECODE.is_match(t) {
        add!(90, "execution of a nested decoder chain");
    } else if DOUBLE_DECODE.is_match(t) {
        add!(60, "stacked decoders");
    }

    // ---- v5 signals -------------------------------------------------------------
    if V5_INVOKE_EVAL.is_match(t) {
        add!(90, "eval() as the first statement of an *invoke method (Behinder/Godzilla loader)");
    }
    // Both halves required - see the rule comment.
    if t.contains('^') && V5_KEYSTREAM_INDEX.is_match(t) && V5_XOR_ASSIGN.is_match(t) {
        add!(80, "hand-rolled XOR keystream loop (Behinder/Godzilla loader)");
    }
    if V5_FFI.is_match(t) {
        add!(80, "FFI::cdef/load/scope in a web tree (disable_functions bypass)");
    }
    if V5_CRYPTO.is_match(t) && V5_RAW_BODY.is_match(t) && V5_HARD_SINK.is_match(t) {
        add!(70, "request body decrypted with AES then executed (Behinder/Godzilla)");
    }
    if V5_WS_BINARY_MAP.is_match(t) {
        add!(100, "whitespace-binary stego decoder (tab/space mapped to 1/0)");
    }
    if let Some(name) = reassembled_sink(t) {
        add!(80, format!("sink name assembled from string literals ({name})"));
    }
    // The carrier alone is never a verdict: it needs its reader or a decoder alongside.
    if ws_mixed_run(t) >= 200 {
        if V5_CHR_BINDEC.is_match(t) {
            add!(80, "whitespace-stego carrier with a chr(bindec()) reader");
        } else if f.decoders >= 1 {
            add!(60, "mixed tab/space carrier run alongside a decoder");
        }
    }
    if let Some(pairs) = goto_packer(t) {
        // A high pair count is a self-replicating packer (the fake-cache-plugin recreators
        // score 86-88 pairs) and is near-zero-FP; at >=20 pairs it convicts on its own so a
        // SUSPECT-tier (80) recreator can no longer slip under the CRITICAL line.
        let pts = if pairs >= 20 { 100 } else { 60 };
        add!(pts, format!("goto packer: {pairs} distinct goto/label pairs"));
    }
    let cv = confusable_vars(t);
    if cv >= 3 {
        add!(45, format!("homoglyph-alphabet identifiers ({cv} distinct)"));
    }
    let hx = hex_idents(t);
    if hx >= 3 {
        add!(40, format!("hex-prefixed machine identifiers ({hx} distinct $_0x....)"));
    }
    if t.contains("...") && V5_FCC_SINK.is_match(t) {
        add!(30, "first-class callable created from an execution sink (supporting signal only)");
    }
    if V5_BIDI_NAME.is_match(path) {
        add!(100, "invisible/bidi Unicode in the filename (upload masquerade)");
    }

    // MISC_CRITICAL: first match in list order only. The `goto` rule sits between
    // "php filter chain" and "class name from user input" in the Python list, so it is
    // evaluated at that position to keep the chosen reason identical.
    {
        // D3: the goto entry is gone (superseded by goto_packer at +60), so this is now a
        // plain first-match-wins over the regex list.
        if let Some(i) = MISC_CRITICAL.matches(t).iter().min() {
            add!(70, MISC_CRITICAL_PATS[i].1);
        }
    }

    if let Some(i) = SPAM.matches(t).iter().min() {
        add!(80, format!("spam mailer: {}", SPAM_PATS[i].1));
    }

    // -- statistical ---------------------------------------------------------------
    // Entropy / IC / compression are meaningless on very short files.
    let metrics = |f: &Features| {
        serde_json::json!({
            "size": f.size,
            "entropy": (f.entropy * 10000.0).round() / 10000.0,
            "ic": (f.ic * 10000.0).round() / 10000.0,
            "compress": (f.compress * 10000.0).round() / 10000.0,
            "longest_line": f.longest_line,
            "first_line": f.first_line,
            "longest_word": f.longest_word,
            "longest_b64": f.longest_b64,
            "nonalnum": (f.nonalnum * 10000.0).round() / 10000.0,
            "hex_escapes": f.hex_escapes,
            "decoders": f.decoders,
            "superglobals": f.superglobals,
        })
    };

    if f.size < 200 {
        return Some(Verdict {
            file: path.to_string(),
            level: level_of(score),
            score,
            reasons,
            metrics: metrics(&f),
        });
    }

    // A high-entropy blob only matters if the file can DECODE it. Generated SDK files and
    // inline data: URI logos are statistically identical to a packed shell and produced
    // ~700 sweep false positives until this gate was added; a packed shell always decodes.
    let packed_ok = f.decoders >= 1;

    // Base64/hex blobs are almost all alphanumeric; real PHP is full of $(){};->=.
    if packed_ok && f.nonalnum <= 0.12 && f.longest_word >= 100 {
        add!(70, format!("punctuation-starved code, nonalnum {:.3} (packed blob)", f.nonalnum));
    }
    // Letter-IC below the natural-language floor = near-random identifiers.
    if packed_ok && f.ic < 0.052 && f.longest_word >= 60 {
        add!(60, format!("letter index-of-coincidence {:.4} < 0.052 (random-looking text)", f.ic));
    }
    // Entropy ALONE flags 23/1492 WP-core files; paired with low IC it flags none.
    if packed_ok && f.entropy > 5.30 && f.ic < 0.056 {
        add!(50, format!("entropy {:.2} with low IC {:.4} (obfuscated)", f.entropy, f.ic));
    }
    if packed_ok && f.longest_b64 >= 2000 {
        add!(50, format!("packed payload, base64 blob {}B", f.longest_b64));
    } else if packed_ok && f.longest_b64 >= 260 {
        add!(20, format!("long base64 blob {}B", f.longest_b64));
    }

    // Family-K hides its block on line 1 behind a wall of tabs; clean core tops out ~181.
    if f.first_line >= 500 && f.hex_escapes >= 1 {
        add!(60, format!("first line {}B with {} hex escapes (prepended block)", f.first_line, f.hex_escapes));
    } else if f.longest_line >= 2000 && f.longest_word >= 200 {
        add!(20, format!("packed one-liner, longest line {}B", f.longest_line));
    }

    if f.decoders >= 1 && f.superglobals >= 1 && DECODER_ON_INPUT.is_match(t) {
        add!(70, "decoder applied directly to user input");
    }

    // write -> include -> unlink IS the dropper staging sequence, but WP core does it too
    // (filesystem classes, ID3, privacy-tools). Only count it when the target is a temp dir.
    if WRITE_CALL.is_match(t) && INCLUDE_KW.is_match(t) && UNLINK_CALL.is_match(t) && TEMP_TARGET.is_match(t) {
        add!(50, "write -> include -> unlink staging into a temp dir");
    }

    // NOTE tried and REMOVED: "many \x escapes + superglobals" (WP core carries 38-187 of
    // them, Family-K only 2-4) and bare dangerous-function density (our own honeypot.php
    // sensor scores highest of all clean files on it).

    Some(Verdict {
        file: path.to_string(),
        level: level_of(score),
        score,
        reasons,
        metrics: metrics(&f),
    })
}

// ---------------------------------------------------------------- main

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (mut as_json, mut show_all, mut from_stdin) = (false, false, false);
    let mut paths: Vec<String> = Vec::new();
    let mut threads: Option<usize> = None;

    // Positional args are file paths. `--threads N` consumes its value so a file that
    // happens to be named like a number is never swallowed.
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => as_json = true,
            "--all" => show_all = true,
            "--stdin" => from_stdin = true,
            "--threads" => threads = it.next().and_then(|s| s.parse::<usize>().ok()),
            other if other.starts_with("--") => {} // ignore unknown flags
            other => paths.push(other.to_string()),
        }
    }
    if let Some(n) = threads {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
    }

    // One process for a whole sweep: accept NUL- or newline-separated paths on stdin.
    if from_stdin {
        let mut buf = Vec::new();
        if std::io::stdin().read_to_end(&mut buf).is_ok() {
            let sep = if buf.contains(&0) { 0u8 } else { b'\n' };
            paths.extend(
                buf.split(|&b| b == sep)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
    }

    // Order-preserving parallel scan.
    let results: Vec<Option<Verdict>> = paths.par_iter().map(|p| verdict(p, as_json)).collect();

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for v in results.into_iter().flatten() {
        if as_json {
            let obj = serde_json::json!({
                "file": v.file,
                "level": v.level,
                "score": v.score,
                "reasons": v.reasons,
                "metrics": v.metrics,
            });
            let _ = writeln!(out, "{obj}");
        } else if show_all || v.level != "CLEAN" {
            let shown: Vec<&str> = v.reasons.iter().take(3).map(|s| s.as_str()).collect();
            let _ = writeln!(out, "{:<8} {:>4}  {} :: {}", v.level, v.score, v.file, shown.join("; "));
        }
    }
}
