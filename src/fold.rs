// B6b - constant-fold string expressions and test the RESULT against the sink set. B6 only joins
// plain literals ('sys'.'tem'); the korat ga.php loader (2026-10-31) built its names with
// 'base64_' . chr(100) . 'ecode' and strrev('ecalper_rts') and scored CLEAN 0. Rather than add a
// signature per trick, evaluate the small pure-string subset of PHP that obfuscators use:
//   'lit' "lit\x41\101" chr(N) strrev() str_rot13() strtolower() strtoupper() base64_decode()
//   hex2bin() ucfirst() ( ... ) joined with '.'
// An expression only counts if it used a transform (a call or an escape) - plain concatenation is
// B6's job and keeps its own score. Results are bounded (64 bytes) and never executed.
const FOLD_FUNCS: &[&str] = &[
    "chr", "strrev", "str_rot13", "strtolower", "strtoupper", "base64_decode", "hex2bin", "ucfirst",
];

struct Folder<'a> {
    b: &'a [u8],
    used_transform: bool,
}

impl<'a> Folder<'a> {
    fn ws(&self, mut i: usize) -> usize {
        while i < self.b.len() && self.b[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    }
    fn lit(&mut self, i: usize) -> Option<(Vec<u8>, usize)> {
        let q = *self.b.get(i)?;
        if q != b'\'' && q != b'"' {
            return None;
        }
        let mut out = Vec::new();
        let mut j = i + 1;
        while j < self.b.len() && j - i < 256 {
            let c = self.b[j];
            if c == q {
                return Some((out, j + 1));
            }
            if c == b'\n' {
                return None;
            }
            if c == b'\\' && j + 1 < self.b.len() {
                let n = self.b[j + 1];
                if q == b'\'' {
                    if n == b'\\' || n == b'\'' {
                        out.push(n);
                        j += 2;
                        continue;
                    }
                } else if n == b'x' {
                    let h: String = self.b[j + 2..].iter().take(2).take_while(|c| c.is_ascii_hexdigit()).map(|&c| c as char).collect();
                    if !h.is_empty() {
                        out.push(u8::from_str_radix(&h, 16).ok()?);
                        self.used_transform = true;
                        j += 2 + h.len();
                        continue;
                    }
                } else if n.is_ascii_digit() && n < b'8' {
                    let o: String = self.b[j + 1..].iter().take(3).take_while(|c| (b'0'..b'8').contains(c)).map(|&c| c as char).collect();
                    out.push(u8::from_str_radix(&o, 8).ok()? as u8);
                    self.used_transform = true;
                    j += 1 + o.len();
                    continue;
                } else if n == b'$' || n == b'"' || n == b'\\' {
                    out.push(n);
                    j += 2;
                    continue;
                }
            } else if q == b'"' && c == b'$' {
                return None; // interpolation: not a constant
            }
            out.push(c);
            j += 1;
        }
        None
    }
    fn int(&self, i: usize) -> Option<(u32, usize)> {
        let s = &self.b[i..self.b.len().min(i + 12)];
        let (radix, skip) = if s.len() > 2 && s[0] == b'0' && (s[1] | 0x20) == b'x' { (16, 2) } else { (10, 0) };
        let d: String = s[skip..].iter().take_while(|c| c.is_ascii_hexdigit() && (radix == 16 || c.is_ascii_digit())).map(|&c| c as char).collect();
        if d.is_empty() {
            return None;
        }
        Some((u32::from_str_radix(&d, radix).ok()?, i + skip + d.len()))
    }
    fn term(&mut self, i: usize, depth: u8) -> Option<(Vec<u8>, usize)> {
        if depth > 6 {
            return None;
        }
        let i = self.ws(i);
        if let Some(r) = self.lit(i) {
            return Some(r);
        }
        if self.b.get(i) == Some(&b'(') {
            let (v, j) = self.expr(i + 1, depth + 1)?;
            let j = self.ws(j);
            return (self.b.get(j) == Some(&b')')).then_some((v, j + 1));
        }
        // a call is only a fold function if it is not a method/function-name suffix (->chr, xchr)
        if i > 0 && (self.b[i - 1].is_ascii_alphanumeric() || matches!(self.b[i - 1], b'_' | b'>' | b'$' | b':')) {
            return None;
        }
        for f in FOLD_FUNCS {
            let fb = f.as_bytes();
            if self.b.len() >= i + fb.len() && self.b[i..i + fb.len()].eq_ignore_ascii_case(fb) {
                let j = self.ws(i + fb.len());
                if self.b.get(j) != Some(&b'(') {
                    continue;
                }
                let j = self.ws(j + 1);
                let (v, j) = if *f == "chr" {
                    let (n, j) = self.int(j)?;
                    (vec![(n % 256) as u8], j)
                } else {
                    let (a, j) = self.expr(j, depth + 1)?;
                    (apply(f, a)?, j)
                };
                let j = self.ws(j);
                if self.b.get(j) != Some(&b')') {
                    return None;
                }
                self.used_transform = true;
                return Some((v, j + 1));
            }
        }
        None
    }
    fn expr(&mut self, i: usize, depth: u8) -> Option<(Vec<u8>, usize)> {
        let (mut v, mut j) = self.term(i, depth)?;
        loop {
            let k = self.ws(j);
            if self.b.get(k) != Some(&b'.') || self.b.get(k + 1) == Some(&b'=') {
                return Some((v, j));
            }
            match self.term(k + 1, depth) {
                Some((w, j2)) if v.len() + w.len() <= 64 => {
                    v.extend(w);
                    j = j2;
                }
                _ => return Some((v, j)),
            }
        }
    }
}

fn apply(f: &str, a: Vec<u8>) -> Option<Vec<u8>> {
    Some(match f {
        "strrev" => a.into_iter().rev().collect(),
        "strtolower" => a.to_ascii_lowercase(),
        "strtoupper" => a.to_ascii_uppercase(),
        "ucfirst" => {
            let mut a = a;
            if let Some(c) = a.first_mut() {
                c.make_ascii_uppercase();
            }
            a
        }
        "str_rot13" => a
            .into_iter()
            .map(|c| match c {
                b'a'..=b'z' => (c - b'a' + 13) % 26 + b'a',
                b'A'..=b'Z' => (c - b'A' + 13) % 26 + b'A',
                _ => c,
            })
            .collect(),
        "hex2bin" => {
            if a.len() % 2 != 0 || a.len() > 128 {
                return None;
            }
            a.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect::<Option<Vec<u8>>>()?
        }
        "base64_decode" => b64(&a)?,
        _ => return None,
    })
}

fn b64(a: &[u8]) -> Option<Vec<u8>> {
    if a.len() > 128 {
        return None;
    }
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
    for &c in a.iter().filter(|&&c| c != b'=') {
        acc = (acc << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// Anchors: the transforms that change bytes, and escape-bearing double-quoted strings. Plain
// strtolower()/ucfirst() are everywhere in honest code and only matter inside such an expression.
static FOLD_ANCHOR: LazyLock<Regex> = LazyLock::new(|| {
    rx(r#"(?i)(?:^|[^\w$>:])(?:chr|strrev|str_rot13|base64_decode|hex2bin)\s*\(|"[^"\n]{0,64}\\(?:x[0-9a-fA-F]|[0-7]{2})"#)
});

/// First sink name produced by a transformed constant string expression, if any.
fn folded_sink(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut done = 0usize;
    for m in FOLD_ANCHOR.find_iter(text) {
        // the expression may start up to ~160 bytes before the anchor ('base64_' . chr(100) ...):
        // try every quote/paren/identifier start in that window, nearest first
        let lo = m.start().saturating_sub(160).max(done);
        let mut cands: Vec<usize> = (lo..=m.start().min(b.len().saturating_sub(1)))
            .filter(|&i| matches!(b[i], b'\'' | b'"' | b'(') || (i == m.start()))
            .collect();
        cands.push((m.start()..m.end()).find(|&i| b[i].is_ascii_alphabetic() || b[i] == b'"').unwrap_or(m.start()));
        for &i in cands.iter() {
            let mut f = Folder { b, used_transform: false };
            if let Some((v, j)) = f.expr(i, 0) {
                if j <= m.start() {
                    continue; // ended before the anchor - not the expression that contains it
                }
                if f.used_transform && v.len() >= 4 && v.len() <= 24 {
                    if let Ok(s) = std::str::from_utf8(&v) {
                        let n = s.trim().trim_matches('\\').to_ascii_lowercase();
                        if V5_SINK_NAMES.contains(&n.as_str()) {
                            return Some(n);
                        }
                    }
                }
            }
        }
        done = m.end();
    }
    None
}

