//! Harness for the disabled-entrypoint isolation regressions (stow#593).
//!
//! Each of the five `disabled_manually` workflows is parsed as YAML, its
//! `run:` steps are substituted with only the `${{ … }}` values the
//! Actions engine supplies (inputs, event payload, env, step outputs),
//! and the resolved script executes under `bash` with a PATH of
//! recording stubs. External tools (`gh`, `curl`, `stow-admin`,
//! `cargo`, `date`, …) append one tab-separated record per invocation to
//! a per-scenario log; assertions read that log, so every external side
//! effect a step would have is captured instead of performed. `uses:`
//! steps and Actions-side semantics (cache keys, concurrency, `if:`,
//! permissions) are asserted as declarations parsed from the same YAML
//! — never emulated.

#![allow(clippy::missing_panics_doc)] // every public helper fails a test loudly

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_yml::Value;

/// The workflows directory, resolved against this crate so the tests
/// always read the checked-out files.
pub fn workflows_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github")
        .join("workflows")
}

/// Parse one workflow file under `.github/workflows/`.
///
/// # Panics
/// The file is missing or is not YAML.
#[must_use]
pub fn load_workflow(file: &str) -> Value {
    let path = workflows_dir().join(file);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// `map[k]` for a YAML mapping, or `None` for any other shape.
#[must_use]
pub fn field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    value.as_mapping()?.get(key)
}

/// Field lookup down a dotted path (`"on.schedule"`, `"jobs.preheat"`).
#[must_use]
pub fn at<'v>(value: &'v Value, path: &str) -> Option<&'v Value> {
    let mut cur = value;
    for seg in path.split('.') {
        cur = field(cur, seg)?;
    }
    Some(cur)
}

/// A YAML scalar as the string Actions would interpolate.
///
/// # Panics
/// The value is a mapping or sequence.
#[must_use]
pub fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => panic!("expected scalar, found {other:?}"),
    }
}

/// One `steps[]` entry of a job.
#[derive(Debug, Clone)]
pub struct Step {
    /// `name:` (falls back to `id:`/`uses:` for identification).
    pub name: String,
    /// `id:` — the `steps.<id>` context key.
    pub id: Option<String>,
    /// `uses:` — present for action steps, which never execute here.
    pub uses: Option<String>,
    /// The literal `run:` script (unsubstituted).
    pub run: Option<String>,
    /// The literal `if:` condition (unsubstituted, `${{}}` stripped later).
    pub if_cond: Option<String>,
    /// `env:` name → unsubstituted value.
    pub env: BTreeMap<String, String>,
    /// `with:` name → unsubstituted value.
    pub with: BTreeMap<String, String>,
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(Value::Mapping(map)) = value {
        for (k, v) in map {
            out.insert(scalar(k), scalar(v));
        }
    }
    out
}

/// The steps of `wf.jobs.<job>` in order.
///
/// # Panics
/// The job or its `steps:` sequence is missing.
#[must_use]
pub fn job_steps(wf: &Value, job: &str) -> Vec<Step> {
    let job_v = at(wf, &format!("jobs.{job}")).unwrap_or_else(|| panic!("no job {job}"));
    let list = field(job_v, "steps")
        .and_then(Value::as_sequence)
        .unwrap_or_else(|| panic!("job {job} has no steps"));
    list.iter()
        .enumerate()
        .map(|(i, s)| Step {
            name: field(s, "name").map_or_else(
                || field(s, "uses").map_or_else(|| format!("step {i}"), scalar),
                scalar,
            ),
            id: field(s, "id").map(scalar),
            uses: field(s, "uses").map(scalar),
            run: field(s, "run").map(scalar),
            if_cond: field(s, "if").map(scalar),
            env: string_map(field(s, "env")),
            with: string_map(field(s, "with")),
        })
        .collect()
}

/// Job-level `env:` map (unsubstituted values).
#[must_use]
pub fn job_env(wf: &Value, job: &str) -> BTreeMap<String, String> {
    string_map(at(wf, &format!("jobs.{job}.env")))
}

/// Workflow-level `env:` map (unsubstituted values).
#[must_use]
pub fn workflow_env(wf: &Value) -> BTreeMap<String, String> {
    string_map(field(wf, "env"))
}

/// `on.workflow_dispatch.inputs` as `name → (default, required, type)`.
///
/// Dispatch inputs declare a `default:`; callers override per scenario
/// and the context carries exactly what the Actions `inputs` context
/// would (an explicitly provided value, else the declared default).
#[must_use]
pub fn dispatch_inputs(wf: &Value) -> BTreeMap<String, Option<Val>> {
    let mut out = BTreeMap::new();
    let Some(Value::Mapping(inputs)) = at(wf, "on.workflow_dispatch.inputs") else {
        return out;
    };
    for (k, v) in inputs {
        let default = field(v, "default").map(yaml_val);
        out.insert(scalar(k), default);
    }
    out
}

fn yaml_val(v: &Value) -> Val {
    match v {
        Value::Null => Val::Null,
        Value::Bool(b) => Val::Bool(*b),
        Value::Number(n) => n.as_f64().map_or(Val::Null, Val::Num),
        Value::String(s) => Val::Str(s.clone()),
        Value::Sequence(seq) => Val::Obj(
            seq.iter()
                .enumerate()
                .map(|(i, x)| (i.to_string(), yaml_val(x)))
                .collect(),
        ),
        Value::Mapping(map) => {
            Val::Obj(map.iter().map(|(k, x)| (scalar(k), yaml_val(x))).collect())
        }
        Value::Tagged(tagged) => yaml_val(&tagged.value),
    }
}

// ---------------------------------------------------------------------------
// Expression evaluation — only the ${{
// }} subset the five workflows use.
// ---------------------------------------------------------------------------

/// A value in the Actions expression language (plus `Obj` for contexts).
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// `${{ null }}` or an unset key.
    Null,
    /// Boolean.
    Bool(bool),
    /// Number.
    Num(f64),
    /// String.
    Str(String),
    /// A context object (`inputs`, `github`, `steps`, …).
    Obj(BTreeMap<String, Self>),
}

impl Val {
    /// Actions truthiness: non-empty strings other than `"false"` are
    /// true, `0`/`null`/`false` are false.
    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Num(n) => *n != 0.0,
            Self::Str(s) => !s.is_empty() && s != "false",
            Self::Obj(_) => true,
        }
    }

    /// String interpolation form of the value.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(b) => b.to_string(),
            Self::Num(n) => n.to_string(),
            Self::Str(s) => s.clone(),
            Self::Obj(_) => "Object".to_owned(),
        }
    }

    /// `self` as a fresh `Obj` root — the expression context is one.
    #[must_use]
    pub const fn context() -> Self {
        Self::Obj(BTreeMap::new())
    }
}

/// Set `path` (dotted) to `v` inside an `Obj` tree, creating maps.
///
/// # Panics
/// An intermediate segment is a non-object.
pub fn set_path(root: &mut Val, path: &str, v: Val) {
    let Val::Obj(map) = root else {
        panic!("context root is not an object")
    };
    let mut cur = map;
    let mut segs = path.split('.').peekable();
    while let Some(seg) = segs.next() {
        if segs.peek().is_none() {
            cur.insert(seg.to_owned(), v);
            return;
        }
        cur = match cur
            .entry(seg.to_owned())
            .or_insert_with(|| Val::Obj(BTreeMap::new()))
        {
            Val::Obj(m) => m,
            other => panic!("{path}: segment {seg} occupied by {other:?}"),
        };
    }
}

/// Whether `path` resolves in the context (for "provided input beats
/// declared default" rules).
#[must_use]
pub fn ctx_has(root: &Val, path: &str) -> bool {
    get_path(root, path).is_some()
}

fn get_path<'v>(root: &'v Val, path: &str) -> Option<&'v Val> {
    let mut cur = root;
    for seg in path.split('.') {
        let Val::Obj(map) = cur else { return None };
        cur = map.get(seg)?;
    }
    Some(cur)
}

/// Whether the job has failed so far — what `success()`/`failure()`
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No preceding step failed.
    Ok,
    /// At least one preceding step failed.
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    LParen,
    RParen,
    Bang,
    And,
    Or,
    Eq,
    Neq,
    Dot,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        match b[i] {
            b' ' | b'\t' | b'\n' => i += 1,
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            b'!' if b.get(i + 1) == Some(&b'=') => {
                out.push(Tok::Neq);
                i += 2;
            }
            b'!' => {
                out.push(Tok::Bang);
                i += 1;
            }
            b'=' if b.get(i + 1) == Some(&b'=') => {
                out.push(Tok::Eq);
                i += 2;
            }
            b'&' if b.get(i + 1) == Some(&b'&') => {
                out.push(Tok::And);
                i += 2;
            }
            b'|' if b.get(i + 1) == Some(&b'|') => {
                out.push(Tok::Or);
                i += 2;
            }
            b'\'' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                if j == b.len() {
                    return Err(format!("unterminated string in {src:?}"));
                }
                out.push(Tok::Str(src[start..j].to_owned()));
                i = j + 1;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                let text = &src[start..i];
                out.push(Tok::Num(
                    text.parse::<f64>()
                        .map_err(|e| format!("bad number {text:?}: {e}"))?,
                ));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-')
                {
                    i += 1;
                }
                out.push(Tok::Ident(src[start..i].to_owned()));
            }
            c => return Err(format!("unsupported character {:?} in {src:?}", c as char)),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    ctx: &'a Val,
    status: Status,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<(), String> {
        match self.next() {
            Some(t) if &t == want => Ok(()),
            other => Err(format!("expected {what}, found {other:?}")),
        }
    }

    fn or(&mut self) -> Result<Val, String> {
        let mut lhs = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            let rhs = self.and()?;
            // Actions `||` returns the first truthy operand's value.
            lhs = if lhs.truthy() { lhs } else { rhs };
        }
        Ok(lhs)
    }

    fn and(&mut self) -> Result<Val, String> {
        let mut lhs = self.cmp()?;
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            let rhs = self.cmp()?;
            lhs = if lhs.truthy() { rhs } else { Val::Bool(false) };
        }
        Ok(lhs)
    }

    fn cmp(&mut self) -> Result<Val, String> {
        let lhs = self.unary()?;
        match self.peek() {
            Some(Tok::Eq) => {
                self.pos += 1;
                let rhs = self.unary()?;
                Ok(Val::Bool(eq(&lhs, &rhs)))
            }
            Some(Tok::Neq) => {
                self.pos += 1;
                let rhs = self.unary()?;
                Ok(Val::Bool(!eq(&lhs, &rhs)))
            }
            _ => Ok(lhs),
        }
    }

    fn unary(&mut self) -> Result<Val, String> {
        if self.peek() == Some(&Tok::Bang) {
            self.pos += 1;
            return Ok(Val::Bool(!self.unary()?.truthy()));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Val, String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Val::Str(s)),
            Some(Tok::Num(n)) => Ok(Val::Num(n)),
            Some(Tok::LParen) => {
                let v = self.or()?;
                self.expect(&Tok::RParen, "')'")?;
                Ok(v)
            }
            Some(Tok::Ident(name)) => {
                if self.peek() == Some(&Tok::LParen) {
                    self.pos += 1;
                    self.expect(&Tok::RParen, "')' after status fn")?;
                    return self.status_fn(&name);
                }
                let mut path = name;
                while self.peek() == Some(&Tok::Dot) {
                    self.pos += 1;
                    match self.next() {
                        Some(Tok::Ident(seg)) => {
                            path.push('.');
                            path.push_str(&seg);
                        }
                        other => return Err(format!("bad path segment: {other:?}")),
                    }
                }
                Ok(get_path(self.ctx, &path).cloned().unwrap_or(Val::Null))
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }

    fn status_fn(&self, name: &str) -> Result<Val, String> {
        Ok(Val::Bool(match name {
            "success" => self.status == Status::Ok,
            "failure" => self.status == Status::Failed,
            "cancelled" => false, // the harness never cancels a job
            "always" => true,
            other => return Err(format!("unsupported function {other}()")),
        }))
    }
}

/// Loose equality for `==`/`!=` — strings compare textually, a null
/// never equals a non-null.
fn eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Str(x), Val::Str(y)) => x == y,
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Num(x), Val::Num(y)) => x == y,
        (Val::Null, Val::Null) => true,
        // String vs bool: Actions coerces the bool to its text form.
        (Val::Str(x), Val::Bool(y)) | (Val::Bool(y), Val::Str(x)) => {
            x == if *y { "true" } else { "false" }
        }
        _ => false,
    }
}

/// Evaluate an Actions `${{ }}` expression (with or without the
/// delimiters) against `ctx`.
///
/// # Errors
/// The expression uses syntax outside the supported subset.
pub fn eval(src: &str, ctx: &Val, status: Status) -> Result<Val, String> {
    let trimmed = src.trim();
    let inner = trimmed
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .unwrap_or(trimmed);
    let mut p = Parser {
        toks: lex(inner)?,
        pos: 0,
        ctx,
        status,
    };
    let v = p.or()?;
    if p.pos != p.toks.len() {
        return Err(format!("trailing tokens in {inner:?}"));
    }
    Ok(v)
}

/// Interpolate every `${{ expr }}` inside `text`.
///
/// # Panics
/// An expression fails to parse — a malformed workflow fails loudly.
#[must_use]
pub fn substitute(text: &str, ctx: &Val, status: Status) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = after
            .find("}}")
            .unwrap_or_else(|| panic!("unclosed ${{{{ in {text:?}"));
        let expr = &after[..end];
        let v = eval(expr, ctx, status).unwrap_or_else(|e| panic!("eval {expr:?}: {e}"));
        out.push_str(&v.render());
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Evaluate a step `if:` — bare or `${{}}`-wrapped. Absent `if:` is the
/// implicit `success()`.
///
/// # Panics
/// The condition uses unsupported syntax.
#[must_use]
pub fn eval_if(cond: Option<&str>, ctx: &Val, status: Status) -> bool {
    cond.map_or_else(
        || status == Status::Ok,
        |c| {
            eval(c, ctx, status)
                .unwrap_or_else(|e| panic!("eval if `{c}`: {e}"))
                .truthy()
        },
    )
}

// ---------------------------------------------------------------------------
// Stubs and step execution.
// ---------------------------------------------------------------------------

/// The env names every stub records (secret-shaped names are masked to
/// `<set>`/`<empty>` — presence is asserted, values never logged).
pub const STUB_ENV_KEYS: &str = "GH_REPO GH_TOKEN GITHUB_TOKEN RUSTC_VERSION TARGETS LIMIT \
     TOP_BINARIES SINCE_DAYS EVENT_NAME RUN_TITLE STOW_EDGE_URL STOW_OIDC_AUDIENCE \
     CF_ACCOUNT_ID CF_ANALYTICS_TOKEN";

const STUB_SCRIPT: &str = r#"#!/usr/bin/env bash
# stow#593 recorder stub — one tab-separated record per invocation, then
# behavior driven by STUB_* environment variables (a "plan"), never by
# guessing. Records: <tool>\t<arg>…\t@@NAME=value… — secret-shaped names
# are masked to <set>/<empty> so presence is asserted without logging it.
tool="$(basename "$0")"
{
  printf '%s' "$tool"
  for a in "$@"; do printf '\t%s' "$a"; done
  for k in $STUB_ENV_KEYS; do
    v="${!k-}"
    case "$k" in
      *TOKEN*|*SECRET*|*KEY*|*PASSWORD*)
        if [ -n "$v" ]; then v='<set>'; else v='<empty>'; fi;;
    esac
    printf '\t@@%s=%s' "$k" "$v"
  done
  printf '\n'
} >> "$STUB_LOG"

case "$tool" in
  date)
    # The cron marker key is day-scoped; the scenario pins the day.
    case " $* " in
      *"+%Y-%m-%d"*) printf '%s\n' "${STUB_DATE:?STUB_DATE unset}"; exit 0;;
    esac
    exec /usr/bin/date "$@";;
  curl)
    url="${!#}"
    case "$url" in
      *channel-rust-stable.toml) cat "${STUB_CHANNEL_TOML:?}"; exit 0;;
      *) exit "${STUB_CURL_EXIT:-0}";;
    esac;;
  stow-admin)
    prev=""
    for a in "$@"; do
      if [ "$prev" = "--output" ]; then
        mkdir -p "$(dirname "$a")"
        printf '%s' "${STUB_OUTPUT_CONTENT-}" > "$a"
      fi
      prev="$a"
    done
    if [ -n "${STUB_STDOUT-}" ]; then printf '%s' "$STUB_STDOUT"; fi
    if [ -n "${STUB_FAIL_RE-}" ] && [[ "$*" =~ $STUB_FAIL_RE ]]; then exit 1; fi
    exit "${STUB_ADMIN_EXIT:-0}";;
  gh|cargo|cosign|oras|docker)
    exit "${STUB_TOOL_EXIT:-0}";;
  *)
    exit "${STUB_TOOL_EXIT:-0}";;
esac
"#;

/// One recorded stub invocation.
#[derive(Debug, Clone)]
pub struct Call {
    /// The tool name (`argv[0]` basename).
    pub tool: String,
    /// argv[1..].
    pub argv: Vec<String>,
    /// Allowlisted env observed (`@@NAME=value` records).
    pub env: BTreeMap<String, String>,
}

impl fmt::Display for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.tool, self.argv.join(" "))
    }
}

/// The directory of a `python3` that has `tomllib` — the channel step's
/// `python3 -c 'import tomllib …'` needs ≥3.11, which is not every
/// box's `/usr/bin/python3`. Probe: explicit override, the caller's own
/// PATH python, then common installs.
fn python3_dir() -> Option<PathBuf> {
    let has_tomllib = |bin: &Path| {
        Command::new(bin)
            .args(["-c", "import tomllib"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if let Ok(override_path) = std::env::var("STOW_TEST_PYTHON3") {
        let bin = PathBuf::from(override_path);
        if has_tomllib(&bin) {
            return bin.parent().map(Path::to_path_buf);
        }
    }
    if let Ok(out) = Command::new("bash")
        .args(["-c", "command -v python3"])
        .output()
    {
        let bin = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        if has_tomllib(&bin) {
            return bin.parent().map(Path::to_path_buf);
        }
    }
    for bin in [
        format!(
            "{}/.pyenv/shims/python3",
            std::env::var("HOME").unwrap_or_default()
        ),
        "/usr/local/bin/python3".to_owned(),
        "/usr/bin/python3".to_owned(),
    ] {
        let bin = PathBuf::from(bin);
        if has_tomllib(&bin) {
            return bin.parent().map(Path::to_path_buf);
        }
    }
    None
}

/// An isolated working directory + stub PATH + invocation log.
#[derive(Debug)]
pub struct Scenario {
    dir: tempfile::TempDir,
    stub_dir: PathBuf,
    python_dir: Option<PathBuf>,
    log: PathBuf,
}

impl Scenario {
    /// Fresh scenario: `bin/` with the recorder stubs, `work/` the
    /// step CWD (with `target/release/stow-admin` also stubbed, the
    /// path the workflows invoke after `cargo build`).
    #[must_use]
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("scenario tempdir");
        let stub_dir = dir.path().join("bin");
        std::fs::create_dir_all(&stub_dir).expect("mkdir bin");
        for tool in [
            "gh",
            "curl",
            "date",
            "stow-admin",
            "cargo",
            "cosign",
            "oras",
            "docker",
        ] {
            let path = stub_dir.join(tool);
            std::fs::write(&path, STUB_SCRIPT).expect("write stub");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod stub");
            }
        }
        let work = dir.path().join("work");
        let admin_path = work.join("target/release/stow-admin");
        std::fs::create_dir_all(admin_path.parent().expect("parent")).expect("mkdir work");
        std::fs::write(&admin_path, STUB_SCRIPT).expect("write admin stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&admin_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod admin stub");
        }
        let log = dir.path().join("stub.log");
        std::fs::write(&log, "").expect("touch log");
        Self {
            dir,
            stub_dir,
            python_dir: python3_dir(),
            log,
        }
    }

    /// The step working directory.
    #[must_use]
    pub fn workdir(&self) -> PathBuf {
        self.dir.path().join("work")
    }

    /// PATH value putting the stubs first, then a tomllib-capable
    /// python's directory when one exists, then the base tools.
    #[must_use]
    pub fn path(&self) -> String {
        format!(
            "{}{}:/usr/bin:/bin",
            self.stub_dir.display(),
            self.python_dir
                .as_ref()
                .map_or_else(String::new, |d| format!(":{}", d.display()))
        )
    }

    /// The stub log path (`STUB_LOG` for the step env).
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.log.clone()
    }

    /// Every recorded invocation, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        let text = std::fs::read_to_string(&self.log).expect("read stub.log");
        text.lines()
            .map(|line| {
                let mut argv = Vec::new();
                let mut env = BTreeMap::new();
                let mut it = line.split('\t');
                let tool = it.next().unwrap_or("").to_owned();
                for part in it {
                    if let Some(kv) = part.strip_prefix("@@") {
                        if let Some((k, v)) = kv.split_once('=') {
                            env.insert(k.to_owned(), v.to_owned());
                        }
                    } else {
                        argv.push(part.to_owned());
                    }
                }
                Call { tool, argv, env }
            })
            .collect()
    }

    /// Recorded invocations of one tool.
    #[must_use]
    pub fn calls_of(&self, tool: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.tool == tool)
            .collect()
    }
}

/// What a step did under the harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A `run:` step executed; carries the exit code.
    Ran(i32),
    /// The `if:` (or implicit `success()`) deselected it.
    Skipped,
    /// A `uses:` step — declared, never executed here.
    Declared,
}

/// Executes one job's steps against a scenario.
#[derive(Debug)]
pub struct Runner<'a> {
    /// The scenario (workdir + stubs + log).
    pub scn: &'a Scenario,
    /// The expression context root (`Obj` containing `inputs`,
    /// `github`, `env`, `steps`, …).
    pub ctx: Val,
    /// Environment variables injected into every `run:` step
    /// (the scenario's `STUB_*` plan lives here).
    pub base_env: BTreeMap<String, String>,
    status: Status,
    /// Per-step outcomes, in order.
    pub outcomes: Vec<(String, Outcome)>,
}

impl<'a> Runner<'a> {
    /// A runner for `scn` with the given context and plan env.
    #[must_use]
    pub const fn new(scn: &'a Scenario, ctx: Val, base_env: BTreeMap<String, String>) -> Self {
        Self {
            scn,
            ctx,
            base_env,
            status: Status::Ok,
            outcomes: Vec::new(),
        }
    }

    /// Seed a step's outputs the way the Actions engine would have
    /// produced them (`steps.<id>.outputs.<name>`).
    pub fn seed_output(&mut self, step: &str, name: &str, value: &str) {
        set_path(
            &mut self.ctx,
            &format!("steps.{step}.outputs.{name}"),
            Val::Str(value.to_owned()),
        );
    }

    /// The job's failure status after the steps run so far.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// Run every step of `wf.jobs.<job>` in order, applying `if:` and
    /// status rules; `uses:` steps resolve to `Declared`.
    ///
    /// # Panics
    /// A script has a bad expression or the step I/O fails.
    pub fn run_job(&mut self, wf: &Value, job: &str) {
        let steps = job_steps(wf, job);
        let wf_env = workflow_env(wf);
        let jenv = job_env(wf, job);
        for step in steps {
            let outcome = self.run_step(&step, &wf_env, &jenv);
            self.outcomes.push((step.name.clone(), outcome));
        }
    }

    fn run_step(
        &mut self,
        step: &Step,
        wf_env: &BTreeMap<String, String>,
        job_env: &BTreeMap<String, String>,
    ) -> Outcome {
        let selected = eval_if(step.if_cond.as_deref(), &self.ctx, self.status);
        if !selected {
            return Outcome::Skipped;
        }
        if step.uses.is_some() {
            return Outcome::Declared;
        }
        let Some(script_src) = &step.run else {
            return Outcome::Declared;
        };

        // Layered env: harness base < workflow < job < step — each
        // value substituted against the context at selection time.
        let mut env = self.base_env.clone();
        for (k, v) in wf_env {
            env.insert(k.clone(), substitute(v, &self.ctx, self.status));
        }
        for (k, v) in job_env {
            env.insert(k.clone(), substitute(v, &self.ctx, self.status));
        }
        for (k, v) in &step.env {
            env.insert(k.clone(), substitute(v, &self.ctx, self.status));
        }

        let out_file = self
            .scn
            .dir
            .path()
            .join(format!("github_output_{}", self.outcomes.len()));
        env.insert("GITHUB_OUTPUT".to_owned(), out_file.display().to_string());
        env.insert(
            "GITHUB_WORKSPACE".to_owned(),
            self.scn.workdir().display().to_string(),
        );
        env.insert(
            "STUB_LOG".to_owned(),
            self.scn.log_path().display().to_string(),
        );
        env.insert("STUB_ENV_KEYS".to_owned(), STUB_ENV_KEYS.to_owned());
        env.insert("PATH".to_owned(), self.scn.path());
        env.insert("HOME".to_owned(), self.scn.dir.path().display().to_string());

        let script = substitute(script_src, &self.ctx, self.status);
        let result = Command::new("bash")
            .arg("-c")
            .arg(&script)
            .current_dir(self.scn.workdir())
            .env_clear()
            .envs(&env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn bash");
        let code = result.status.code().unwrap_or(-1);
        if code != 0 {
            self.status = Status::Failed;
            eprintln!(
                "step {:?} exited {code}\nstdout:\n{}\nstderr:\n{}",
                step.name,
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        if let Some(id) = &step.id {
            for (k, v) in parse_github_output(&out_file) {
                set_path(
                    &mut self.ctx,
                    &format!("steps.{id}.outputs.{k}"),
                    Val::Str(v),
                );
            }
        }
        Outcome::Ran(code)
    }

    /// The recorded outcome of the step named `name`.
    ///
    /// # Panics
    /// No step with that name ran.
    #[must_use]
    pub fn outcome_of(&self, name: &str) -> &Outcome {
        self.outcomes.iter().find(|(n, _)| n == name).map_or_else(
            || panic!("no step named {name:?}; have {:?}", self.outcomes),
            |(_, o)| o,
        )
    }
}

/// `name=value` and `name<<DELIM` forms of `$GITHUB_OUTPUT`.
fn parse_github_output(path: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some((name, delim)) = line.split_once("<<") {
            let mut body = String::new();
            for l in lines.by_ref() {
                if l == delim {
                    break;
                }
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(l);
            }
            out.push((name.to_owned(), body));
        } else if let Some((name, value)) = line.split_once('=') {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

/// Resolve `steps.<id>.outputs.<name>` to a string.
///
/// # Panics
/// The output was never produced.
#[must_use]
pub fn step_output(ctx: &Val, step: &str, name: &str) -> String {
    get_path(ctx, &format!("steps.{step}.outputs.{name}"))
        .unwrap_or_else(|| panic!("steps.{step}.outputs.{name} unset"))
        .render()
}
