// config.json: written by the user (directly or through `netwhere
// classify` / `netwhere rules`), read by the elevated collector, which
// treats it as untrusted input: size limit, every field checked, unknown
// fields ignored.
//
// {
//   "controller": "127.0.0.1:9090",
//   "secret": "",
//   "rules": [
//     {"app": "Work",   "domain": "github.com"},            // suffix
//     {"app": "Editor", "process": "code.exe"},
//     {"app": "Sync",   "process": "code.exe", "domain": "full:api.github.com"}
//   ],
//   "multipliers": {"HK 01": 2.0},
//   "retention_days": 400
// }

///|
pub let max_config_bytes : Int32 = 1024 * 1024

///|
#derive(Eq, Debug)
pub(all) struct UserRule {
  app : String
  /// "" when the rule does not look at the process.
  process : String
  /// None when the rule does not look at the domain.
  domain : @rules.DomainPattern?
}

///|
#derive(Eq, Debug)
pub(all) struct Config {
  controller : String
  secret : String
  rules : Array[UserRule]
  multipliers : Map[String, Double]
  retention_days : Int32
}

///|
pub fn default() -> Config {
  {
    controller: "127.0.0.1:9090",
    secret: "",
    rules: [],
    multipliers: Map([]),
    retention_days: 400,
  }
}

///|
#derive(Debug)
pub(all) suberror ConfigError {
  ConfigError(String)
}

///|
pub impl Show for ConfigError with fn output(self, logger) {
  let ConfigError(m) = self
  logger.write_string("config.json: " + m)
}

///|
/// "full:x", "keyword:x", "suffix:x" / "domain:x", or a bare domain
/// (suffix).
pub fn parse_pattern(s : String) -> @rules.DomainPattern? {
  let s = s.trim().to_owned()
  let (kind, v) = match s.find(":") {
    Some(i) => (s[:i].to_owned(), s[i + 1:].to_owned())
    None => ("suffix", s)
  }
  let v = @rules.normalize_domain(v)
  if v.length() == 0 || v.length() > 253 || v.contains(" ") {
    return None
  }
  match kind {
    "suffix" | "domain" => Some(Suffix(v))
    "full" => Some(Full(v))
    "keyword" => Some(Keyword(v))
    _ => None
  }
}

///|
pub fn pattern_text(p : @rules.DomainPattern) -> String {
  match p {
    Suffix(d) => d
    Full(d) => "full:" + d
    Keyword(k) => "keyword:" + k
  }
}

///|
fn short_string(
  v : Json?,
  what : String,
  max : Int32,
) -> String? raise ConfigError {
  match v {
    None | Some(Null) => None
    Some(String(s)) if s.length() <= max => Some(s)
    _ =>
      raise ConfigError("\{what} must be a string of at most \{max} characters")
  }
}

///|
pub fn parse(text : String) -> Config raise ConfigError {
  if text.length() > max_config_bytes {
    raise ConfigError("larger than \{max_config_bytes} bytes")
  }
  let text = match text.strip_prefix("\u{feff}") {
    Some(t) => t.to_owned()
    None => text
  }
  if text.trim().length() == 0 {
    return default()
  }
  let j = @json.parse(text) catch {
    e => raise ConfigError("invalid JSON: \{e}")
  }
  guard j is Object(m) else { raise ConfigError("top level must be an object") }
  let d = default()
  let controller = match short_string(m.get("controller"), "controller", 255) {
    Some(c) => c
    None => d.controller
  }
  let secret = match short_string(m.get("secret"), "secret", 1024) {
    Some(s) => s
    None => ""
  }
  let rules = []
  match m.get("rules") {
    None | Some(Null) => ()
    Some(Array(xs)) =>
      for i, x in xs {
        guard x is Object(r) else {
          raise ConfigError("rules[\{i}] must be an object")
        }
        guard short_string(r.get("app"), "rules[\{i}].app", 100) is Some(app) &&
          app.trim().length() > 0 else {
          raise ConfigError("rules[\{i}].app is required")
        }
        let process = match
          short_string(r.get("process"), "rules[\{i}].process", 260) {
          Some(p) => @rules.normalize_process(p)
          None => ""
        }
        let domain = match
          short_string(r.get("domain"), "rules[\{i}].domain", 260) {
          Some(t) =>
            match parse_pattern(t) {
              Some(p) => Some(p)
              None =>
                raise ConfigError("rules[\{i}].domain is not a valid pattern")
            }
          None => None
        }
        if process == "" && domain is None {
          raise ConfigError("rules[\{i}] needs a process, a domain or both")
        }
        rules.push({ app: app.trim().to_owned(), process, domain, })
      }
    _ => raise ConfigError("rules must be an array")
  }
  let multipliers = Map([])
  match m.get("multipliers") {
    None | Some(Null) => ()
    Some(Object(ms)) =>
      for name, v in ms {
        guard v is Number(x, ..) && x >= 0.0 && x <= 100.0 else {
          raise ConfigError(
            "multiplier for \"\{name}\" must be a number in 0..100",
          )
        }
        multipliers[name] = x
      }
    _ => raise ConfigError("multipliers must be an object")
  }
  let retention_days = match m.get("retention_days") {
    None | Some(Null) => d.retention_days
    Some(Number(x, ..)) if x >= 1.0 && x <= 36500.0 => x.to_int()
    _ => raise ConfigError("retention_days must be 1..36500")
  }
  { controller, secret, rules, multipliers, retention_days, }
}

///|
/// Pretty JSON for writing back (rules keep their order).
pub fn Config::to_text(self : Config) -> String {
  let m = Map([])
  m["controller"] = Json::string(self.controller)
  m["secret"] = Json::string(self.secret)
  m["rules"] = Json::array(
    self.rules.map(r => {
      let o = Map([])
      o["app"] = Json::string(r.app)
      if r.process != "" {
        o["process"] = Json::string(r.process)
      }
      if r.domain is Some(p) {
        o["domain"] = Json::string(pattern_text(p))
      }
      Json::object(o)
    }),
  )
  let mult = Map([])
  for k, v in self.multipliers {
    mult[k] = Json::number(v)
  }
  m["multipliers"] = Json::object(mult)
  m["retention_days"] = Json::number(self.retention_days.to_double())
  Json::object(m).stringify(indent=2) + "\n"
}

///|
/// Loads the user rules into a rule set as User rules.
pub fn Config::apply_rules(self : Config, set : @rules.RuleSet) -> Unit {
  for r in self.rules {
    match (r.process, r.domain) {
      ("", Some(p)) => set.add_domain(User, p, r.app)
      (proc, None) => set.add_process(User, proc, r.app)
      (proc, Some(p)) => set.add_process_domain(User, proc, p, r.app)
    }
  }
}

///|
/// Node multiplier: configured value, else a marker in the node name such
/// as "2x", "x2", "0.5x" or "2倍", else 1.
pub fn Config::multiplier(self : Config, node : String) -> Double {
  match self.multipliers.get(node) {
    Some(x) => x
    None =>
      match multiplier_from_name(node) {
        Some(x) => x
        None => 1.0
      }
  }
}

///|
fn parse_decimal(s : StringView) -> Double? {
  if s.length() == 0 || s.length() > 6 {
    return None
  }
  let mut int_part = 0.0
  let mut frac = 0.0
  let mut scale = 1.0
  let mut seen_dot = false
  let mut digits = 0
  for c in s {
    match c {
      '0'..<='9' => {
        let v = (c.to_int() - '0'.to_int()).to_double()
        if seen_dot {
          scale = scale / 10.0
          frac = frac + v * scale
        } else {
          int_part = int_part * 10.0 + v
        }
        digits += 1
      }
      '.' if !seen_dot => seen_dot = true
      _ => return None
    }
  }
  if digits == 0 {
    None
  } else {
    Some(int_part + frac)
  }
}

///|
pub fn multiplier_from_name(name : String) -> Double? {
  // Split into tokens on anything that is not a digit, '.', 'x', 'X' or '倍'.
  let tokens = []
  let cur = StringBuilder()
  for c in name {
    match c {
      '0'..<='9' | '.' | 'x' | 'X' | '×' | '倍' => cur.write_char(c)
      _ => {
        tokens.push(cur.to_string())
        cur.reset()
      }
    }
  }
  tokens.push(cur.to_string())
  for t in tokens {
    if t.length() < 2 {
      continue
    }
    let lower = t.to_lower()
    let num = if lower.has_suffix("x") ||
      lower.has_suffix("×") ||
      lower.has_suffix("倍") {
      lower[:lower.length() - 1]
    } else if lower.has_prefix("x") || lower.has_prefix("×") {
      lower[1:]
    } else {
      continue
    }
    match parse_decimal(num) {
      Some(x) if x > 0.0 && x <= 100.0 => return Some(x)
      _ => ()
    }
  }
  None
}
