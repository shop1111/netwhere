// Editing the user rules in config.json (shared by `netwhere classify`,
// `netwhere rules` and the UI). The collector reloads the file within a
// few seconds; rules only affect traffic counted afterwards.

///|
/// A process target: ends in .exe or is a path.
pub fn is_process_target(t : String) -> Bool {
  t.to_lower().has_suffix(".exe") || t.contains("\\")
}

///|
/// "process P + domain D -> App"
pub fn rule_text(r : @config.UserRule) -> String {
  let parts = []
  if r.process != "" {
    parts.push("process " + r.process)
  }
  if r.domain is Some(p) {
    parts.push("domain " + @config.pattern_text(p))
  }
  parts.join(" + ") + " -> " + r.app
}

///|
/// A rule from optional process and domain texts; Err says what is wrong.
pub fn make_rule(
  app : String,
  process~ : String = "",
  domain~ : String = "",
) -> Result[@config.UserRule, String] {
  let app = app.trim().to_owned()
  if app == "" {
    return Err("the app name is empty")
  }
  if app.length() > 100 {
    return Err("the app name is too long")
  }
  let process = if process.trim() == "" {
    ""
  } else {
    @rules.normalize_process(process.trim().to_owned())
  }
  let domain = if domain.trim() == "" {
    None
  } else {
    match @config.parse_pattern(domain.trim().to_owned()) {
      Some(p) => Some(p)
      None => return Err("not a domain pattern: \{domain}")
    }
  }
  if process == "" && domain is None {
    return Err("give a process, a domain or both")
  }
  Ok({ app, process, domain, })
}

///|
/// `classify TARGET APP`: a process rule for an .exe or path, else a domain
/// rule.
pub fn classify_rule(
  target : String,
  app : String,
) -> Result[@config.UserRule, String] {
  if is_process_target(target) {
    make_rule(app, process=target)
  } else {
    make_rule(app, domain=target)
  }
}

///|
/// Adds a rule; a rule with the same process and domain is replaced.
pub fn with_rule(c : @config.Config, rule : @config.UserRule) -> @config.Config {
  let rules = c.rules.filter(r => {
    r.process != rule.process || r.domain != rule.domain
  })
  rules.push(rule)
  { ..c, rules, }
}

///|
/// Removes rule `index` (0-based); None when out of range.
pub fn without_rule(c : @config.Config, index : Int32) -> @config.Config? {
  if index < 0 || index >= c.rules.length() {
    return None
  }
  let rules = c.rules.copy()
  ignore(rules.remove(index))
  Some({ ..c, rules, })
}
