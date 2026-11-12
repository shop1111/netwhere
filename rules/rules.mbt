// Classification of traffic into named applications.
//
// Priority (PLAN.md §4.7): user rules before built-in rules; within each,
// "process + domain" > "process only" > "domain only"; otherwise Unknown.
// Among domain patterns the most specific wins: full > longest suffix >
// keyword (first added).

///|
#derive(Eq, Hash, Debug)
pub(all) enum DomainPattern {
  /// Matches the domain and all its subdomains.
  Suffix(String)
  /// Matches exactly this domain.
  Full(String)
  /// Matches any domain containing the text.
  Keyword(String)
}

///|
pub impl Show for DomainPattern with fn output(self, logger) {
  match self {
    Suffix(d) => logger.write_string("domain:" + d)
    Full(d) => logger.write_string("full:" + d)
    Keyword(k) => logger.write_string("keyword:" + k)
  }
}

///|
#derive(Eq, Hash, Debug)
pub(all) enum Origin {
  User
  Builtin
}

///|
#derive(Eq, Hash, Debug)
pub(all) enum MatchKind {
  ProcessAndDomain
  ProcessOnly
  DomainOnly
}

///|
#derive(Eq, Debug)
pub(all) struct Classified {
  app : String
  origin : Origin
  kind : MatchKind
}

///|
/// Domains are compared lowercase and without a trailing dot.
pub fn normalize_domain(d : StringView) -> String {
  let d = d.trim()
  let d = if d.has_suffix(".") { d[:d.length() - 1] } else { d }
  d.to_lower().to_owned()
}

///|
/// Process rules name either an executable ("git.exe", matched against the
/// base name) or a full path (contains a backslash). Case-insensitive.
pub fn normalize_process(p : StringView) -> String {
  p.trim().to_lower().to_owned()
}

///|
fn process_base(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[i + 1:].to_owned()
    None => path
  }
}

///|
/// Domain patterns of one origin, indexed for lookup.
priv struct DomainIndex {
  full : Map[String, String]
  suffix : Map[String, String]
  keywords : Array[(String, String)]
}

///|
fn DomainIndex::new() -> DomainIndex {
  { full: Map([]), suffix: Map([]), keywords: [], }
}

///|
fn DomainIndex::add(
  self : DomainIndex,
  p : DomainPattern,
  app : String,
) -> Unit {
  match p {
    Full(d) => self.full[normalize_domain(d)] = app
    Suffix(d) => self.suffix[normalize_domain(d)] = app
    Keyword(k) => self.keywords.push((k.to_lower(), app))
  }
}

///|
fn DomainIndex::lookup(self : DomainIndex, domain : String) -> String? {
  if self.full.get(domain) is Some(app) {
    return Some(app)
  }
  // Longest suffix first: "a.b.example.com", "b.example.com", ...
  let mut rest = domain[:]
  while rest.length() > 0 {
    if self.suffix.get(rest.to_owned()) is Some(app) {
      return Some(app)
    }
    match rest.find(".") {
      Some(i) => rest = rest[i + 1:]
      None => break
    }
  }
  for kw in self.keywords {
    if domain.contains(kw.0) {
      return Some(kw.1)
    }
  }
  None
}

///|
fn DomainIndex::size(self : DomainIndex) -> Int32 {
  self.full.length() + self.suffix.length() + self.keywords.length()
}

///|
priv struct Tier {
  /// process -> domain index for "process + domain" rules.
  combo : Map[String, DomainIndex]
  process : Map[String, String]
  domain : DomainIndex
}

///|
fn Tier::new() -> Tier {
  { combo: Map([]), process: Map([]), domain: DomainIndex::new(), }
}

///|
fn[X] find_process(m : Map[String, X], path : String, base : String) -> X? {
  match m.get(path) {
    Some(v) => Some(v)
    None => m.get(base)
  }
}

///|
fn Tier::classify(
  self : Tier,
  path : String,
  base : String,
  domain : String?,
) -> (String, MatchKind)? {
  if domain is Some(d) && find_process(self.combo, path, base) is Some(idx) {
    if idx.lookup(d) is Some(app) {
      return Some((app, ProcessAndDomain))
    }
  }
  if find_process(self.process, path, base) is Some(app) {
    return Some((app, ProcessOnly))
  }
  if domain is Some(d) && self.domain.lookup(d) is Some(app) {
    return Some((app, DomainOnly))
  }
  None
}

///|
pub struct RuleSet {
  priv user : Tier
  priv builtin : Tier
}

///|
pub fn RuleSet::new() -> RuleSet {
  { user: Tier::new(), builtin: Tier::new(), }
}

///|
fn RuleSet::tier(self : RuleSet, origin : Origin) -> Tier {
  match origin {
    User => self.user
    Builtin => self.builtin
  }
}

///|
pub fn RuleSet::add_domain(
  self : RuleSet,
  origin : Origin,
  pattern : DomainPattern,
  app : String,
) -> Unit {
  self.tier(origin).domain.add(pattern, app)
}

///|
pub fn RuleSet::add_process(
  self : RuleSet,
  origin : Origin,
  process : String,
  app : String,
) -> Unit {
  self.tier(origin).process[normalize_process(process)] = app
}

///|
pub fn RuleSet::add_process_domain(
  self : RuleSet,
  origin : Origin,
  process : String,
  pattern : DomainPattern,
  app : String,
) -> Unit {
  let combo = self.tier(origin).combo
  let key = normalize_process(process)
  let idx = match combo.get(key) {
    Some(i) => i
    None => {
      let i = DomainIndex::new()
      combo[key] = i
      i
    }
  }
  idx.add(pattern, app)
}

///|
/// Number of domain patterns of the given origin (for status output).
pub fn RuleSet::domain_count(self : RuleSet, origin : Origin) -> Int32 {
  self.tier(origin).domain.size()
}

///|
/// Classifies one flow. `process` is a full image path or a bare executable
/// name; `domain` is the best known name for the peer, if any.
pub fn RuleSet::classify(
  self : RuleSet,
  process : String,
  domain : String?,
) -> Classified? {
  let path = normalize_process(process)
  let base = process_base(path)
  let domain = match domain {
    Some(d) =>
      match normalize_domain(d) {
        "" => None
        n => Some(n)
      }
    None => None
  }
  for origin in [User, Builtin] {
    if self.tier(origin).classify(path, base, domain) is Some((app, kind)) {
      return Some({ app, origin, kind, })
    }
  }
  None
}
