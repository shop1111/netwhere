// Reader for v2fly/domain-list-community "data/<name>" files (MIT).
//
//   # comment
//   example.com               same as domain:example.com
//   domain:example.com @cn    attributes follow the value
//   full:www.example.com
//   keyword:example
//   regexp:^ex.*\.com$        not supported: skipped and counted
//   include:other             all entries of data/other
//   include:other @cn         only entries of other carrying @cn
//   include:other @-cn        only entries of other not carrying @cn

///|
#derive(Eq, Debug)
pub(all) struct V2flyEntry {
  pattern : DomainPattern
  attrs : Array[String]
}

///|
#derive(Eq, Debug)
pub(all) struct V2flyInclude {
  name : String
  /// Attribute filters: "cn" requires @cn, "-cn" forbids it.
  filters : Array[String]
}

///|
#derive(Eq, Debug)
pub(all) struct V2flyList {
  name : String
  entries : Array[V2flyEntry]
  includes : Array[V2flyInclude]
  regexp_skipped : Int32
}

///|
#derive(Debug)
pub(all) suberror V2flyError {
  V2flyError(String)
}

///|
pub impl Show for V2flyError with fn output(self, logger) {
  let V2flyError(msg) = self
  logger.write_string("v2fly: " + msg)
}

///|
pub fn parse_v2fly_list(
  name : String,
  text : StringView,
) -> V2flyList raise V2flyError {
  let entries = []
  let includes = []
  let mut regexp_skipped = 0
  let mut line_no = 0
  for line in text.split("\n") {
    line_no += 1
    let line = match line.find("#") {
      Some(i) => line[:i]
      None => line
    }
    let line = line.trim(chars=" \t\r")
    if line.length() == 0 {
      continue
    }
    let words = line.split(" ").filter(w => w.length() > 0).collect()
    let value = words[0]
    let attrs = []
    for w in words[1:] {
      match w.strip_prefix("@") {
        Some(a) if a.length() > 0 => attrs.push(a.to_lower().to_owned())
        _ =>
          match w.strip_prefix("&") {
            // Affiliation markers ("&other") do not change matching.
            Some(_) => ()
            None =>
              raise V2flyError("\{name}:\{line_no}: unexpected token \"\{w}\"")
          }
      }
    }
    let (kind, v) = match value.find(":") {
      Some(i) => (value[:i].to_owned(), value[i + 1:])
      None => ("domain", value)
    }
    if v.length() == 0 {
      raise V2flyError("\{name}:\{line_no}: empty value")
    }
    match kind {
      "domain" => entries.push({ pattern: Suffix(normalize_domain(v)), attrs, })
      "full" => entries.push({ pattern: Full(normalize_domain(v)), attrs, })
      "keyword" =>
        entries.push({ pattern: Keyword(v.to_lower().to_owned()), attrs, })
      "regexp" => regexp_skipped += 1
      "include" =>
        includes.push({ name: v.to_lower().to_owned(), filters: attrs, })
      other => raise V2flyError("\{name}:\{line_no}: unknown type \"\{other}\"")
    }
  }
  { name, entries, includes, regexp_skipped, }
}

///|
fn passes(attrs : Array[String], filters : Array[String]) -> Bool {
  for f in filters {
    match f.strip_prefix("-") {
      Some(neg) => if attrs.contains(neg.to_owned()) { return false }
      None => if !attrs.contains(f) { return false }
    }
  }
  true
}

///|
/// Expands includes recursively. Missing lists and include cycles are
/// errors, so a broken dataset never silently produces a smaller rule set.
pub fn resolve_v2fly(
  lists : Map[String, V2flyList],
  name : String,
) -> Array[V2flyEntry] raise V2flyError {
  let out = []
  let seen : Map[DomainPattern, Bool] = Map([])
  fn go(
    n : String,
    filters : Array[String],
    stack : Array[String],
  ) raise V2flyError {
    if stack.contains(n) {
      raise V2flyError("include cycle: \{stack.join(" -> ")} -> \{n}")
    }
    guard lists.get(n) is Some(list) else {
      raise V2flyError("missing list \"\{n}\"")
    }
    stack.push(n)
    for e in list.entries {
      if passes(e.attrs, filters) && !seen.contains(e.pattern) {
        seen[e.pattern] = true
        out.push(e)
      }
    }
    for inc in list.includes {
      // Filters accumulate: the outer filter still applies to nested lists.
      let combined = filters.copy()
      for f in inc.filters {
        combined.push(f)
      }
      go(inc.name, combined, stack)
    }
    let _ = stack.pop()
  }
  go(name, [], [])
  out
}
