// Text format of the generated built-in rule file (rules/builtin.txt),
// written by cmd/rules-import and loaded at startup:
//
//   # netwhere builtin rules v1
//   # source: v2fly/domain-list-community@<commit>
//   [GitHub]
//   s github.com          suffix
//   f api.github.com      full
//   k github              keyword
//
// One app section per v2fly list; entries are sorted so regeneration from the
// same input is byte-identical.

///|
pub let builtin_header : String = "# netwhere builtin rules v1"

///|
/// Lexicographic order by UTF-16 code unit. (String's own Compare orders by
/// length first, which would make the file layout surprising.)
fn lex_compare(a : String, b : String) -> Int32 {
  let n = if a.length() < b.length() { a.length() } else { b.length() }
  for i in 0..<n {
    let c = a.code_unit_at(i).compare(b.code_unit_at(i))
    if c != 0 {
      return c
    }
  }
  a.length().compare(b.length())
}

///|
/// Writes one section per app. Apps and entries are emitted in sorted order.
pub fn write_builtin(
  sections : Array[(String, Array[DomainPattern])],
  source : String,
) -> String {
  let buf = StringBuilder()
  buf.write_string(builtin_header + "\n")
  buf.write_string("# source: " + source + "\n")
  let sorted = sections.copy()
  sorted.sort_by((a, b) => lex_compare(a.0, b.0))
  for s in sorted {
    let (app, patterns) = s
    let lines = patterns.map(p => {
      match p {
        Suffix(d) => "s " + d
        Full(d) => "f " + d
        Keyword(k) => "k " + k
      }
    })
    lines.sort_by(lex_compare)
    buf.write_string("[" + app + "]\n")
    let mut prev = ""
    for l in lines {
      if l != prev {
        buf.write_string(l + "\n")
      }
      prev = l
    }
  }
  buf.to_string()
}

///|
/// Loads a built-in rule file into `set` as Builtin domain rules; returns the
/// number of patterns loaded.
pub fn load_builtin(set : RuleSet, text : StringView) -> Int32 raise V2flyError {
  let mut app : String? = None
  let mut count = 0
  let mut line_no = 0
  for line in text.split("\n") {
    line_no += 1
    let line = line.trim(chars=" \t\r")
    if line.length() == 0 || line.has_prefix("#") {
      continue
    }
    if line.has_prefix("[") && line.has_suffix("]") {
      app = Some(line[1:line.length() - 1].to_owned())
      continue
    }
    guard app is Some(a) else {
      raise V2flyError("builtin:\{line_no}: entry before any [app] section")
    }
    guard line.length() > 2 && line.code_unit_at(1) == ' ' else {
      raise V2flyError("builtin:\{line_no}: malformed entry")
    }
    let v = line[2:].to_owned()
    let p : DomainPattern = match line.code_unit_at(0) {
      's' => Suffix(v)
      'f' => Full(v)
      'k' => Keyword(v)
      _ => raise V2flyError("builtin:\{line_no}: unknown entry kind")
    }
    set.add_domain(Builtin, p, a)
    count += 1
  }
  count
}
