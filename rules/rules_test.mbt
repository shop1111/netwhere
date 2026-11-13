///|
fn app_of(set : @rules.RuleSet, process : String, domain : String?) -> String {
  match set.classify(process, domain) {
    Some(c) => {
      let origin = match c.origin {
        User => "user"
        Builtin => "builtin"
      }
      let kind = match c.kind {
        ProcessAndDomain => "proc+domain"
        ProcessOnly => "proc"
        DomainOnly => "domain"
      }
      "\{c.app} (\{origin}, \{kind})"
    }
    None => "Unknown"
  }
}

///|
test "domain specificity: full > longest suffix > keyword" {
  let set = @rules.RuleSet::new()
  set.add_domain(Builtin, Suffix("github.com"), "GitHub")
  set.add_domain(Builtin, Suffix("githubusercontent.com"), "GitHub")
  set.add_domain(Builtin, Suffix("microsoft.com"), "Microsoft")
  set.add_domain(Builtin, Suffix("copilot.microsoft.com"), "Copilot")
  set.add_domain(Builtin, Full("login.microsoft.com"), "Microsoft Login")
  set.add_domain(Builtin, Keyword("bilibili"), "Bilibili")
  inspect(
    app_of(set, "git.exe", Some("api.github.com")),
    content="GitHub (builtin, domain)",
  )
  inspect(
    app_of(set, "x.exe", Some("github.com")),
    content="GitHub (builtin, domain)",
  )
  // Suffix matches whole labels only.
  inspect(app_of(set, "x.exe", Some("notgithub.com")), content="Unknown")
  inspect(
    app_of(set, "x.exe", Some("a.copilot.microsoft.com")),
    content="Copilot (builtin, domain)",
  )
  inspect(
    app_of(set, "x.exe", Some("LOGIN.Microsoft.com.")),
    content="Microsoft Login (builtin, domain)",
  )
  inspect(
    app_of(set, "x.exe", Some("www.login.microsoft.com")),
    content="Microsoft (builtin, domain)",
  )
  inspect(
    app_of(set, "x.exe", Some("upos-bilibili-cdn.example.net")),
    content="Bilibili (builtin, domain)",
  )
  inspect(app_of(set, "x.exe", None), content="Unknown")
  inspect(app_of(set, "x.exe", Some("")), content="Unknown")
}

///|
test "priority: user before builtin, then combo > process > domain" {
  let set = @rules.RuleSet::new()
  set.add_domain(Builtin, Suffix("github.com"), "GitHub")
  set.add_process(Builtin, "Code.exe", "VS Code")
  inspect(
    app_of(
      set,
      "C:\\Program Files\\Microsoft VS Code\\Code.exe",
      Some("github.com"),
    ),
    content="VS Code (builtin, proc)",
  )
  // A user domain rule outranks any builtin rule.
  set.add_domain(User, Suffix("github.com"), "Work")
  inspect(
    app_of(
      set,
      "C:\\Program Files\\Microsoft VS Code\\Code.exe",
      Some("github.com"),
    ),
    content="Work (user, domain)",
  )
  set.add_process(User, "code.exe", "Editor")
  inspect(
    app_of(set, "code.exe", Some("github.com")),
    content="Editor (user, proc)",
  )
  set.add_process_domain(User, "CODE.EXE", Suffix("github.com"), "Editor sync")
  inspect(
    app_of(set, "code.exe", Some("api.github.com")),
    content="Editor sync (user, proc+domain)",
  )
  inspect(
    app_of(set, "code.exe", Some("example.org")),
    content="Editor (user, proc)",
  )
  // Full-path process rules win over base-name rules.
  set.add_process(User, "D:\\portable\\code.exe", "Portable editor")
  inspect(
    app_of(set, "d:\\Portable\\Code.exe", None),
    content="Portable editor (user, proc)",
  )
}

///|
let google_list : String =
  #|# comment line
  #|google.com
  #|domain:youtube.com @ads
  #|full:www.google.cn @cn
  #|keyword:googleapis   # trailing comment
  #|regexp:^gg[0-9]+\.example$
  #|include:google-ads
  #|include:google-cn @cn

///|
let google_ads_list : String =
  #|doubleclick.net @ads
  #|googleadservices.com &google

///|
let google_cn_list : String =
  #|g.cn @cn
  #|google.com.hk

///|
test "v2fly parse" {
  let l = @rules.parse_v2fly_list("google", google_list)
  inspect(l.entries.length(), content="4")
  inspect(
    l.entries.map(e => e.pattern.to_string()).join(" "),
    content="domain:google.com domain:youtube.com full:www.google.cn keyword:googleapis",
  )
  assert_eq(l.entries[1].attrs, ["ads"])
  assert_eq(l.regexp_skipped, 1)
  assert_eq(l.includes.length(), 2)
  assert_eq(l.includes[1].filters, ["cn"])
  let bad = try {
    let _ = @rules.parse_v2fly_list("x", "foo:bar.com")
    "ok"
  } catch {
    e => e.to_string()
  }
  inspect(bad, content="v2fly: x:1: unknown type \"foo\"")
}

///|
fn lists() -> Map[String, @rules.V2flyList] raise {
  let m = Map([])
  m["google"] = @rules.parse_v2fly_list("google", google_list)
  m["google-ads"] = @rules.parse_v2fly_list("google-ads", google_ads_list)
  m["google-cn"] = @rules.parse_v2fly_list("google-cn", google_cn_list)
  m
}

///|
test "v2fly include expansion and attribute filters" {
  let all = @rules.resolve_v2fly(lists(), "google")
  // google-cn is included with @cn: only g.cn passes, google.com.hk does not.
  inspect(
    all.map(e => e.pattern.to_string()).join(" "),
    content="domain:google.com domain:youtube.com full:www.google.cn keyword:googleapis domain:doubleclick.net domain:googleadservices.com domain:g.cn",
  )
  let m = lists()
  m["no-ads"] = @rules.parse_v2fly_list("no-ads", "include:google @-ads")
  let filtered = @rules.resolve_v2fly(m, "no-ads")
  assert_false(
    filtered.map(e => e.pattern.to_string()).contains("domain:youtube.com"),
  )
  assert_false(
    filtered.map(e => e.pattern.to_string()).contains("domain:doubleclick.net"),
  )
  assert_true(
    filtered.map(e => e.pattern.to_string()).contains("domain:google.com"),
  )
}

///|
test "v2fly cycles and missing lists are errors" {
  let m = Map([])
  m["a"] = @rules.parse_v2fly_list("a", "include:b\na.com")
  m["b"] = @rules.parse_v2fly_list("b", "include:a")
  let e1 = try {
    let _ = @rules.resolve_v2fly(m, "a")
    "ok"
  } catch {
    e => e.to_string()
  }
  inspect(e1, content="v2fly: include cycle: a -> b -> a")
  m["c"] = @rules.parse_v2fly_list("c", "include:nope")
  let e2 = try {
    let _ = @rules.resolve_v2fly(m, "c")
    "ok"
  } catch {
    e => e.to_string()
  }
  inspect(e2, content="v2fly: missing list \"nope\"")
}

///|
test "builtin file round trip is deterministic" {
  let google = @rules.resolve_v2fly(lists(), "google").map(e => e.pattern)
  let text = @rules.write_builtin(
    [
      ("Google", google),
      ("GitHub", [Suffix("github.com"), Suffix("github.com")]),
    ],
    "test fixture",
  )
  inspect(
    text,
    content=(
      #|# netwhere builtin rules v1
      #|# source: test fixture
      #|[GitHub]
      #|s github.com
      #|[Google]
      #|f www.google.cn
      #|k googleapis
      #|s doubleclick.net
      #|s g.cn
      #|s google.com
      #|s googleadservices.com
      #|s youtube.com
      #|
    ),
  )
  let set = @rules.RuleSet::new()
  assert_eq(@rules.load_builtin(set, text), 8)
  inspect(
    app_of(set, "chrome.exe", Some("www.youtube.com")),
    content="Google (builtin, domain)",
  )
  inspect(
    app_of(set, "chrome.exe", Some("x.github.com")),
    content="GitHub (builtin, domain)",
  )
  assert_eq(set.domain_count(Builtin), 8)
}

///|
test "shared patterns go to the most specific app" {
  let out = @rules.assign_unique([
    (
      "Google",
      [Suffix("google.com"), Suffix("youtube.com"), Suffix("ytimg.com")],
    ),
    ("YouTube", [Suffix("youtube.com"), Suffix("ytimg.com")]),
    ("A", [Suffix("same.test")]),
    ("B", [Suffix("same.test")]),
  ])
  inspect(
    out.map(s => s.0 + ":" + s.1.map(p => p.to_string()).join(",")).join(" "),
    content="Google:domain:google.com YouTube:domain:youtube.com,domain:ytimg.com A:domain:same.test B:",
  )
}
