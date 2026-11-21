///|
fn row(
  minute : Int64,
  app : String,
  entry : String,
  exit_kind : String,
  bytes : Int64,
  node~ : String = "",
  domain~ : String = "",
  process~ : String = "a.exe",
) -> @store.UsageRecord {
  {
    minute,
    app,
    process,
    domain,
    entry,
    exit_kind,
    node,
    rule: "",
    up: bytes / 4L,
    down: bytes - bytes / 4L,
  }
}

///|
let rows : Array[@store.UsageRecord] = [
  row(
    100L,
    "Git",
    "proxy-port",
    "node",
    1000L,
    node="HK 01",
    domain="github.com",
  ),
  row(101L, "Git", "bypass", "", 400L, domain="github.com"),
  row(102L, "Chat", "tun", "core-direct", 300L, domain="qq.com"),
  row(103L, "Unknown", "tun", "unknown", 200L, domain="x.io", process="b.exe"),
  row(104L, "Unknown", "lan", "", 50L, process="b.exe"),
  row(130L, "Chat", "proxy-port", "node", 600L, node="JP 02 [2x]"),
  row(131L, "Chat", "proxy-port", "ambiguous", 100L),
]

///|
test "group by app: routes, totals, largest first" {
  let gs = @query.group(rows, "app")
  inspect(
    gs
    .map(g => {
      let s = g.split
      "\{g.key}: node \{s.via_node} direct \{s.core_direct} ? \{s.core_unknown} bypass \{s.bypass} lan \{s.lan} = \{s.total}"
    })
    .join("\n"),
    content=(
      #|Git: node 1000 direct 0 ? 0 bypass 400 lan 0 = 1400
      #|Chat: node 600 direct 300 ? 100 bypass 0 lan 0 = 1000
      #|Unknown: node 0 direct 0 ? 200 bypass 0 lan 50 = 250
    ),
  )
  inspect(
    @query.group(rows, "domain").map(g => g.key).join(", "),
    content="github.com, (no name), qq.com, x.io",
  )
}

///|
test "nodes and totals with multipliers" {
  let m = fn(n : String) { @config.multiplier_from_name(n).unwrap_or(1.0) }
  inspect(
    @query.nodes(rows, m)
    .map(n => "\{n.node} \{n.bytes} x\{n.multiplier} = \{n.plan}")
    .join("\n"),
    content=(
      #|HK 01 1000 x1 = 1000
      #|JP 02 [2x] 600 x2 = 1200
    ),
  )
  let t = @query.totals(rows, m)
  assert_eq(t.split.total, 2650L)
  assert_eq(t.up + t.down, 2650L)
  // Unknown and ambiguous exits (300 B) widen the plan range.
  inspect(
    "\{t.plan.low} \{t.plan.high} \{t.plan.uncertain}",
    content="2200 2800 300",
  )
}

///|
test "filters" {
  assert_eq(@query.filter(rows, app="git").length(), 2)
  assert_eq(@query.filter(rows, entry="tun").length(), 2)
  assert_eq(@query.filter(rows, key=("domain", "github.com")).length(), 2)
  assert_eq(@query.filter(rows, app="Chat", key=("node", "")).length(), 2)
}

///|
test "timeline buckets cover the period" {
  let p : @query.Period = { from: 100L, to: 140L, label: "", }
  let step = @query.timeline_step(p, max_points=4)
  assert_eq(step, 10L)
  let tl = @query.timeline(rows, p, step)
  inspect(
    tl.map(b => "\{b.start}:\{b.split.total}").join(" "),
    content="100:1950 110:0 120:0 130:700",
  )
  // Edges on local multiples of the step: with offset 5, local minute 100
  // is 105, so buckets start at local 100 (UTC 95), 110, ….
  let tl = @query.timeline(
    rows,
    { from: 101L, to: 140L, label: "", },
    10L,
    offset=5L,
  )
  inspect(
    tl.map(b => "\{b.start}:\{b.split.total}").join(" "),
    content="95:950 105:0 115:0 125:700 135:0",
  )
  assert_eq(
    @query.timeline_step({ from: 0L, to: 1440L * 30L, label: "", }),
    720L,
  )
}

///|
test "unclassified traffic" {
  inspect(
    @query.unclassified(rows)
    .map(u => "\{u.process} \{u.domain} \{u.bytes}")
    .join("\n"),
    content=(
      #|b.exe x.io 200
      #|b.exe  50
    ),
  )
}

///|
test "csv quoting" {
  let text = @query.csv(
    [row(0L, "A, B", "tun", "node", 8L, node="say \"hi\"")],
    0,
  )
  inspect(
    text,
    content=(
      #|minute,app,process,domain,entry,exit,node,rule,up,down
      #|1601-01-01 00:00,"A, B",a.exe,,tun,node,"say ""hi""",,2,6
      #|
    ),
  )
}

///|
test "rules: make, classify, replace, remove" {
  let err = fn(r : Result[@config.UserRule, String]) {
    match r {
      Ok(_) => "ok"
      Err(e) => e
    }
  }
  inspect(
    err(@query.make_rule(" ", domain="x.com")),
    content="the app name is empty",
  )
  inspect(
    err(@query.make_rule("Work")),
    content="give a process, a domain or both",
  )
  inspect(
    err(@query.make_rule("Work", domain="regex:a.*")),
    content="not a domain pattern: regex:a.*",
  )
  let r = @query.classify_rule("C:\\Tools\\Code.EXE", "Editor").unwrap()
  inspect(@query.rule_text(r), content="process c:\\tools\\code.exe -> Editor")
  let d = @query.classify_rule("github.com", "Work").unwrap()
  let c = @query.with_rule(@query.with_rule(@config.default(), r), d)
  // Same target again replaces the older rule.
  let c = @query.with_rule(
    c,
    @query.classify_rule("C:\\tools\\code.exe", "IDE").unwrap(),
  )
  inspect(
    c.rules.map(@query.rule_text).join("\n"),
    content=(
      #|domain github.com -> Work
      #|process c:\tools\code.exe -> IDE
    ),
  )
  assert_eq(@query.without_rule(c, 2), None)
  assert_eq(@query.without_rule(c, 0).unwrap().rules.length(), 1)
}
