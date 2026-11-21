// Aggregations over ledger rows shared by the command line and the UI, so
// both show the same numbers. Formatting stays with each front end.

///|
/// [from, to) in minutes since 1601 (the ledger's minute numbers).
#derive(Eq, Debug)
pub(all) struct Period {
  from : Int64
  to : Int64
  label : String
}

///|
/// From the start of the local day to now.
pub fn today(now : Int64, offset : Int32) -> Period {
  let minute = @store.ticks_per_minute
  {
    from: @report.local_day_start(now, offset) / minute,
    to: now / minute + 1L,
    label: "today",
  }
}

///|
/// The last `n` days, ending now.
pub fn last_days(n : Int32, now : Int64) -> Period {
  let to = now / @store.ticks_per_minute + 1L
  { from: to - n.to_int64() * 1440L, to, label: "last \{n} days", }
}

///|
/// The last `n` hours, ending now.
pub fn last_hours(n : Int32, now : Int64) -> Period {
  let to = now / @store.ticks_per_minute + 1L
  { from: to - n.to_int64() * 60L, to, label: "last \{n} hours", }
}

///|
/// Where a row's bytes went, in five columns.
#derive(Eq, Debug)
pub(all) enum Route {
  /// Through the core to a proxy node.
  ViaNode
  /// Through the core, out DIRECT (or REJECT).
  CoreDirect
  /// Into the core, exit unknown or ambiguous.
  CoreUnknown
  /// Around the core (bypass) or no core at all (direct).
  Bypass
  Lan
}

///|
pub fn route_of(r : @store.UsageRecord) -> Route {
  match (r.exit_kind, r.entry) {
    ("node", _) => ViaNode
    ("core-direct", _) | ("core-reject", _) => CoreDirect
    ("unknown", _) | ("ambiguous", _) => CoreUnknown
    (_, "lan") => Lan
    _ => Bypass
  }
}

///|
fn route_index(r : Route) -> Int32 {
  match r {
    ViaNode => 0
    CoreDirect => 1
    CoreUnknown => 2
    Bypass => 3
    Lan => 4
  }
}

///|
/// Bytes (up + down) per route, plus the total.
#derive(Eq, Debug)
pub(all) struct Split {
  via_node : Int64
  core_direct : Int64
  core_unknown : Int64
  bypass : Int64
  lan : Int64
  total : Int64
}

///|
fn split_of(v : FixedArray[Int64]) -> Split {
  {
    via_node: v[0],
    core_direct: v[1],
    core_unknown: v[2],
    bypass: v[3],
    lan: v[4],
    total: v[5],
  }
}

///|
fn add_row(v : FixedArray[Int64], r : @store.UsageRecord) -> Unit {
  let i = route_index(route_of(r))
  v[i] = v[i] + r.up + r.down
  v[5] = v[5] + r.up + r.down
}

///|
/// The grouping key: "app", "domain", "process", "node" or "entry".
pub fn key_of(r : @store.UsageRecord, by : String) -> String {
  match by {
    "domain" => if r.domain == "" { "(no name)" } else { r.domain }
    "process" => r.process
    "node" => r.node
    "entry" => r.entry
    _ => r.app
  }
}

///|
pub let groupings : Array[String] = [
  "app", "domain", "process", "node", "entry",
]

///|
#derive(Eq, Debug)
pub(all) struct Group {
  key : String
  split : Split
}

///|
/// Bytes per key, largest first. `by == "node"` keeps only rows that went
/// to a proxy node.
pub fn group(rows : Array[@store.UsageRecord], by : String) -> Array[Group] {
  let sums : Map[String, FixedArray[Int64]] = Map([])
  for r in rows {
    if by == "node" && r.exit_kind != "node" {
      continue
    }
    let k = key_of(r, by)
    let v = match sums.get(k) {
      Some(v) => v
      None => {
        let v = FixedArray::make(6, 0L)
        sums[k] = v
        v
      }
    }
    add_row(v, r)
  }
  let out = sums
    .iter()
    .map(kv => { key: kv.0, split: split_of(kv.1), })
    .collect()
  out.sort_by((a, b) => {
    match b.split.total.compare(a.split.total) {
      0 => a.key.compare(b.key)
      c => c
    }
  })
  out
}

///|
/// Rows matching an optional key filter per grouping (e.g. app = "Git").
pub fn filter(
  rows : Array[@store.UsageRecord],
  app? : String,
  entry? : String,
  key? : (String, String),
) -> Array[@store.UsageRecord] {
  rows.filter(r => {
    (match app {
      Some(a) => r.app.to_lower() == a.to_lower()
      None => true
    }) &&
    (match entry {
      Some(e) => r.entry == e
      None => true
    }) &&
    (match key {
      Some((by, k)) => key_of(r, by) == k
      None => true
    })
  })
}

///|
#derive(Eq, Debug)
pub(all) struct NodeUse {
  node : String
  bytes : Int64
  multiplier : Double
  /// bytes × multiplier
  plan : Int64
}

///|
/// Proxy-node traffic with each node's multiplier, largest first.
pub fn nodes(
  rows : Array[@store.UsageRecord],
  multiplier : (String) -> Double,
) -> Array[NodeUse] {
  group(rows, "node").map(g => {
    let m = multiplier(g.key)
    {
      node: g.key,
      bytes: g.split.total,
      multiplier: m,
      plan: (g.split.total.to_double() * m).to_int64(),
    }
  })
}

///|
#derive(Eq, Debug)
pub(all) struct Totals {
  split : Split
  up : Int64
  down : Int64
  plan : @report.PlanEstimate
}

///|
pub fn totals(
  rows : Array[@store.UsageRecord],
  multiplier : (String) -> Double,
) -> Totals {
  let v = FixedArray::make(6, 0L)
  let mut up = 0L
  let mut down = 0L
  for r in rows {
    add_row(v, r)
    up += r.up
    down += r.down
  }
  {
    split: split_of(v),
    up,
    down,
    plan: @report.plan_estimate(
      rows.map(r => (r.exit_kind, r.node, r.up + r.down)),
      multiplier,
    ),
  }
}

///|
#derive(Eq, Debug)
pub(all) struct Bucket {
  /// First minute of the bucket.
  start : Int64
  split : Split
}

///|
/// Bytes per route in buckets of `step` minutes covering the period, empty
/// buckets included (for a trend chart). Bucket edges fall on whole
/// multiples of the step in local time (`offset` minutes east of UTC), so a
/// 2-hour bucket starts at 00:00, 02:00, …; the first one may begin before
/// the period does (it only holds the period's rows).
pub fn timeline(
  rows : Array[@store.UsageRecord],
  p : Period,
  step : Int64,
  offset~ : Int64 = 0L,
) -> Array[Bucket] {
  let step = if step < 1L { 1L } else { step }
  let local_from = p.from + offset
  let first = local_from - (local_from % step + step) % step - offset
  let n = ((p.to - first + step - 1L) / step).to_int()
  let n = if n < 0 { 0 } else { n }
  let acc = Array::makei(n, _ => FixedArray::make(6, 0L))
  for r in rows {
    if r.minute >= p.from && r.minute < p.to {
      add_row(acc[((r.minute - first) / step).to_int()], r)
    }
  }
  Array::makei(n, i => {
    start: first + i.to_int64() * step,
    split: split_of(acc[i]),
  })
}

///|
/// A bucket size giving at most about `max_points` points.
pub fn timeline_step(p : Period, max_points~ : Int32 = 96) -> Int64 {
  let span = p.to - p.from
  for s in [1L, 5L, 10L, 15L, 30L, 60L, 120L, 180L, 360L, 720L, 1440L] {
    if span / s <= max_points.to_int64() {
      return s
    }
  }
  1440L
}

///|
#derive(Eq, Debug)
pub(all) struct Unclassified {
  process : String
  domain : String
  bytes : Int64
}

///|
/// Traffic of app "Unknown" per (process, domain), largest first.
pub fn unclassified(rows : Array[@store.UsageRecord]) -> Array[Unclassified] {
  let sums : Map[(String, String), Int64] = Map([])
  for r in rows {
    if r.app == "Unknown" {
      let k = (r.process, r.domain)
      sums[k] = sums.get_or_default(k, 0L) + r.up + r.down
    }
  }
  let out = sums
    .iter()
    .map(kv => { process: kv.0.0, domain: kv.0.1, bytes: kv.1, })
    .collect()
  out.sort_by((x, y) => {
    match y.bytes.compare(x.bytes) {
      0 => (x.process + x.domain).compare(y.process + y.domain)
      c => c
    }
  })
  out
}

///|
fn csv_field(s : String) -> String {
  if s.contains(",") || s.contains("\"") || s.contains("\n") {
    "\"" + s.replace_all(old="\"", new="\"\"") + "\""
  } else {
    s
  }
}

///|
/// The rows as CSV, one line per ledger row, minutes in local time.
pub fn csv(rows : Array[@store.UsageRecord], offset : Int32) -> String {
  let buf = StringBuilder()
  buf.write_string("minute,app,process,domain,entry,exit,node,rule,up,down\n")
  for r in rows {
    let cells = [
      @report.format_local(r.minute * @store.ticks_per_minute, offset),
      r.app,
      r.process,
      r.domain,
      r.entry,
      r.exit_kind,
      r.node,
      r.rule,
      r.up.to_string(),
      r.down.to_string(),
    ]
    buf.write_string(cells.map(csv_field).join(","))
    buf.write_char('\n')
  }
  buf.to_string()
}
