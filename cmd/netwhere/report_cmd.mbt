// `netwhere report`, `netwhere unknown`, `netwhere export`.

///|
let period_help : String = "--today (default) | --7d | --30d | --hours N"

///|
/// [from, to) in minutes from the period options.
fn period(a : @cli.Args, now : Int64) -> (Int64, Int64, String) raise {
  let minute = @store.ticks_per_minute
  let to = now / minute + 1L
  if a.has("--7d") {
    (to - 7L * 1440L, to, "last 7 days")
  } else if a.has("--30d") {
    (to - 30L * 1440L, to, "last 30 days")
  } else if a.options.contains("--hours") {
    let h = a.int("--hours", 24)
    (to - h.to_int64() * 60L, to, "last \{h} hours")
  } else {
    (@report.local_day_start(now, offset) / minute, to, "today")
  }
}

///|
/// The column a row's bytes go to in the app table.
fn route_column(r : @store.UsageRecord) -> Int32 {
  match (r.exit_kind, r.entry) {
    ("node", _) => 0
    ("core-direct", _) | ("core-reject", _) => 1
    ("unknown", _) | ("ambiguous", _) => 2
    (_, "lan") => 4
    _ => 3
  }
}

///|
fn key_of(r : @store.UsageRecord, by : String) -> String {
  match by {
    "domain" => if r.domain == "" { "(no name)" } else { r.domain }
    "process" => r.process
    "node" => r.node
    "entry" => r.entry
    _ => r.app
  }
}

///|
fn cmd_report_rows(
  rows : Array[@store.UsageRecord],
  by : String,
  limit : Int32,
  config : @config.Config,
) -> String {
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
    v[route_column(r)] = v[route_column(r)] + r.up + r.down
    v[5] = v[5] + r.up + r.down
  }
  let keys = sums.keys().collect()
  keys.sort_by((a, b) => sums[b][5].compare(sums[a][5]))
  let shown = if keys.length() > limit { keys[:limit].to_owned() } else { keys }
  let h = @report.human_bytes
  if by == "node" {
    @report.table(
      ["node", "traffic", "multiplier", "plan usage"],
      shown.map(k => {
        let m = config.multiplier(k)
        let est = (sums[k][5].to_double() * m).to_int64()
        [k, h(sums[k][5]), m.to_string(), h(est)]
      }),
    )
  } else {
    @report.table(
      [by, "via node", "core direct", "core ?", "bypass/direct", "lan", "total"],
      shown.map(k => {
        let v = sums[k]
        [k, h(v[0]), h(v[1]), h(v[2]), h(v[3]), h(v[4]), h(v[5])]
      }),
    )
  }
}

///|
async fn cmd_report(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(
    args,
    with_value=["--data-dir", "--hours", "--by", "--app", "--route", "--limit"],
    switches=["--today", "--7d", "--30d"],
  ) catch {
    e => {
      println(
        "report: \{e}\nusage: netwhere report [\{period_help}] [--by app|domain|node|process|entry] [--app X] [--route ENTRY] [--limit N]",
      )
      return 2
    }
  }
  let dir = data_dir_of(a)
  let by = a.get("--by", "app")
  if !["app", "domain", "node", "process", "entry"].contains(by) {
    println("report: --by must be app, domain, node, process or entry")
    return 2
  }
  guard open_ledger(dir) is Some(db) else { return 1 }
  let result = try {
    let (from, to, label) = period(a, @sys.now())
    let limit = a.int("--limit", 25)
    let config = load_config(dir) catch { _ => @config.default() }
    let rows = db
      .usage_between(from, to)
      .filter(r => {
        (match a.options.get("--app") {
          Some(app) => r.app.to_lower() == app.to_lower()
          None => true
        }) &&
        (match a.options.get("--route") {
          Some(e) => r.entry == e
          None => true
        })
      })
    println("traffic \{label}, by \{by}:")
    println("")
    println(cmd_report_rows(rows, by, limit, config).trim_end())
    // Plan consumption: proxy-node bytes times each node's multiplier; a
    // range when some exits are unknown or ambiguous.
    let mut total = 0L
    let mut bypass = 0L
    for r in rows {
      total += r.up + r.down
      if r.entry == "bypass" {
        bypass += r.up + r.down
      }
    }
    let plan = @report.plan_estimate(
      rows.map(r => (r.exit_kind, r.node, r.up + r.down)),
      n => config.multiplier(n),
    )
    let h = @report.human_bytes
    println("")
    println(
      if plan.uncertain == 0L {
        "total \{h(total)}; estimated plan usage \{h(plan.low)}"
      } else {
        "total \{h(total)}; estimated plan usage \{h(plan.low)} to \{h(plan.high)} (\{h(plan.uncertain)} with unknown or ambiguous exit)"
      },
    )
    println(
      "  plan usage counts application bytes (with TLS/HTTP, without proxy-protocol overhead); multipliers come from config.json or node names",
    )
    if bypass > 0L {
      println(
        "  \{h(bypass)} bypassed the core; `netwhere trace -- COMMAND` shows candidate causes for a command",
      )
    }
    let now_minute = @sys.now() / @store.ticks_per_minute + 1L
    let cov_rows = db.coverage_between(from, to)
    let cov = @report.summarize_coverage(
      cov_rows,
      from,
      if to < now_minute {
        to
      } else {
        now_minute
      },
    )
    let gaps = @report.coverage_text(cov)
    if cov_rows.length() == 0 {
      // Ledgers written before coverage existed (0.1.0) have none.
      println("")
      println(
        "not covered: no coverage records for this period, so gaps cannot be ruled out",
      )
    } else if gaps != "" {
      println("")
      println("not covered:")
      println(gaps.trim_end())
    }
    0
  } catch {
    e => {
      println("report: \{e}")
      1
    }
  }
  db.close()
  result
}

///|
async fn cmd_unknown(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir", "--hours", "--limit"], switches=[
    "--today", "--7d", "--30d",
  ]) catch {
    e => {
      println("unknown: \{e}")
      return 2
    }
  }
  guard open_ledger(data_dir_of(a)) is Some(db) else { return 1 }
  let result = try {
    let now = @sys.now()
    let (from, to, label) = if a.has("--today") ||
      a.has("--30d") ||
      a.options.contains("--hours") {
      period(a, now)
    } else {
      let to = now / @store.ticks_per_minute + 1L
      (to - 7L * 1440L, to, "last 7 days")
    }
    let sums : Map[(String, String), Int64] = Map([])
    for r in db.usage_between(from, to) {
      if r.app == "Unknown" {
        let k = (r.process, r.domain)
        sums[k] = sums.get_or_default(k, 0L) + r.up + r.down
      }
    }
    let keys = sums.keys().collect()
    keys.sort_by((x, y) => sums[y].compare(sums[x]))
    let limit = a.int("--limit", 30)
    let shown = if keys.length() > limit {
      keys[:limit].to_owned()
    } else {
      keys
    }
    println("unclassified traffic, \{label}:")
    println("")
    println(
      @report.table(
        ["process", "domain", "traffic"],
        shown.map(k => {
          [
            k.0,
            if k.1 == "" {
              "(no name)"
            } else {
              k.1
            },
            @report.human_bytes(sums[k]),
          ]
        }),
      ).trim_end(),
    )
    println("")
    println("classify with: netwhere classify <domain|process.exe> <app name>")
    0
  } catch {
    e => {
      println("unknown: \{e}")
      1
    }
  }
  db.close()
  result
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
async fn cmd_export(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir", "--hours", "--out"], switches=[
    "--csv", "--today", "--7d", "--30d",
  ]) catch {
    e => {
      println("export: \{e}")
      return 2
    }
  }
  guard open_ledger(data_dir_of(a)) is Some(db) else { return 1 }
  let result = try {
    let (from, to, _) = period(a, @sys.now())
    let buf = StringBuilder()
    buf.write_string("minute,app,process,domain,entry,exit,node,rule,up,down\n")
    for r in db.usage_between(from, to) {
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
    match a.options.get("--out") {
      Some(path) => {
        @fs.write_file(path, buf.to_string())
        println("wrote \{path}")
      }
      None => println(buf.to_string().trim_end())
    }
    0
  } catch {
    e => {
      println("export: \{e}")
      1
    }
  }
  db.close()
  result
}
