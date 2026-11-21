// `netwhere report`, `netwhere unknown`, `netwhere export`.

///|
let period_help : String = "--today (default) | --7d | --30d | --hours N"

///|
/// The period from the options.
fn period(a : @cli.Args, now : Int64) -> @query.Period raise {
  if a.has("--7d") {
    @query.last_days(7, now)
  } else if a.has("--30d") {
    @query.last_days(30, now)
  } else if a.options.contains("--hours") {
    @query.last_hours(a.int("--hours", 24), now)
  } else {
    @query.today(now, offset)
  }
}

///|
fn cmd_report_rows(
  rows : Array[@store.UsageRecord],
  by : String,
  limit : Int32,
  config : @config.Config,
) -> String {
  let h = @report.human_bytes
  if by == "node" {
    let ns = @query.nodes(rows, n => config.multiplier(n))
    let shown = if ns.length() > limit { ns[:limit].to_owned() } else { ns }
    @report.table(
      ["node", "traffic", "multiplier", "plan usage"],
      shown.map(n => [n.node, h(n.bytes), n.multiplier.to_string(), h(n.plan)]),
    )
  } else {
    let gs = @query.group(rows, by)
    let shown = if gs.length() > limit { gs[:limit].to_owned() } else { gs }
    @report.table(
      [by, "via node", "core direct", "core ?", "bypass/direct", "lan", "total"],
      shown.map(g => {
        let v = g.split
        [
          g.key,
          h(v.via_node),
          h(v.core_direct),
          h(v.core_unknown),
          h(v.bypass),
          h(v.lan),
          h(v.total),
        ]
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
    let { from, to, label, } = period(a, @sys.now())
    let limit = a.int("--limit", 25)
    let config = load_config(dir) catch { _ => @config.default() }
    let rows = @query.filter(
      db.usage_between(from, to),
      app?=a.options.get("--app"),
      entry?=a.options.get("--route"),
    )
    println("traffic \{label}, by \{by}:")
    println("")
    println(cmd_report_rows(rows, by, limit, config).trim_end())
    // Plan consumption: proxy-node bytes times each node's multiplier; a
    // range when some exits are unknown or ambiguous.
    let t = @query.totals(rows, n => config.multiplier(n))
    let total = t.split.total
    let plan = t.plan
    let mut bypass = 0L
    for r in rows {
      if r.entry == "bypass" {
        bypass += r.up + r.down
      }
    }
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
    let { from, to, label, } = if a.has("--today") ||
      a.has("--30d") ||
      a.options.contains("--hours") {
      period(a, now)
    } else {
      @query.last_days(7, now)
    }
    let all = @query.unclassified(db.usage_between(from, to))
    let limit = a.int("--limit", 30)
    let shown = if all.length() > limit { all[:limit].to_owned() } else { all }
    println("unclassified traffic, \{label}:")
    println("")
    println(
      @report.table(
        ["process", "domain", "traffic"],
        shown.map(u => {
          [
            u.process,
            if u.domain == "" {
              "(no name)"
            } else {
              u.domain
            },
            @report.human_bytes(u.bytes),
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
    let { from, to, .. } = period(a, @sys.now())
    let text = @query.csv(db.usage_between(from, to), offset)
    match a.options.get("--out") {
      Some(path) => {
        @fs.write_file(path, text)
        println("wrote \{path}")
      }
      None => println(text.trim_end())
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
