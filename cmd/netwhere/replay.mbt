// `netwhere replay FILE`: run a recording through the ledger and print what
// `trace` would print. `--pid N` limits the output to that process tree;
// `--expect` prints a JSON summary to start a scenario's expected.json from.

///|
fn group_json(flows : Array[@ledger.FlowSummary], core_present : Bool) -> Json {
  let groups : Map[String, (@ledger.FlowSummary, Int64, Int64, Int32)] = Map([])
  let order = []
  for f in flows {
    let dest = if f.domain != "" {
      "\{f.domain}:\{f.target_port}"
    } else {
      f.peer.to_string()
    }
    let key = "\{@ledger.base_name(f.process)}|\{f.proto}|\{dest}|\{f.entry}|\{f.exit}"
    match groups.get(key) {
      Some((g, u, d, n)) => groups[key] = (g, u + f.up, d + f.down, n + 1)
      None => {
        groups[key] = (f, f.up, f.down, 1)
        order.push((key, dest))
      }
    }
  }
  let items = order.map(kd => {
    let (f, u, d, n) = groups[kd.0]
    let m = Map([])
    m["process"] = Json::string(@ledger.base_name(f.process))
    m["proto"] = Json::string(if f.proto == Tcp { "tcp" } else { "udp" })
    m["dest"] = Json::string(kd.1)
    m["entry"] = Json::string(@report.entry_label(f.entry, core_present))
    m["exit"] = Json::string(@report.exit_label(f.exit))
    m["up"] = Json::number(u.to_double())
    m["down"] = Json::number(d.to_double())
    m["conns"] = Json::number(n.to_double())
    Json::object(m)
  })
  let top = Map([])
  top["flows"] = Json::array(items)
  Json::object(top)
}

///|
async fn cmd_replay(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--pid"], switches=["--expect"]) catch {
    e => {
      println("replay: \{e}")
      return 2
    }
  }
  guard a.positional is [path] else {
    println("usage: netwhere replay FILE [--pid N] [--expect]")
    return 2
  }
  let text = @fs.read_file(path).text() catch {
    e => {
      println("replay: cannot read \{path}: \{e}")
      return 1
    }
  }
  let rec = @ledger.parse_recording(text) catch {
    e => {
      println("replay: \{e}")
      return 1
    }
  }
  let (engine, stats) = @ledger.replay(rec)
  let pid = a.int("--pid", 0) catch { _ => 0 }
  let flows = if pid > 0 {
    let tree = engine.process_tree(pid)
    engine.flows().filter(f => tree.contains(f.pid))
  } else {
    engine.flows()
  }
  let core = engine.core_present()
  if a.has("--expect") {
    println(group_json(flows, core).stringify(indent=2))
    return 0
  }
  let h = rec.header
  println("recording: \{path}")
  if h.note != "" {
    println("note: \{h.note}")
  }
  println(
    "cores: " +
    (if h.cores.length() == 0 {
      "none"
    } else {
      h.cores.map(c => "\{c.name}(\{c.pid})").join(", ")
    }) +
    "; tun: " +
    (if h.tun.length() == 0 {
      "off"
    } else {
      h.tun.map(t => t.if_name).join(", ")
    }),
  )
  println("records: \{rec.records.length()}, flows: \{flows.length()}")
  if stats.net_ignored + stats.dns_ignored + stats.core_frames_bad > 0 {
    println(
      "ignored: net \{stats.net_ignored}, dns \{stats.dns_ignored}, bad core frames \{stats.core_frames_bad}",
    )
  }
  println("")
  println(@report.flow_table(flows, core).trim_end())
  println("")
  println("totals:")
  println(
    @report.totals_text(
      if pid > 0 {
        @ledger.totals_of(flows)
      } else {
        engine.totals()
      },
      core,
    ).trim_end(),
  )
  0
}
