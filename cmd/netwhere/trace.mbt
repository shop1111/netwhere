// `netwhere trace -- COMMAND ...`: run a command in this terminal (with
// this terminal's environment) and report where its process tree's traffic
// went.
//
// With a running collector the mailbox protocol is used: register, start
// the command suspended, report its pid, resume once the collector tracks
// it, report "done" when it exits, read the stored result. Without one the
// trace degrades to what an unprivileged process can see: the proxy core's
// view of the tree's connections.

///|
let tick : Int64 = 10_000_000L

///|
async fn send_message(dir : String, m : @mailbox.Message, seq : Int32) -> Unit {
  let name = "\{dir}\\requests\\\{m.id}.\{seq + 100}.json"
  @fs.write_file(name + ".tmp", m.to_json_text())
  @fs.rename(name + ".tmp", name, replace=true)
}

///|
/// Polls the request row until its state is one of `states` or `ms` pass.
async fn wait_state(
  db : @store.Db,
  id : String,
  states : Array[String],
  ms : Int32,
) -> @store.RequestRow? {
  let deadline = @sys.now() + ms.to_int64() * 10_000L
  for ;; {
    let row = db.request(id) catch { _ => None }
    match row {
      Some(r) if states.contains(r.state) => return Some(r)
      _ => ()
    }
    if @sys.now() > deadline {
      return row
    }
    @async.sleep(100)
  }
}

///|
/// Waits for the child, keeping the event loop responsive.
async fn wait_child() -> Int32 {
  while !@sys.child_wait(20) {
    @async.sleep(80)
  }
  @sys.child_exit_code()
}

///|
fn exit_text(kind : String, node : String) -> String {
  match kind {
    "node" => node
    "core-direct" => "DIRECT (core)"
    "core-reject" => "REJECT (core)"
    "unknown" => "?"
    _ => "-"
  }
}

///|
fn trace_table(flows : Array[@store.TraceFlow]) -> String {
  let groups : Map[
    (String, String, String, String, String),
    (Int64, Int64, Int32),
  ] = Map([])
  let order = []
  for f in flows {
    let dest = if f.domain != "" {
      "\{f.domain}:\{f.target_port}"
    } else {
      f.peer
    }
    let k = (
      @ledger.base_name(f.process),
      "\{f.proto} \{dest}",
      f.entry,
      exit_text(f.exit_kind, f.node) +
      (if f.match_kind == "ambiguous" { " ~" } else { "" }) +
      (if f.inconsistent { " !" } else { "" }),
      f.rule,
    )
    match groups.get(k) {
      Some((u, d, n)) => groups[k] = (u + f.up, d + f.down, n + 1)
      None => {
        groups[k] = (f.up, f.down, 1)
        order.push(k)
      }
    }
  }
  order.sort_by((a, b) => {
    let (ua, da, _) = groups[a]
    let (ub, db, _) = groups[b]
    (ub + db).compare(ua + da)
  })
  @report.table(
    ["process", "destination", "entry", "exit", "up", "down", "conns", "rule"],
    order.map(k => {
      let (u, d, n) = groups[k]
      [
        k.0,
        k.1,
        k.2,
        k.3,
        @report.human_bytes(u),
        @report.human_bytes(d),
        n.to_string(),
        k.4,
      ]
    }),
  )
}

///|
fn route_summary(flows : Array[@store.TraceFlow]) -> String {
  let sums : Map[String, Int64] = Map([])
  let order = []
  for f in flows {
    let k = if f.exit_kind == "node" { f.entry + " -> node" } else { f.entry }
    if !sums.contains(k) {
      order.push(k)
    }
    sums[k] = sums.get_or_default(k, 0L) + f.up + f.down
  }
  order.map(k => "\{k} \{@report.human_bytes(sums[k])}").join(", ")
}

///|
async fn trace_with_collector(
  dir : String,
  db : @store.Db,
  cmdline : String,
  controller : @client.Controller,
) -> Int32 {
  let me = @sys.current_pid()
  let id = "trace-\{@sys.now()}-\{me}"
  let msg : @mailbox.Message = {
    id,
    kind: Trace,
    op: Start,
    client_pid: me,
    root_pid: 0,
  }
  send_message(dir, msg, 0) catch {
    e => {
      println("trace: cannot write to the mailbox: \{e}")
      return 2
    }
  }
  match wait_state(db, id, ["ready", "rejected", "expired"], 5000) {
    Some(r) if r.state == "ready" => ()
    Some(r) => {
      println("trace: the collector refused the request: \{r.reason}")
      return 2
    }
    None => {
      println(
        "trace: the collector did not answer (is it running? see `netwhere status`)",
      )
      return 2
    }
  }
  let started = @sys.now()
  let pid = @sys.spawn_suspended(cmdline) catch {
    e => {
      println("trace: \{e}")
      send_message(dir, { ..msg, op: Done, }, 2) catch {
        _ => ()
      }
      return 2
    }
  }
  send_message(dir, { ..msg, op: Root, root_pid: pid, }, 1) catch {
    _ => ()
  }
  let confirmed = wait_state(db, id, ["running", "rejected"], 6000)
  // The command runs whatever the collector said; the report says why it
  // is missing when tracking failed.
  ignore(@sys.resume_child())
  let code = wait_child()
  send_message(dir, { ..msg, op: Done, }, 2) catch {
    _ => ()
  }
  let done = wait_state(db, id, ["complete", "rejected", "expired"], 15000)
  println("")
  println("---- netwhere trace: \{cmdline}")
  match (confirmed, done) {
    (Some(c), _) if c.state == "rejected" => println("not traced: \{c.reason}")
    (_, Some(d)) if d.state == "complete" => {
      let procs = db.trace_procs(id) catch { _ => [] }
      let flows = db.trace_flows(id) catch { _ => [] }
      println(
        "exit code \{code}; processes: " +
        procs.map(p => "\{@ledger.base_name(p.2)}(\{p.0})").join(", "),
      )
      if flows.length() == 0 {
        println("no network traffic")
      } else {
        println(trace_table(flows).trim_end())
        println("")
        println("by route: " + route_summary(flows))
        let marks = marks_text(flows)
        if marks != "" {
          println(marks.trim_end())
        }
        let why = why_text(flows, diag_context(controller, flows))
        if why != "" {
          println("")
          println(why.trim_end())
        }
      }
      let minute = @store.ticks_per_minute
      let cov = db.coverage_between(started / minute, @sys.now() / minute + 1L) catch {
        _ => []
      }
      let gaps = trace_gaps_text(cov)
      if gaps != "" {
        println("")
        println("what this trace may have missed:")
        println(gaps.trim_end())
      }
    }
    (_, Some(d)) => println("not traced: \{d.state} \{d.reason}")
    (_, None) => println("not traced: the collector did not finish the request")
  }
  code
}

///|
/// Without a collector: what the proxy core saw for the command's tree.
async fn trace_degraded(
  cmdline : String,
  controller : @client.Controller,
) -> Int32 {
  println(
    "note: no running collector; showing only connections that reached the proxy core.",
  )
  println(
    "      Direct connections are not visible without `netwhere install`.",
  )
  let logs : Array[@mihomo.ConnLog] = []
  let snaps : Map[String, @mihomo.Conn] = Map([])
  let started = @sys.now()
  let code = @async.with_task_group(group => {
    group.spawn_bg(no_wait=true, () => {
      let parser = @mihomo.ConnLogParser::new()
      controller.watch_logs(text => {
        if (Ok(@mihomo.parse_log_message(text)) catch { e => Err(e) }) is Ok(m) &&
          parser.feed(m.payload) is Some(l) {
          logs.push(l)
        }
      })
    })
    group.spawn_bg(no_wait=true, () => {
      controller.watch_connections(500, text => {
        if (Ok(@mihomo.parse_snapshot(text)) catch { e => Err(e) }) is Ok(s) {
          for c in s.conns {
            match c.start {
              Some(t) if t >= started - tick => snaps[c.id] = c
              _ => ()
            }
          }
        }
      })
    })
    @async.sleep(300)
    let pid = @sys.spawn_suspended(cmdline) catch {
      e => {
        println("trace: \{e}")
        return 2
      }
    }
    ignore(@sys.resume_child())
    // Follow the tree by polling process snapshots (no process events
    // without elevation).
    let names : Map[String, Bool] = Map([])
    let tree = [pid]
    while !@sys.child_wait(20) {
      for e in @sys.process_list() {
        if tree.contains(e.ppid) && !tree.contains(e.pid) {
          tree.push(e.pid)
        }
        if tree.contains(e.pid) {
          names[e.exe.to_lower()] = true
        }
      }
      @async.sleep(100)
    }
    let code = @sys.child_exit_code()
    @async.sleep(1500)
    println("")
    println("---- netwhere trace (degraded): \{cmdline}")
    println(
      "exit code \{code}; processes seen: " + names.keys().collect().join(", "),
    )
    let rows = []
    for _, c in snaps {
      if names.contains(c.process.to_lower()) {
        rows.push([
          c.process,
          "\{c.network} \{c.host}:\{c.dest_port}",
          c.inbound_type,
          c.outbound(),
          @report.human_bytes(c.upload),
          @report.human_bytes(c.download),
          c.rule,
        ])
      }
    }
    for l in logs {
      if names.contains(l.process.to_lower()) &&
        !snaps.values().any(c => c.source_port == l.source_port) {
        rows.push([
          l.process,
          "\{l.network} \{l.dest_host}:\{l.dest_port}",
          "",
          l.outbound,
          "?",
          "?",
          l.rule,
        ])
      }
    }
    if rows.length() == 0 {
      println("no connection of this command reached the proxy core")
    } else {
      println(
        @report.table(
          ["process", "destination", "inbound", "exit", "up", "down", "rule"],
          rows,
        ).trim_end(),
      )
    }
    code
  })
  code
}

///|
async fn cmd_trace(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[
    "--degraded", "--via-collector",
  ]) catch {
    e => {
      println("trace: \{e}")
      return 2
    }
  }
  if a.rest.length() == 0 {
    println("usage: netwhere trace [--degraded] -- COMMAND [ARGS...]")
    return 2
  }
  let cmdline = @sys.join_command_line(a.rest[:])
  let dir = data_dir_of(a)
  let config = load_config(dir) catch { _ => @config.default() }
  let controller = @client.Controller::new(
    addr=config.controller,
    secret=config.secret,
  )
  let db = if a.has("--degraded") || !@fs.exists(dir + "\\ledger.db") {
    None
  } else {
    Some(@store.Db::open_reader(dir + "\\ledger.db")) catch {
      _ => None
    }
  }
  match db {
    Some(db) => {
      let hb = db.heartbeat() catch { _ => None }
      let (running, _) = collector_state(hb, @sys.now())
      let degraded = match hb {
        Some(h) => h.degraded
        None => true
      }
      // --via-collector: use the mailbox even when the collector is
      // degraded (protocol testing without elevation).
      let code = if running && (!degraded || a.has("--via-collector")) {
        trace_with_collector(dir, db, cmdline, controller)
      } else {
        trace_degraded(cmdline, controller)
      }
      db.close()
      code
    }
    None => trace_degraded(cmdline, controller)
  }
}
