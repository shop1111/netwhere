///|
async fn cmd_status(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("status: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  println("data: \{dir}")
  guard open_ledger(dir) is Some(db) else { return 1 }
  let h = db.heartbeat() catch { _ => None }
  db.close()
  let now = @sys.now()
  let (running, state) = collector_state(h, now)
  match h {
    None => println("collector: \{state}")
    Some(h) => {
      println(
        "collector: \{state} (pid \{h.pid}, since \{@report.format_local(h.started, offset)})",
      )
      if running {
        println(
          if h.degraded {
            "mode: degraded: not elevated, so direct traffic is not recorded (only DNS and the proxy core)"
          } else {
            "mode: full (Kernel-Network, DNS-Client, Kernel-Process)"
          },
        )
        println("mihomo: \{h.core_link}")
        println(
          "events: \{h.events}, dropped: \{h.dropped}, live flows: \{h.flows}, memory: \{@report.human_bytes(h.private_bytes)}",
        )
      }
      if h.last_error != "" {
        println("last error: \{h.last_error}")
      }
    }
  }
  match (Ok(load_config(dir)) catch { e => Err(e) }) {
    Ok(c) =>
      println(
        "config: \{c.rules.length()} user rules, controller \{c.controller}",
      )
    Err(e) => println("config: \{e}")
  }
  if running {
    0
  } else {
    1
  }
}
