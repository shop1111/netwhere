// Spike: subscribe to Mihomo /connections (with a short interval) and /logs
// over WebSocket using moonbitlang/async, to learn whether short-lived
// connections can be captured.
//
//   main <controller host:port> <secs> [interval_ms] [log_level]

///|
async fn watch_connections(base : String, interval : String) -> Unit {
  let ws = @websocket.connect("ws://\{base}/connections?interval=\{interval}")
  defer ws.close()
  let seen : Map[String, Bool] = {}
  let mut msgs = 0
  let mut bytes = 0
  for ;; {
    let text = ws.recv().read_all().text()
    msgs += 1
    bytes += text.length()
    // Cheap scan for "sourcePort":"NNNN" occurrences, without a JSON dep.
    let key = "\"sourcePort\":\""
    let mut rest = text[:]
    while rest.find(key) is Some(i) {
      let after = rest[i + key.length():]
      let port = match after.find("\"") {
        Some(j) => after[:j].to_string()
        None => ""
      }
      if !seen.contains(port) {
        seen[port] = true
        println("[conn #\{msgs}] new sourcePort \{port}")
      }
      rest = after
    }
    if msgs % 25 == 0 {
      println(
        "[conn] \{msgs} messages, \{bytes} chars, \{seen.length()} distinct ports",
      )
    }
  }
}

///|
async fn watch_logs(base : String, level : String) -> Unit {
  let ws = @websocket.connect("ws://\{base}/logs?level=\{level}")
  defer ws.close()
  for ;; {
    let text = ws.recv().read_all().text()
    println("[log] \{text}")
  }
}

///|
async fn main {
  let args = @env.args()
  let base = if args.length() > 1 { args[1] } else { "127.0.0.1:9090" }
  let secs = if args.length() > 2 { parse_int(args[2]) } else { 10 }
  let interval = if args.length() > 3 { args[3] } else { "200" }
  let level = if args.length() > 4 { args[4] } else { "info" }
  let _ = @async.with_timeout_opt(secs * 1000, () => {
    @async.with_task_group(group => {
      group.spawn_bg(() => watch_connections(base, interval))
      group.spawn_bg(() => watch_logs(base, level))
    })
  })
  println("done after \{secs}s")
}

///|
fn parse_int(s : String) -> Int32 {
  let mut n : Int32 = 0
  for ch in s {
    n = n * 10 + (ch.to_int() - '0'.to_int())
  }
  n
}
