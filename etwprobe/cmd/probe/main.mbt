// etwprobe: can MoonBit native consume real-time ETW network / DNS / process events?
//
//   probe env                       privilege check + start each provider separately
//   probe leak | probe check        start a session and exit without stopping it / look for it
//   probe schema [secs]             print the first event of every (provider, id, version)
//   probe net [secs]                aggregate network bytes per process and endpoint
//   probe trace [--proxy-port N] [--secs-after S] -- <command line>
//                                   run a command, follow its process tree, report where
//                                   its traffic went

///|
const Session : String = "MoonEtwProbe"

///|
fn mb(n : Int64) -> String {
  let v = n.to_double() / 1048576.0
  let s = (v * 100.0).round() / 100.0
  "\{s} MB"
}

///|
fn kb(n : Int64) -> String {
  if n < 10240L {
    "\{n} B"
  } else {
    let s = (n.to_double() / 1024.0 * 10.0).round() / 10.0
    "\{s} KB"
  }
}

///|
fn pad(s : String, n : Int32) -> String {
  let len = s.length()
  if len >= n {
    s
  } else {
    s + " ".repeat(n - len)
  }
}

///|
fn basename(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[i + 1:].to_owned()
    None => path
  }
}

///|
let image_cache : Map[Int32, String] = Map([])

///|
fn image(pid : Int32) -> String {
  match image_cache.get(pid) {
    Some(s) => s
    None => {
      let full = @etw.image_name(pid)
      let s = if full == "" {
        if pid == 4 {
          "System"
        } else if pid == 0 {
          "Idle"
        } else {
          "?"
        }
      } else {
        basename(full)
      }
      image_cache[pid] = s
      s
    }
  }
}

///|
fn start_or_exit(
  net~ : Bool = true,
  dns~ : Bool = true,
  process~ : Bool = true,
) -> Unit {
  @etw.start(Session, net~, dns~, process~) catch {
    e => {
      println("FAILED to start ETW session: \{e.message()}")
      panic()
    }
  }
}

///|
fn print_usage_summary(wall_ms : Double) -> Unit {
  let s = @etw.stats()
  let u = @etw.self_usage()
  let per_event = if s.events > 0L { s.callback_ns / s.events } else { 0L }
  let secs = wall_ms / 1000.0
  let rate = if secs > 0.0 {
    (s.events.to_double() / secs).round()
  } else {
    0.0
  }
  println("---- consumer statistics")
  println(
    "events: \{s.events} (net \{s.net}, dns \{s.dns}, process \{s.process}, other \{s.other}) over \{secs.round()} s = \{rate}/s",
  )
  println(
    "dropped records: \{s.dropped}; TDH decode failures: \{s.decode_fail}; max queue: \{kb(s.max_queue)}; queued total: \{mb(s.queued_bytes)}",
  )
  println(
    "callback cost: \{per_event} ns/event (TDH generic decoding, includes queue append)",
  )
  match @etw.query() {
    Some(q) =>
      println(
        "session: EventsLost=\{q[0]} BuffersWritten=\{q[1]} LogBuffersLost=\{q[2]} RealTimeBuffersLost=\{q[3]} Buffers=\{q[4]} Free=\{q[5]}",
      )
    None => ()
  }
  println(
    "probe process: cpu \{u[0]} ms, private \{mb(u[1])}, working set \{mb(u[2])}, peak WS \{mb(u[3])}",
  )
}

// ------------------------------------------------------------------ env

///|
fn run_env() -> Unit {
  let elev = @etw.is_elevated()
  println("[env] token elevated: \{elev} (1 = yes, 0 = no)")
  let cases : Array[(String, Bool, Bool, Bool)] = [
    ("Kernel-Network", true, false, false),
    ("DNS-Client", false, true, false),
    ("Kernel-Process", false, false, true),
    ("all three", true, true, true),
  ]
  for c in cases {
    let (label, net, dns, process) = c
    try @etw.start(Session, net~, dns~, process~) catch {
      e => println("[env] \{pad(label, 15)} FAILED  \{e.message()}")
    } noraise {
      _ => {
        @etw.sleep_ms(1500)
        let r = @etw.Reader::new()
        let n = r.drain().length()
        let code = @etw.stop()
        println(
          "[env] \{pad(label, 15)} OK      \{n} events in 1.5 s, stop -> \{code}",
        )
      }
    }
  }
  println(
    "[env] session \{Session} exists after stop: \{@etw.session_exists(Session)}",
  )
}

///|
fn run_leak() -> Unit {
  start_or_exit()
  @etw.abandon()
  println("[leak] started \{Session} and exiting without stopping it")
}

///|
fn run_check() -> Unit {
  println(
    "[check] session \{Session} exists: \{@etw.session_exists(Session)} (1 = running)",
  )
  start_or_exit()
  @etw.sleep_ms(300)
  println(
    "[check] stale sessions stopped on start: \{@etw.stats().stale_sessions}",
  )
  ignore(@etw.stop())
  println("[check] exists after stop: \{@etw.session_exists(Session)}")
}

// ------------------------------------------------------------------ schema

///|
fn run_schema(secs : Int32) -> Unit {
  start_or_exit()
  let r = @etw.Reader::new()
  let seen : Map[String, Int32] = Map([])
  let order : Array[String] = []
  let t0 = @etw.now_ms()
  while @etw.now_ms() - t0 < secs.to_double() * 1000.0 {
    @etw.sleep_ms(100)
    for e in r.drain() {
      let k = e.key()
      match seen.get(k) {
        Some(n) => seen[k] = n + 1
        None => {
          seen[k] = 1
          order.push(k)
          println(
            "== \{k} task=\{e.schema.task} opcode=\{e.schema.opcode}(\{e.opcode}) header pid=\{e.pid} (\{image(e.pid)})",
          )
          for i, name in e.schema.names {
            println("     \{pad(name, 22)} \{e.values[i].render()}")
          }
        }
      }
    }
  }
  ignore(@etw.stop())
  println("---- event counts")
  for k in order {
    println("  \{pad(k, 30)} \{seen.get(k).unwrap_or(0)}")
  }
  println("unknown-schema records: \{r.unknown_schema()}")
  print_usage_summary(@etw.now_ms() - t0)
}

// ------------------------------------------------------------------ network helpers

///|
priv struct NetEv {
  pid : Int32
  header_pid : Int32
  tcp : Bool
  send : Bool
  size : Int64
  daddr : String
  dport : Int32
  saddr : String
  sport : Int32
}

///|
/// Recognises byte-carrying Kernel-Network events by schema, not by event id.
fn net_event(e : @etw.Event) -> NetEv? {
  if e.provider != @etw.ProviderNet {
    return None
  }
  guard e.int("size") is Some(size) else { None }
  guard e.str("daddr") is Some(daddr) else { None }
  let op = e.schema.opcode.to_lower()
  let send = op.contains("send") || op.contains("sent")
  let recv = op.contains("recv") || op.contains("receiv")
  if !send && !recv {
    return None
  }
  Some({
    pid: e.int("PID").unwrap_or(-1L).to_int(),
    header_pid: e.pid,
    tcp: e.schema.task.to_upper().contains("TCP"),
    send,
    size,
    daddr: strip_mapped(daddr),
    dport: e.int("dport").unwrap_or(0L).to_int(),
    saddr: strip_mapped(e.str("saddr").unwrap_or("?")),
    sport: e.int("sport").unwrap_or(0L).to_int(),
  })
}

///|
fn strip_mapped(ip : String) -> String {
  if ip.has_prefix("::ffff:") {
    ip[7:].to_owned()
  } else {
    ip
  }
}

///|
fn is_loopback(ip : String) -> Bool {
  ip.has_prefix("127.") || ip == "0:0:0:0:0:0:0:1"
}

///|
fn is_private(ip : String) -> Bool {
  if ip.has_prefix("10.") ||
    ip.has_prefix("192.168.") ||
    ip.has_prefix("169.254.") {
    return true
  }
  if ip.has_prefix("172.") {
    let parts = ip.split(".").collect()
    if parts.length() > 1 {
      let second = @string.parse_int(parts[1].to_owned()) catch { _ => -1 }
      return second >= 16 && second <= 31
    }
  }
  ip.has_prefix("fe80") || ip.has_prefix("fc") || ip.has_prefix("fd")
}

///|
fn is_fake_ip(ip : String) -> Bool {
  ip.has_prefix("198.18.") || ip.has_prefix("198.19.")
}

///|
fn route_of(ip : String, port : Int32, proxy_port : Int32) -> String {
  if is_loopback(ip) {
    if port == proxy_port {
      "PROXY-PORT"
    } else {
      "loopback"
    }
  } else if is_fake_ip(ip) {
    "TUN-fake-ip"
  } else if is_private(ip) {
    "LAN"
  } else {
    "direct"
  }
}

///|
priv struct Agg {
  mut send : Int64
  mut recv : Int64
  mut sends : Int32
  mut recvs : Int32
  ports : Map[Int32, Bool]
}

///|
fn Agg::new() -> Agg {
  { send: 0L, recv: 0L, sends: 0, recvs: 0, ports: {}, }
}

///|
fn Agg::add(self : Agg, n : NetEv) -> Unit {
  if n.send {
    self.send += n.size
    self.sends += 1
  } else {
    self.recv += n.size
    self.recvs += 1
  }
  self.ports[n.sport] = true
}

// ------------------------------------------------------------------ net

///|
fn run_net(secs : Int32, proxy_port : Int32) -> Unit {
  start_or_exit()
  let r = @etw.Reader::new()
  let by_flow : Map[String, Agg] = Map([])
  let dns_by : Map[String, Int32] = Map([])
  let mut header_mismatch = 0
  let mut net_total = 0
  let t0 = @etw.now_ms()
  while @etw.now_ms() - t0 < secs.to_double() * 1000.0 {
    @etw.sleep_ms(200)
    for e in r.drain() {
      match net_event(e) {
        Some(n) => {
          net_total += 1
          if n.pid != n.header_pid {
            header_mismatch += 1
          }
          let proto = if n.tcp { "tcp" } else { "udp" }
          let key = "\{n.pid}|\{proto}|\{n.daddr}:\{n.dport}|\{n.saddr}"
          let a = match by_flow.get(key) {
            Some(a) => a
            None => {
              let a = Agg::new()
              by_flow[key] = a
              a
            }
          }
          a.add(n)
        }
        None =>
          if e.provider == @etw.ProviderDns {
            match e.str("QueryName") {
              Some(q) => {
                let k = "\{image(e.pid)}(\{e.pid}) \{q}"
                dns_by[k] = dns_by.get(k).unwrap_or(0) + 1
              }
              None => ()
            }
          }
      }
    }
  }
  let wall = @etw.now_ms() - t0
  ignore(@etw.stop())
  let flows = by_flow.iter().collect()
  flows.sort_by((x, y) => {
    let tx = x.1.send + x.1.recv
    let ty = y.1.send + y.1.recv
    ty.compare(tx)
  })
  println(
    "---- top flows (key: PID property | proto | daddr:dport | saddr; sport set = local ports seen)",
  )
  for i, f in flows {
    if i >= 30 {
      break
    }
    let (key, a) = f
    let parts = key.split("|").collect()
    let pid = @string.parse_int(parts[0].to_owned()) catch { _ => -1 }
    let ep = parts[2].to_owned()
    let ip = match ep.rev_find(":") {
      Some(j) => ep[:j].to_owned()
      None => ep
    }
    let port = match ep.rev_find(":") {
      Some(j) => @string.parse_int(ep[j + 1:].to_owned()) catch { _ => 0 }
      None => 0
    }
    let sports = a.ports.keys().collect()
    let sport_desc = if sports.length() <= 3 {
      sports.map(p => p.to_string()).join(",")
    } else {
      "\{sports.length()} ports"
    }
    println(
      "  \{pad(image(pid), 22)} pid=\{pad(pid.to_string(), 6)} \{parts[1]} \{pad(ep, 40)} saddr \{pad(parts[3].to_owned(), 16)} \{pad(route_of(ip, port, proxy_port), 11)} send \{pad(kb(a.send), 10)}(\{a.sends}) recv \{pad(kb(a.recv), 10)}(\{a.recvs}) sport \{sport_desc}",
    )
  }
  println(
    "network byte events: \{net_total}; events whose header pid != PID property: \{header_mismatch}",
  )
  let dns = dns_by.iter().collect()
  dns.sort_by((x, y) => y.1.compare(x.1))
  println("---- DNS-Client events carrying QueryName (header pid)")
  for i, d in dns {
    if i >= 25 {
      break
    }
    println("  \{pad(d.1.to_string(), 4)} \{d.0}")
  }
  print_usage_summary(wall)
}

// ------------------------------------------------------------------ trace

///|
fn quote_arg(a : String) -> String {
  if a == "" || a.contains(" ") || a.contains("\t") || a.contains("\"") {
    "\"" + a.replace_all(old="\"", new="\\\"") + "\""
  } else {
    a
  }
}

///|
fn run_trace(
  cmd : Array[String],
  proxy_port : Int32,
  secs_after : Int32,
) -> Unit {
  start_or_exit()
  let r = @etw.Reader::new()
  // Give the real-time session time to deliver events before the command starts.
  @etw.sleep_ms(1500)
  ignore(r.drain())
  let cmdline = cmd.map(quote_arg).join(" ")
  let t0 = @etw.now_ms()
  let root = @etw.spawn(cmdline)
  if root <= 0 {
    println("spawn failed: Win32 error \{-root}")
    ignore(@etw.stop())
    return
  }
  let events : Array[@etw.Event] = []
  while @etw.child_wait(100) == 1 {
    events.append(r.drain())
  }
  let t_exit = @etw.now_ms()
  // FlushTimer is 1 s: wait for the buffers holding the tail of the run.
  @etw.sleep_ms(secs_after * 1000)
  events.append(r.drain())
  let wall = @etw.now_ms() - t0
  ignore(@etw.stop())
  println("")
  println("==== trace: \{cmdline}")
  println(
    "root pid \{root}, exit code \{@etw.child_exit_code()}, ran \{((t_exit - t0) / 10.0).round() / 100.0} s",
  )

  // 1. process tree (iterate until no new children: start events may arrive out of order)
  let tree : Map[Int32, String] = Map([])
  let parent : Map[Int32, Int32] = Map([])
  for e in events {
    if e.provider == @etw.ProviderProcess {
      match (e.int("ProcessID"), e.int("ParentProcessID")) {
        (Some(p), Some(pp)) => {
          parent[p.to_int()] = pp.to_int()
          match e.str("ImageName") {
            Some(n) => image_cache[p.to_int()] = basename(n)
            None => ()
          }
        }
        _ => ()
      }
    }
  }
  // Names come from ProcessStart events: the processes may have exited by now.
  tree[root] = image(root)
  let mut grew = true
  while grew {
    grew = false
    for p, pp in parent {
      if tree.contains(pp) && !tree.contains(p) {
        tree[p] = image(p)
        grew = true
      }
    }
  }
  println("process tree (\{tree.length()}):")
  for p, name in tree {
    let pp = parent.get(p).map(x => x.to_string()).unwrap_or("-")
    println("  pid \{pad(p.to_string(), 6)} parent \{pad(pp, 6)} \{name}")
  }

  // 2. DNS answers seen in the tree: ip -> names
  let names : Map[String, Array[String]] = Map([])
  let queries : Array[String] = []
  for e in events {
    if e.provider == @etw.ProviderDns && tree.contains(e.pid) {
      match e.str("QueryName") {
        Some(q) =>
          match e.str("QueryResults") {
            Some(res) if res != "" => {
              queries.push("  \{q} -> \{res}")
              for part in res.split(";") {
                let ip = strip_mapped(part.trim(chars=" ").to_owned())
                if ip != "" {
                  let arr = match names.get(ip) {
                    Some(a) => a
                    None => {
                      let a = []
                      names[ip] = a
                      a
                    }
                  }
                  if !arr.contains(q) {
                    arr.push(q)
                  }
                }
              }
            }
            _ => ()
          }
        None => ()
      }
    }
  }
  println("DNS answers seen for the tree (\{queries.length()}):")
  for q in queries {
    println(q)
  }

  // 3. flows of the tree, plus the peer process on loopback connections
  let flows : Map[String, Agg] = Map([])
  let loop_peers : Map[Int32, Int32] = Map([]) // local port of tree socket -> peer pid
  let tree_loop_ports : Map[Int32, Bool] = Map([])
  let nets : Array[NetEv] = []
  for e in events {
    match net_event(e) {
      Some(n) => nets.push(n)
      None => ()
    }
  }
  for n in nets {
    if tree.contains(n.pid) {
      let key = "\{if n.tcp { "tcp" } else { "udp" }}|\{n.daddr}|\{n.dport}"
      let a = match flows.get(key) {
        Some(a) => a
        None => {
          let a = Agg::new()
          flows[key] = a
          a
        }
      }
      a.add(n)
      if is_loopback(n.daddr) {
        tree_loop_ports[n.sport] = true
      }
    }
  }
  for n in nets {
    if !tree.contains(n.pid) &&
      is_loopback(n.daddr) &&
      tree_loop_ports.contains(n.dport) {
      loop_peers[n.dport] = n.pid
    }
  }
  println("flows of the tree:")
  let list = flows.iter().collect()
  list.sort_by((x, y) => (y.1.send + y.1.recv).compare(x.1.send + x.1.recv))
  let totals : Map[String, (Int64, Int64)] = Map([])
  for f in list {
    let (key, a) = f
    let parts = key.split("|").collect()
    let ip = parts[1].to_owned()
    let port = @string.parse_int(parts[2].to_owned()) catch { _ => 0 }
    let route = route_of(ip, port, proxy_port)
    let label = match names.get(ip) {
      Some(ns) => ns.join(",")
      None => ""
    }
    let (ts, tr) = totals.get(route).unwrap_or((0L, 0L))
    totals[route] = (ts + a.send, tr + a.recv)
    let ports = a.ports.keys().collect()
    let port_desc = if ports.length() <= 4 {
      " sport " + ports.map(p => p.to_string()).join(",")
    } else {
      ""
    }
    println(
      "  \{parts[0]} \{pad(ip + ":" + port.to_string(), 30)} \{pad(route, 11)} send \{pad(kb(a.send), 10)} recv \{pad(kb(a.recv), 10)} conns \{a.ports.length()}\{port_desc} \{label}",
    )
  }
  if !loop_peers.is_empty() {
    let peers : Map[Int32, Bool] = Map([])
    for _, pid in loop_peers {
      peers[pid] = true
    }
    for pid, _ in peers {
      println("loopback peer process: pid \{pid} \{image(pid)}")
      // Its non-loopback traffic in the same window (all clients of the proxy, not
      // only this command): shows what counting the core's outbound leg would add.
      let out : Map[String, Agg] = Map([])
      for n in nets {
        if n.pid == pid && !is_loopback(n.daddr) {
          let k = "\{n.daddr}:\{n.dport}"
          let a = match out.get(k) {
            Some(a) => a
            None => {
              let a = Agg::new()
              out[k] = a
              a
            }
          }
          a.add(n)
        }
      }
      let top = out.iter().collect()
      top.sort_by((x, y) => (y.1.send + y.1.recv).compare(x.1.send + x.1.recv))
      for i, t in top {
        if i >= 3 {
          break
        }
        println(
          "  peer outbound \{pad(t.0, 40)} send \{pad(kb(t.1.send), 10)} recv \{kb(t.1.recv)}",
        )
      }
    }
  }
  println("totals by route:")
  for route, t in totals {
    println("  \{pad(route, 11)} send \{kb(t.0)} recv \{kb(t.1)}")
  }
  print_usage_summary(wall)
}

// ------------------------------------------------------------------ main

///|
fn int_arg(args : Array[String], i : Int32, default : Int32) -> Int32 {
  if i < args.length() {
    @string.parse_int(args[i]) catch {
      _ => default
    }
  } else {
    default
  }
}

///|
fn main {
  let args = @env.args()
  let mode = if args.length() > 1 { args[1] } else { "env" }
  match mode {
    "env" => run_env()
    "leak" => run_leak()
    "check" => run_check()
    "schema" => run_schema(int_arg(args, 2, 10))
    "net" => run_net(int_arg(args, 2, 10), int_arg(args, 3, 7890))
    "trace" => {
      let mut proxy_port = 7890
      let mut secs_after = 3
      let mut i = 2
      while i < args.length() && args[i] != "--" {
        if args[i] == "--proxy-port" {
          proxy_port = int_arg(args, i + 1, 7890)
          i += 2
        } else if args[i] == "--secs-after" {
          secs_after = int_arg(args, i + 1, 3)
          i += 2
        } else {
          i += 1
        }
      }
      if i >= args.length() - 1 {
        println(
          "usage: probe trace [--proxy-port N] [--secs-after S] -- <command line>",
        )
        return
      }
      run_trace(args[i + 1:].to_owned(), proxy_port, secs_after)
    }
    _ => println("unknown mode \{mode}; see the header of cmd/probe/main.mbt")
  }
}
