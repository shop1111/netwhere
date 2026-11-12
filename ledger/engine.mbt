// Accounting engine (PLAN.md §4). Pure: everything it needs from the OS
// comes in as events or through the two lookup functions in EngineEnv, so
// the same code runs live and in replay tests.
//
//  1. Owner = the event's PID property (done in normalize.mbt).
//  2. Address direction (normalize.mbt).
//  3. Only the application side counts: proxy-core traffic on loopback/TUN
//     mirrors apps and is dropped; core traffic elsewhere goes to a separate
//     "core outbound" total; other loopback traffic is dropped.
//  4. Entry: loopback peer whose listener is a core -> ProxyPort; otherwise
//     the route decides: TUN adapter -> Tun; private/link-local -> Lan;
//     else Direct (reported as "bypassed the core" when a core is running).
//  5. Exit: join Mihomo by (source port, process, time window); snapshots
//     first, routed-connection log lines second; else Unknown, and a long
//     TUN flow without any match is flagged inconsistent.
//  6. Domain: Mihomo host > this process's DNS answer > any DNS answer.

///|
#derive(Eq, Hash, Debug)
pub(all) enum Entry {
  ProxyPort
  Tun
  Direct
  Lan
}

///|
pub impl Show for Entry with fn output(self, logger) {
  logger.write_string(
    match self {
      ProxyPort => "proxy-port"
      Tun => "tun"
      Direct => "direct"
      Lan => "lan"
    },
  )
}

///|
#derive(Eq, Hash, Debug)
pub(all) enum Exit {
  /// A proxy node (the outbound that carried the connection).
  Node(String)
  /// The core sent it out directly (DIRECT outbound).
  CoreDirect
  /// The core refused it (REJECT, REJECT-DROP).
  CoreReject
  /// Entered the core but no Mihomo record matched.
  Unknown
  /// Never entered a core (Direct and Lan entries).
  NotProxied
}

///|
pub impl Show for Exit with fn output(self, logger) {
  logger.write_string(
    match self {
      Node(n) => "node:" + n
      CoreDirect => "core-direct"
      CoreReject => "core-reject"
      Unknown => "unknown"
      NotProxied => "-"
    },
  )
}

///|
#derive(Eq, Hash, Debug)
pub(all) enum DomainSource {
  FromCore
  FromProcessDns
  FromAnyDns
  NoDomain
}

///|
/// Lookups the engine cannot do itself.
pub(all) struct EngineEnv {
  /// Does traffic to this address leave through a TUN adapter?
  via_tun : (@netaddr.IpAddr) -> Bool
  /// Pid of the process listening on (addr, port), if any.
  listener_pid : (@netaddr.IpAddr, Int32) -> Int32?
}

///|
/// Executable names treated as proxy cores even when not configured.
pub let known_core_names : Array[String] = [
  "mihomo.exe", "mihomo-windows-amd64.exe", "clash.exe", "clash-meta.exe", "verge-mihomo.exe",
  "verge-mihomo-alpha.exe", "flclashcore.exe", "sing-box.exe", "xray.exe", "v2ray.exe",
]

///|
/// Time window for joining a flow with a core record: 5 seconds.
pub let join_window : Int64 = 50_000_000L

///|
/// A TUN flow lasting longer than this without any core record is flagged.
pub let inconsistent_after : Int64 = 30_000_000L

///|
#derive(Eq, Hash)
priv struct FlowKey {
  pid : Int32
  proto : Proto
  sock : Endpoint
  peer : Endpoint
}

///|
priv struct Flow {
  key : FlowKey
  entry : Entry
  first : Ticks
  mut last : Ticks
  mut up : Int64
  mut down : Int64
  /// minute index -> (up, down)
  minutes : Map[Int64, (Int64, Int64)]
}

///|
/// What the core said about one connection.
priv struct CoreInfo {
  t : Ticks
  network : String
  process : String
  host : String
  /// Destination port the application asked the core for.
  port : Int32
  outbound : String
  group : String
  rule : String
  from_snapshot : Bool
}

///|
pub struct Engine {
  priv env : EngineEnv
  priv core_pids : Map[Int32, String]
  priv tun_prefixes : Array[@netaddr.Cidr]
  priv flows : Map[FlowKey, Flow]
  priv order : Array[FlowKey]
  priv images : Map[Int32, String]
  priv parents : Map[Int32, Int32]
  priv dns_by_proc : Map[(Int32, @netaddr.IpAddr), String]
  priv dns_any : Map[@netaddr.IpAddr, String]
  priv core_by_port : Map[Int32, Array[CoreInfo]]
  priv seen_core_ids : Map[String, Bool]
  mut core_out_up : Int64
  mut core_out_down : Int64
  mut dropped_mirror : Int64
  mut dropped_loopback : Int64
}

///|
pub fn Engine::new(
  env : EngineEnv,
  cores~ : Array[(Int32, String)] = [],
  tun_prefixes~ : Array[@netaddr.Cidr] = [],
) -> Engine {
  let core_pids = Map([])
  for c in cores {
    core_pids[c.0] = c.1
  }
  {
    env,
    core_pids,
    tun_prefixes,
    flows: Map([]),
    order: [],
    images: Map([]),
    parents: Map([]),
    dns_by_proc: Map([]),
    dns_any: Map([]),
    core_by_port: Map([]),
    seen_core_ids: Map([]),
    core_out_up: 0L,
    core_out_down: 0L,
    dropped_mirror: 0L,
    dropped_loopback: 0L,
  }
}

///|
/// Records the image of a process that started before observation began.
pub fn Engine::seed_process(self : Engine, pid : Int32, image : String) -> Unit {
  self.images[pid] = image
  if known_core_names.contains(base_name(image).to_lower()) {
    self.core_pids[pid] = base_name(image)
  }
}

///|
/// Records a parent link for a process that started before observation.
pub fn Engine::seed_parent(self : Engine, pid : Int32, ppid : Int32) -> Unit {
  self.parents[pid] = ppid
}

///|
pub fn Engine::is_core(self : Engine, pid : Int32) -> Bool {
  self.core_pids.contains(pid)
}

///|
pub fn Engine::core_present(self : Engine) -> Bool {
  self.core_pids.length() > 0
}

///|
pub fn Engine::on_proc_start(self : Engine, p : ProcStart) -> Unit {
  self.parents[p.pid] = p.ppid
  self.seed_process(p.pid, p.image)
}

///|
pub fn Engine::on_dns(self : Engine, a : DnsAnswer) -> Unit {
  for ip in a.addrs {
    self.dns_by_proc[(a.pid, ip)] = a.name
    self.dns_any[ip] = a.name
  }
}

///|
fn Engine::in_tun_net(self : Engine, ip : @netaddr.IpAddr) -> Bool {
  self.tun_prefixes.iter().any(p => p.contains(ip))
}

///|
pub fn Engine::on_net(self : Engine, e : NetEvent) -> Unit {
  let bytes = match e.kind {
    Send | Recv => e.size.to_int64()
    _ => 0L
  }
  let local_side = e.peer.addr.is_loopback() ||
    e.sock.addr.is_loopback() ||
    (self.in_tun_net(e.peer.addr) && self.in_tun_net(e.sock.addr))
  if self.is_core(e.pid) {
    if local_side {
      // Mirror of an application's traffic: never counted twice.
      self.dropped_mirror += bytes
    } else if e.kind == Send {
      self.core_out_up += bytes
    } else if e.kind == Recv {
      self.core_out_down += bytes
    }
    return
  }
  let key : FlowKey = {
    pid: e.pid,
    proto: e.proto,
    sock: e.sock,
    peer: e.peer,
  }
  let flow = match self.flows.get(key) {
    Some(f) => f
    None => {
      let entry = if e.peer.addr.is_loopback() {
        match (self.env.listener_pid)(e.peer.addr, e.peer.port) {
          Some(owner) if self.is_core(owner) => Some(ProxyPort)
          _ => None
        }
      } else if (self.env.via_tun)(e.peer.addr) {
        Some(Tun)
      } else if e.peer.addr.is_private() ||
        e.peer.addr.is_link_local() ||
        e.peer.addr.is_multicast() {
        Some(Lan)
      } else {
        Some(Direct)
      }
      guard entry is Some(entry) else {
        // Loopback traffic between ordinary processes.
        self.dropped_loopback += bytes
        return
      }
      let f : Flow = {
        key,
        entry,
        first: e.t,
        last: e.t,
        up: 0L,
        down: 0L,
        minutes: Map([]),
      }
      self.flows[key] = f
      self.order.push(key)
      f
    }
  }
  if e.t > flow.last {
    flow.last = e.t
  }
  if bytes == 0L {
    return
  }
  let minute = e.t / (60L * ticks_per_second)
  let (u, d) = match flow.minutes.get(minute) {
    Some(v) => v
    None => (0L, 0L)
  }
  if e.kind == Send {
    flow.up += bytes
    flow.minutes[minute] = (u + bytes, d)
  } else {
    flow.down += bytes
    flow.minutes[minute] = (u, d + bytes)
  }
}

///|
fn Engine::add_core_info(self : Engine, port : Int32, info : CoreInfo) -> Unit {
  match self.core_by_port.get(port) {
    Some(xs) => xs.push(info)
    None => self.core_by_port[port] = [info]
  }
}

///|
/// Adds the connections of one /connections snapshot taken at time t.
pub fn Engine::on_core_snapshot(
  self : Engine,
  t : Ticks,
  snap : @mihomo.Snapshot,
) -> Unit {
  for c in snap.conns {
    if self.seen_core_ids.contains(c.id) {
      continue
    }
    self.seen_core_ids[c.id] = true
    let group = match c.chains {
      [] => ""
      xs => xs[xs.length() - 1]
    }
    self.add_core_info(c.source_port, {
      t: match c.start {
        Some(s) => s
        None => t
      },
      network: c.network,
      process: c.process,
      host: c.host,
      port: c.dest_port,
      outbound: c.outbound(),
      group,
      rule: if c.rule_payload == "" {
        c.rule
      } else {
        "\{c.rule}(\{c.rule_payload})"
      },
      from_snapshot: true,
    })
  }
}

///|
/// Adds one routed-connection log line received at time t.
pub fn Engine::on_core_log(
  self : Engine,
  t : Ticks,
  l : @mihomo.ConnLog,
) -> Unit {
  self.add_core_info(l.source_port, {
    t,
    network: l.network,
    process: l.process,
    host: if @netaddr.IpAddr::parse(l.dest_host) is Some(_) {
      ""
    } else {
      l.dest_host
    },
    port: l.dest_port,
    outbound: l.outbound,
    group: l.group,
    rule: if l.rule_payload == "" {
      l.rule
    } else {
      "\{l.rule}(\{l.rule_payload})"
    },
    from_snapshot: false,
  })
}

///|
fn abs64(x : Int64) -> Int64 {
  if x < 0L {
    -x
  } else {
    x
  }
}

///|
fn Engine::process_name(self : Engine, pid : Int32) -> String {
  match self.images.get(pid) {
    Some(img) => img
    None => "pid:\{pid}"
  }
}

///|
fn Engine::core_match(self : Engine, f : Flow) -> CoreInfo? {
  guard self.core_by_port.get(f.key.sock.port) is Some(candidates) else {
    return None
  }
  let network = match f.key.proto {
    Tcp => "tcp"
    Udp => "udp"
  }
  let proc = base_name(self.process_name(f.key.pid)).to_lower()
  let mut best : CoreInfo? = None
  let mut best_score = 0L
  for c in candidates {
    if c.network != "" && c.network != network {
      continue
    }
    if c.process != "" &&
      !proc.has_prefix("pid:") &&
      c.process.to_lower() != proc {
      continue
    }
    let dt = abs64(c.t - f.first)
    if dt > join_window {
      continue
    }
    // Snapshots carry the full chain: prefer them, then the closest time.
    let penalty = if c.from_snapshot { 0L } else { join_window + 1L }
    let score = dt + penalty
    if best is None || score < best_score {
      best = Some(c)
      best_score = score
    }
  }
  best
}

///|
fn exit_of(outbound : String) -> Exit {
  match outbound.to_upper() {
    "DIRECT" => CoreDirect
    "REJECT" | "REJECT-DROP" => CoreReject
    _ => Node(outbound)
  }
}

///|
/// A flow with everything resolved, as reported by trace and stored rows.
#derive(Eq, Debug)
pub(all) struct FlowSummary {
  pid : Int32
  process : String
  proto : Proto
  sock : Endpoint
  peer : Endpoint
  entry : Entry
  exit : Exit
  group : String
  rule : String
  domain : String
  domain_source : DomainSource
  /// Port the application meant to reach: the peer port, or for flows
  /// through a proxy port the target port reported by the core.
  target_port : Int32
  first : Ticks
  last : Ticks
  up : Int64
  down : Int64
  /// Entered TUN, lasted long, and the core never reported it.
  inconsistent : Bool
}

///|
fn Engine::summarize(self : Engine, f : Flow) -> FlowSummary {
  let core = match f.entry {
    ProxyPort | Tun => self.core_match(f)
    Direct | Lan => None
  }
  let exit = match (f.entry, core) {
    (Direct, _) | (Lan, _) => NotProxied
    (_, Some(c)) => exit_of(c.outbound)
    (_, None) => Unknown
  }
  let (domain, domain_source) = match core {
    Some(c) if c.host != "" => (c.host, FromCore)
    _ =>
      match self.dns_by_proc.get((f.key.pid, f.key.peer.addr)) {
        Some(n) => (n, FromProcessDns)
        None =>
          match self.dns_any.get(f.key.peer.addr) {
            Some(n) => (n, FromAnyDns)
            None => ("", NoDomain)
          }
      }
  }
  {
    pid: f.key.pid,
    process: self.process_name(f.key.pid),
    proto: f.key.proto,
    sock: f.key.sock,
    peer: f.key.peer,
    entry: f.entry,
    exit,
    group: match core {
      Some(c) => c.group
      None => ""
    },
    rule: match core {
      Some(c) => c.rule
      None => ""
    },
    domain,
    domain_source,
    target_port: match core {
      Some(c) if c.port > 0 => c.port
      _ => f.key.peer.port
    },
    first: f.first,
    last: f.last,
    up: f.up,
    down: f.down,
    inconsistent: f.entry == Tun &&
    core is None &&
    f.last - f.first > inconsistent_after,
  }
}

///|
/// All flows in first-seen order.
pub fn Engine::flows(self : Engine) -> Array[FlowSummary] {
  self.order.map(k => self.summarize(self.flows[k]))
}

///|
/// The pid and all its descendants seen through ProcStart events.
pub fn Engine::process_tree(self : Engine, root : Int32) -> Array[Int32] {
  let out = [root]
  let mut i = 0
  while i < out.length() {
    let parent = out[i]
    for pid, ppid in self.parents {
      if ppid == parent && !out.contains(pid) && pid != parent {
        out.push(pid)
      }
    }
    i += 1
  }
  out
}

///|
/// One aggregated ledger row (PLAN.md §3, table usage).
#derive(Eq, Debug)
pub(all) struct UsageRow {
  minute : Int64
  app : String
  process : String
  domain : String
  entry : Entry
  exit : Exit
  rule : String
  up : Int64
  down : Int64
}

///|
/// Aggregates flows into per-minute rows keyed by (minute, app, process,
/// domain, entry, exit, rule). Rows are sorted by minute, then by first
/// appearance.
pub fn Engine::usage_rows(
  self : Engine,
  rules : @rules.RuleSet,
) -> Array[UsageRow] {
  let rows : Map[
    (Int64, String, String, String, Entry, Exit, String),
    (Int64, Int64),
  ] = Map([])
  let keys = []
  for f in self.flows() {
    let domain = if f.domain == "" { None } else { Some(f.domain) }
    let app = match rules.classify(f.process, domain) {
      Some(c) => c.app
      None => "Unknown"
    }
    let flow = self.flows[{
        pid: f.pid,
        proto: f.proto,
        sock: f.sock,
        peer: f.peer,
      }]
    for minute, v in flow.minutes {
      let k = (
        minute,
        app,
        base_name(f.process),
        f.domain,
        f.entry,
        f.exit,
        f.rule,
      )
      match rows.get(k) {
        Some((u, d)) => rows[k] = (u + v.0, d + v.1)
        None => {
          rows[k] = v
          keys.push(k)
        }
      }
    }
  }
  keys.sort_by((a, b) => a.0.compare(b.0))
  keys.map(k => {
    let (u, d) = rows[k]
    {
      minute: k.0,
      app: k.1,
      process: k.2,
      domain: k.3,
      entry: k.4,
      exit: k.5,
      rule: k.6,
      up: u,
      down: d,
    }
  })
}

///|
#derive(Eq, Debug)
pub(all) struct Totals {
  by_entry : Map[Entry, (Int64, Int64)]
  /// Bytes that entered a core but matched no core record.
  unknown_exit : Int64
  core_outbound_up : Int64
  core_outbound_down : Int64
  dropped_mirror : Int64
  dropped_loopback : Int64
}

///|
pub fn Engine::totals(self : Engine) -> Totals {
  let by_entry = Map([])
  let mut unknown_exit = 0L
  for f in self.flows() {
    let (u, d) = match by_entry.get(f.entry) {
      Some(v) => v
      None => (0L, 0L)
    }
    by_entry[f.entry] = (u + f.up, d + f.down)
    if f.exit == Unknown {
      unknown_exit += f.up + f.down
    }
  }
  {
    by_entry,
    unknown_exit,
    core_outbound_up: self.core_out_up,
    core_outbound_down: self.core_out_down,
    dropped_mirror: self.dropped_mirror,
    dropped_loopback: self.dropped_loopback,
  }
}
