// `netwhered run`: the background collector (PLAN.md section 3).
//
// Every 200 ms: drain ETW into the engine, read the mailbox, advance
// requests. Every 5 s: heartbeat, config reload check. Every 10 s: write
// settled usage and evict idle flows. Every 15 s: refresh what the core is
// (pids, TUN adapters). Hourly: retention.

///|
priv struct RunOptions {
  data_dir : String
  secs : Int32
  decoder : @etw.Decoder
}

///|
priv struct Live {
  dir : String
  db : @store.Db
  engine : @ledger.Engine
  mut rules : @rules.RuleSet
  mut config : @config.Config
  mut config_mtime : Int64
  inbox : @mailbox.Inbox
  /// Active traces: request id -> pid whose subtree is collected.
  traces : Map[String, Int32]
  mut paused : Bool
  mut core_link : String
  mut last_error : String
  degraded : Bool
  started : Int64
  owner_sid : String
  routes : Map[@netaddr.IpAddr, (Bool, Int64)]
  tun_ifs : Array[Int32]
  listeners : Map[(@netaddr.IpAddr, Int32), Int32]
  mut listeners_at : Int64
  log : StringBuilder
}

///|
let sec : Int64 = 10_000_000L

///|
fn Live::note(self : Live, msg : String) -> Unit {
  self.log.write_string("\{@sys.now()} \{msg}\n")
}

///|
async fn Live::flush_log(self : Live) -> Unit {
  let text = self.log.to_string()
  if text.length() == 0 {
    return
  }
  self.log.reset()
  let path = self.dir + "\\netwhered.log"
  // Keep the log small: rotate once at 5 MB.
  let size = @fs.file_size(path) catch { _ => 0L }
  if size > 5_000_000L {
    @fs.rename(path, path + ".old", replace=true) catch {
      _ => ()
    }
  }
  @fs.write_file(path, text, append=true, create_mode=OpenOrCreate) catch {
    _ => ()
  }
}

///|
fn Live::refresh_listeners(self : Live, now : Int64) -> Unit {
  let ls = @route.tcp_listeners() catch { _ => return }
  self.listeners.clear()
  for l in ls {
    self.listeners[(l.addr, l.port)] = l.pid
  }
  self.listeners_at = now
}

///|
fn Live::via_tun(self : Live, ip : @netaddr.IpAddr) -> Bool {
  if self.tun_ifs.length() == 0 {
    return false
  }
  let now = @sys.now()
  match self.routes.get(ip) {
    Some((v, at)) if now - at < 30L * sec => v
    _ => {
      let v = match (Ok(@route.best_route(ip)) catch { e => Err(e) }) {
        Ok(r) => self.tun_ifs.contains(r.if_index)
        Err(_) => false
      }
      if self.routes.length() > 50_000 {
        self.routes.clear()
      }
      self.routes[ip] = (v, now)
      v
    }
  }
}

///|
fn Live::listener_pid(
  self : Live,
  ip : @netaddr.IpAddr,
  port : Int32,
) -> Int32? {
  let wildcard = if ip.is_v4() {
    @netaddr.IpAddr::v4(0, 0, 0, 0)
  } else {
    @netaddr.IpAddr::V6(0, 0)
  }
  let find = fn() {
    match self.listeners.get((ip, port)) {
      Some(p) => Some(p)
      None => self.listeners.get((wildcard, port))
    }
  }
  match find() {
    Some(p) => Some(p)
    None => {
      // A listener that appeared since the last refresh: refresh at most
      // once a second.
      let now = @sys.now()
      if now - self.listeners_at > sec {
        self.refresh_listeners(now)
        find()
      } else {
        None
      }
    }
  }
}

///|
async fn read_text(path : String) -> String? {
  if !@fs.exists(path) {
    return None
  }
  Some(@fs.read_file(path).text()) catch {
    _ => None
  }
}

///|
/// Built-in rules ship as builtin-rules.txt in the data directory.
async fn load_rules(
  dir : String,
  config : @config.Config,
) -> (@rules.RuleSet, Int32) {
  let set = @rules.RuleSet::new()
  let n = match read_text(dir + "\\builtin-rules.txt") {
    Some(text) => @rules.load_builtin(set, text) catch { _ => 0 }
    None => 0
  }
  config.apply_rules(set)
  (set, n)
}

///|
/// Reloads config.json when its modification time changed.
async fn Live::check_config(self : Live) -> Unit {
  let path = self.dir + "\\config.json"
  let mtime = if @fs.exists(path) {
    (@fs.mtime(path) catch { _ => (0L, 0) }).0
  } else {
    0L
  }
  if mtime == self.config_mtime {
    return
  }
  self.config_mtime = mtime
  let text = read_text(path).unwrap_or("")
  match (Ok(@config.parse(text)) catch { e => Err(e) }) {
    Ok(c) => {
      self.config = c
      let (set, n) = load_rules(self.dir, c)
      self.rules = set
      self.note(
        "config loaded: \{c.rules.length()} user rules, \{n} built-in patterns",
      )
    }
    Err(e) => {
      // Keep the previous configuration.
      self.last_error = e.to_string()
      self.note(e.to_string())
    }
  }
}

///|
fn Live::checks(self : Live) -> @mailbox.Checks {
  {
    client_problem: pid => {
      match @sys.process_user_sid(pid) {
        None => Some("client process not found")
        Some(sid) if sid != self.owner_sid =>
          Some("client belongs to another user")
        Some(_) =>
          match @sys.process_elevated(pid) {
            Some(false) => None
            Some(true) => Some("client process is elevated")
            None => Some("client process cannot be inspected")
          }
      }
    },
    parent_of: pid => {
      match self.engine.parent_of(pid) {
        Some(p) => Some(p)
        None =>
          // Unelevated runs see no process events; fall back to a snapshot.
          @sys.process_list()
          .iter()
          .find_first(e => e.pid == pid)
          .map(e => e.ppid)
      }
    },
  }
}

///|
fn Live::trace_pids(self : Live) -> Array[Int32] {
  let out = []
  for _, scope in self.traces {
    for p in self.engine.process_tree(scope) {
      out.push(p)
    }
  }
  out
}

///|
fn Live::request_row(self : Live, id : String) -> @store.RequestRow? {
  guard self.inbox.requests.get(id) is Some(r) else { return None }
  Some({
    id: r.id,
    kind: match r.kind {
      Trace => "trace"
      Pause => "pause"
      Resume => "resume"
    },
    client_pid: r.client_pid,
    root_pid: r.root_pid,
    state: @mailbox.state_name(r.state),
    reason: r.reason,
    created: r.created,
    updated: r.updated,
  })
}

///|
fn Live::apply_effects(self : Live, fx : Array[@mailbox.Effect]) -> Unit {
  // Results first, then states: a client that sees "complete" can read them.
  for e in fx {
    match e {
      Track(id, pid) => self.traces[id] = pid
      Narrow(id, root) => {
        self.traces[id] = root
        // The root is still suspended: its image can always be read now,
        // even when no process-start event will arrive (degraded mode).
        if self.engine.image_of(root) is None &&
          @sys.process_name(root) is Some(image) {
          self.engine.seed_process(root, image)
        }
      }
      Finish(id) => {
        let req = self.inbox.requests.get(id)
        match (self.traces.get(id), req) {
          (Some(scope), Some(r)) if r.state == Complete && r.root_pid > 0 => {
            let tree = self.engine.process_tree(scope)
            let procs = tree.map(p => {
              (
                p,
                self.engine.parent_of(p).unwrap_or(0),
                self.engine.image_of(p).unwrap_or(""),
              )
            })
            let flows = self.engine.flows_of(tree)
            self.db.put_trace(id, procs, flows, self.engine.core_present()) catch {
              err => self.note("trace \{id}: \{err}")
            }
          }
          _ => ()
        }
        self.traces.remove(id)
      }
      Pause => {
        self.paused = true
        self.note("paused")
      }
      Resume => {
        self.paused = false
        self.note("resumed")
      }
      Changed(_) => ()
    }
  }
  for e in fx {
    if e is Changed(id) && self.request_row(id) is Some(row) {
      self.db.put_request(row) catch {
        err => self.note("request \{id}: \{err}")
      }
    }
  }
}

///|
/// Reads and deletes every message file, oldest name first.
async fn Live::read_mailbox(self : Live) -> Unit {
  let dir = self.dir + "\\requests"
  let names = @fs.readdir(dir, sort=true) catch { _ => return }
  let now = @sys.now()
  for name in names {
    guard name.has_suffix(".json") else { continue }
    let path = dir + "\\" + name
    let size = @fs.file_size(path) catch { _ => 0L }
    let text = if size > @mailbox.max_message_bytes.to_int64() {
      ""
    } else {
      read_text(path).unwrap_or("")
    }
    @fs.remove(path, allow_missing=true) catch {
      _ => ()
    }
    match (Ok(@mailbox.parse_message(text)) catch { e => Err(e) }) {
      Ok(m) => self.apply_effects(self.inbox.apply(m, now, self.checks()))
      Err(@mailbox.MessageError(why)) =>
        self.note("mailbox: ignored \{name}: \{why}")
    }
  }
  self.apply_effects(self.inbox.tick(now, self.checks()))
}

///|
fn Live::feed(
  self : Live,
  events : Array[@etw.LiveEvent],
  devices : @ledger.DeviceMap,
) -> Unit {
  for ev in events {
    match ev {
      NetE(e) => if !self.paused { self.engine.on_net(e) }
      OtherE(Dns(raw)) =>
        if @ledger.normalize_dns(raw) is Some(a) {
          self.engine.on_dns(a)
        }
      OtherE(ProcStart(raw)) =>
        self.engine.on_proc_start(@ledger.normalize_proc_start(raw, devices))
      _ => ()
    }
  }
}

///|
fn Live::write_usage(self : Live, now : Int64, settle : Int64) -> Unit {
  let rows = self.engine.take_usage(self.rules, now, settle~)
  self.db.add_usage(rows, self.engine.core_present()) catch {
    e => {
      self.last_error = e.to_string()
      self.note(e.to_string())
    }
  }
}

///|
fn Live::heartbeat(self : Live, state : String) -> Unit {
  let s = @etw.stats()
  self.db.write_heartbeat({
    pid: @sys.current_pid(),
    started: self.started,
    updated: @sys.now(),
    state,
    degraded: self.degraded,
    core_link: self.core_link,
    last_error: self.last_error,
    events: s.events,
    dropped: s.dropped,
    flows: self.engine.flow_count(),
    private_bytes: @sys.self_usage().private_bytes,
  }) catch {
    e => self.note(e.to_string())
  }
}

///|
/// Refreshes which processes are cores and which adapters are TUN.
async fn Live::refresh_core(self : Live, ctl : @client.Controller) -> Unit {
  let config = match (Ok(ctl.configs()) catch { e => Err(e) }) {
    Ok(c) => Some(c)
    Err(_) => None
  }
  let now = @sys.now()
  self.refresh_listeners(now)
  let ls = self.listeners
    .iter()
    .map(kv => @route.TcpListener::{ addr: kv.0.0, port: kv.0.1, pid: kv.1, })
    .collect()
  for pid in core_listener_pids(config, ls) {
    if !self.engine.is_core(pid) {
      let name = match @sys.process_name(pid) {
        Some(n) => @ledger.base_name(n)
        None => "pid:\{pid}"
      }
      self.engine.set_core(pid, name)
      self.note("core: \{name} (\{pid})")
    }
  }
  let tun = find_tun(config).map(i => i.if_index)
  if tun != self.tun_ifs {
    self.tun_ifs.clear()
    for i in tun {
      self.tun_ifs.push(i)
    }
    self.routes.clear()
    self.note("tun adapters: " + tun.map(i => i.to_string()).join(", "))
  }
}

///|
async fn run_collector(opts : RunOptions) -> Int32 {
  let dir = opts.data_dir
  @fs.mkdir(dir + "\\requests", recursive=true, allow_exist=true) catch {
    e => {
      println("run: cannot create \{dir}: \{e}")
      return 2
    }
  }
  let db_path = dir + "\\ledger.db"
  // One collector at a time: a fresh heartbeat from another live process
  // means it is running, and starting would stop its ETW session.
  if @fs.exists(db_path) {
    let peek = Ok(@store.Db::open_reader(db_path)) catch { e => Err(e) }
    if peek is Ok(r) {
      let hb = r.heartbeat() catch { _ => None }
      r.close()
      match hb {
        Some(h) if h.state != "stopped" &&
          @sys.now() - h.updated < 15L * sec &&
          h.pid != @sys.current_pid() &&
          @sys.process_create_time(h.pid) is Some(_) => {
          println("run: a collector is already running (pid \{h.pid})")
          return 3
        }
        _ => ()
      }
    }
  }
  let db = @store.Db::open_writer(db_path) catch {
    e => {
      println("run: \{e}")
      return 2
    }
  }
  let elevated = @sys.is_elevated()
  let providers = if elevated {
    @etw.all_providers
  } else {
    @etw.unelevated_providers
  }
  let owner_sid = match read_text(dir + "\\owner.sid") {
    Some(s) if s.trim().length() > 0 => s.trim().to_owned()
    _ => @sys.current_user_sid()
  }
  let routes = Map([])
  let tun_ifs = []
  let listeners = Map([])
  // The engine's lookups go through the caches in `live`, which is created
  // right after; the cell breaks the cycle.
  let cell : Ref[Live?] = Ref(None)
  let engine = @ledger.Engine::new({
    via_tun: ip => {
      match cell.val {
        Some(l) => l.via_tun(ip)
        None => false
      }
    },
    listener_pid: (ip, port) => {
      match cell.val {
        Some(l) => l.listener_pid(ip, port)
        None => None
      }
    },
  })
  let live : Live = {
    dir,
    db,
    engine,
    rules: @rules.RuleSet::new(),
    config: @config.default(),
    config_mtime: -1L,
    inbox: @mailbox.Inbox::new(),
    traces: Map([]),
    paused: false,
    core_link: "not connected",
    last_error: "",
    degraded: !elevated,
    started: @sys.now(),
    owner_sid,
    routes,
    tun_ifs,
    listeners,
    listeners_at: 0L,
    log: StringBuilder(),
  }
  cell.val = Some(live)
  live.note(
    "netwhered starting (pid \{@sys.current_pid()}, elevated \{elevated}, data \{dir})",
  )
  // Processes already running: names and parents.
  for e in @sys.process_list() {
    engine.seed_parent(e.pid, e.ppid)
    engine.seed_process(e.pid, @sys.image_path(e.pid).unwrap_or(e.exe))
  }
  live.check_config()
  let devices = @ledger.DeviceMap::new(@route.dos_devices() catch { _ => [] })
  @etw.start("netwhere", providers~, decoder=opts.decoder) catch {
    e => {
      live.note("etw: \{e}")
      live.last_error = e.to_string()
      println("run: \{e}")
      live.heartbeat("stopped")
      live.flush_log()
      db.close()
      return 2
    }
  }
  if !elevated {
    live.note("degraded: not elevated, collecting DNS-Client and Mihomo only")
  }
  let reader = @etw.Reader::new()
  let ctl = @client.Controller::new(
    addr=live.config.controller,
    secret=live.config.secret,
  )
  live.refresh_core(ctl)
  let begun = @sys.now()
  let body = async fn() {
    @async.with_task_group(group => {
      group.spawn_bg(no_wait=true, () => {
        ctl.watch_connections(
          1000,
          text => {
            match (Ok(@mihomo.parse_snapshot(text)) catch { e => Err(e) }) {
              Ok(s) => engine.on_core_snapshot(@sys.now(), s)
              Err(_) => ()
            }
          },
          on_state=s => {
            live.core_link = match s {
              Connected => "connected"
              Disconnected(m) => "disconnected: " + m
            }
          },
        )
      })
      group.spawn_bg(no_wait=true, () => {
        ctl.watch_logs(text => {
          match (Ok(@mihomo.parse_log_message(text)) catch { e => Err(e) }) {
            Ok(m) =>
              if @mihomo.parse_conn_log(m.payload) is Some(l) {
                engine.on_core_log(@sys.now(), l)
              }
            Err(_) => ()
          }
        })
      })
      let mut last_hb = 0L
      let mut last_usage = @sys.now()
      let mut last_core = @sys.now()
      let mut last_prune = 0L
      live.heartbeat("running")
      for ;; {
        @async.sleep(200)
        live.feed(reader.drain_live(), devices)
        live.read_mailbox()
        let now = @sys.now()
        if now - last_usage >= 10L * sec {
          live.write_usage(now, @ledger.join_window)
          let protect = live.trace_pids()
          ignore(
            engine.evict_idle(now, 120L * sec, protect=p => protect.contains(p)),
          )
          last_usage = now
        }
        if now - last_hb >= 5L * sec {
          live.heartbeat(if live.paused { "paused" } else { "running" })
          live.check_config()
          live.flush_log()
          last_hb = now
        }
        if now - last_core >= 15L * sec {
          live.refresh_core(ctl)
          last_core = now
        }
        if now - last_prune >= 3600L * sec {
          let keep_minutes = live.config.retention_days.to_int64() * 24L * 60L
          let minute_now = now / @store.ticks_per_minute
          try {
            db.prune_usage(minute_now - keep_minutes)
            db.prune_requests(now - 24L * 3600L * sec)
          } catch {
            e => live.note(e.to_string())
          }
          live.inbox.forget(now, 3600L * sec)
          last_prune = now
        }
        if opts.secs > 0 && now - begun > opts.secs.to_int64() * sec {
          break
        }
      }
    })
  }
  let finished = @async.handle_cancellation(body)
  // Shutdown: deliver the ETW tail, write everything still pending.
  @async.sleep(1200)
  live.feed(reader.drain_live(), devices)
  @etw.stop()
  live.feed(reader.drain_live(), devices)
  live.write_usage(9_000_000_000_000_000_000L, 0L)
  live.heartbeat("stopped")
  live.note(if finished is None { "stopped (signal)" } else { "stopped" })
  live.flush_log()
  db.close()
  0
}
