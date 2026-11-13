// `netwhered record`: write a recording (ledger NDJSON v1) of the decoded
// ETW events, Mihomo snapshots and connection log lines, route facts for
// every new peer, and the listener table. Recordings feed the replay tests.

///|
priv struct RecordOptions {
  out : String
  secs : Int32
  controller : String
  secret : String
  decoder : @etw.Decoder
  snapshot_ms : Int32
  note : String
  /// Recording stops once this file exists ("" = not used).
  stop_file : String
  /// Created once the ETW session runs ("" = not used).
  ready_file : String
}

///|
priv struct Recorder {
  t0 : Int64
  mut buf : StringBuilder
  tun_ifs : Array[Int32]
  routed : Map[@netaddr.IpAddr, Bool]
  counts : Map[String, Int32]
  mut core_link : String
}

///|
fn Recorder::emit(self : Recorder, r : @ledger.Record) -> Unit {
  self.buf.write_string(r.to_line(self.t0))
  self.buf.write_char('\n')
  let k = match r {
    Net(_) => "net"
    Dns(_) => "dns"
    ProcStart(_) => "pstart"
    ProcStop(_) => "pstop"
    MihomoSnapshot(_, _) => "msnap"
    MihomoLog(_, _) => "mlog"
    Route(_) => "route"
    Listeners(_, _) => "listen"
  }
  self.counts[k] = self.counts.get_or_default(k, 0) + 1
}

///|
async fn Recorder::flush(self : Recorder, file : @fs.File) -> Unit {
  let text = self.buf.to_string()
  if text.length() > 0 {
    self.buf = StringBuilder()
    file.write(text)
  }
}

///|
/// Adds a route fact the first time a non-loopback peer is seen.
fn Recorder::route_fact(self : Recorder, raw : @ledger.RawNet) -> Unit {
  guard @ledger.normalize_net(raw) is Some(e) else { return }
  let peer = e.peer.addr
  if peer.is_loopback() || peer.is_unspecified() || self.routed.contains(peer) {
    return
  }
  self.routed[peer] = true
  match (Ok(@route.best_route(peer)) catch { e => Err(e) }) {
    Ok(r) =>
      self.emit(
        Route({
          t: e.t,
          dst: peer,
          if_index: r.if_index,
          if_name: r.if_name,
          via_tun: self.tun_ifs.contains(r.if_index),
        }),
      )
    Err(_) =>
      self.counts["route_error"] = self.counts.get_or_default("route_error", 0) +
        1
  }
}

///|
/// Loopback and wildcard TCP listeners (the ones that can be a core's
/// inbound port).
fn local_listeners() -> Array[@ledger.Listener] {
  let ls = @route.tcp_listeners() catch { _ => [] }
  ls
  .filter(l => l.addr.is_loopback() || l.addr.is_unspecified())
  .map(l => @ledger.Listener::{ addr: l.addr, port: l.port, pid: l.pid, })
}

///|
/// Builds the header: device map, proxy cores, TUN adapters, listeners.
async fn build_header(
  opts : RecordOptions,
  t0 : Int64,
) -> (@ledger.Header, Array[Int32], String) {
  let devices = @ledger.DeviceMap::new(@route.dos_devices() catch { _ => [] })
  let listeners = local_listeners()
  let ctl = @client.Controller::new(addr=opts.controller, secret=opts.secret)
  let (config, core_note) = match (Ok(ctl.configs()) catch { e => Err(e) }) {
    Ok(c) => (Some(c), "mihomo reachable at \{opts.controller}")
    Err(e) => (None, "mihomo unreachable at \{opts.controller}: \{e}")
  }
  // Cores: owners of the configured inbound ports, plus any listener whose
  // image is a known core executable.
  let snapshot = @sys.process_list()
  let procs : Array[@ledger.ProcInfo] = snapshot.map(e => {
    pid: e.pid,
    ppid: e.ppid,
    image: match @sys.image_path(e.pid) {
      Some(p) => p
      None => e.exe
    },
  })
  let name_of = fn(pid : Int32) {
    match procs.search_by(p => p.pid == pid) {
      Some(i) => procs[i].image
      None => "pid:\{pid}"
    }
  }
  let cores : Array[@ledger.CoreProc] = []
  let add_core = fn(pid : Int32) {
    if cores.iter().any(c => c.pid == pid) {
      return
    }
    cores.push({ pid, name: @ledger.base_name(name_of(pid)), })
  }
  for l in listeners {
    let by_port = match config {
      Some(c) => c.ports.contains(l.port)
      None => false
    }
    let by_name = @ledger.known_core_names.contains(
      @ledger.base_name(name_of(l.pid)).to_lower(),
    )
    if by_port || by_name {
      add_core(l.pid)
    }
  }
  // TUN adapters: by configured device name or by configured prefix.
  let tun : Array[@ledger.TunInfo] = []
  match config {
    Some(c) if c.tun_enabled => {
      let ifs = @route.interfaces() catch { _ => [] }
      for i in ifs {
        let by_name = c.tun_device != "" && i.name == c.tun_device
        let by_prefix = i.prefixes
          .iter()
          .any(p => c.tun_prefixes.iter().any(t => t.contains(p.addr)))
        if i.up && (by_name || by_prefix) {
          tun.push({
            if_index: i.if_index,
            if_name: i.name,
            prefixes: i.prefixes,
          })
        }
      }
    }
    _ => ()
  }
  let header : @ledger.Header = {
    version: @ledger.record_version,
    t0,
    note: opts.note,
    devices,
    cores,
    tun,
    listeners,
    procs,
    controller: opts.controller,
  }
  (header, tun.map(t => t.if_index), core_note)
}

///|
async fn record(opts : RecordOptions) -> Int32 {
  let elevated = @sys.is_elevated()
  let providers = if elevated {
    @etw.all_providers
  } else {
    println(
      "warning: not elevated; Kernel-Network and Kernel-Process need admin rights. Recording DNS-Client and Mihomo only.",
    )
    @etw.unelevated_providers
  }
  let t0 = @sys.now()
  let (header, tun_ifs, core_note) = build_header(opts, t0)
  println(core_note)
  println("cores: " + header.cores.map(c => "\{c.name}(\{c.pid})").join(", "))
  println(
    "tun adapters: " +
    header.tun.map(t => "\{t.if_name}#\{t.if_index}").join(", "),
  )
  let file = @fs.create(opts.out, allow_existing=false)
  defer file.close()
  file.write(header.to_line() + "\n")
  let rec : Recorder = {
    t0,
    buf: StringBuilder(),
    tun_ifs,
    routed: Map([]),
    counts: Map([]),
    core_link: "not connected",
  }
  @etw.start("netwhere-record", providers~, decoder=opts.decoder) catch {
    e => {
      println("error: \{e}")
      return 2
    }
  }
  if opts.ready_file != "" {
    @fs.write_file(opts.ready_file, "ready")
  }
  let reader = @etw.Reader::new()
  let ctl = @client.Controller::new(addr=opts.controller, secret=opts.secret)
  let drain = fn() {
    for r in reader.drain() {
      if r is Net(raw) {
        rec.route_fact(raw)
      }
      rec.emit(r)
    }
  }
  let started = @sys.now()
  let run = async fn() {
    @async.with_task_group(group => {
      group.spawn_bg(no_wait=true, () => {
        ctl.watch_connections(
          opts.snapshot_ms,
          text => {
            match (Ok(@json.parse(text)) catch { e => Err(e) }) {
              Ok(j) => rec.emit(MihomoSnapshot(@sys.now(), j))
              Err(_) =>
                rec.counts["msnap_bad"] = rec.counts.get_or_default(
                    "msnap_bad", 0,
                  ) +
                  1
            }
          },
          on_state=s => {
            rec.core_link = match s {
              Connected => "connected"
              Disconnected(m) => "disconnected: " + m
            }
          },
        )
      })
      group.spawn_bg(no_wait=true, () => {
        ctl.watch_logs(text => {
          match (Ok(@mihomo.parse_log_message(text)) catch { e => Err(e) }) {
            // Only routed-connection lines are kept; other log lines may carry
            // unrelated information.
            Ok(m) =>
              if @mihomo.parse_conn_log(m.payload) is Some(_) {
                rec.emit(MihomoLog(@sys.now(), m.payload))
              }
            Err(_) => ()
          }
        })
      })
      let mut last_listeners = @sys.now()
      for ;; {
        @async.sleep(200)
        drain()
        let now = @sys.now()
        if now - last_listeners > 5L * @ledger.ticks_per_second {
          rec.emit(Listeners(now, local_listeners()))
          last_listeners = now
        }
        rec.flush(file)
        if opts.secs > 0 &&
          now - started > opts.secs.to_int64() * @ledger.ticks_per_second {
          break
        }
        if opts.stop_file != "" && @fs.exists(opts.stop_file) {
          break
        }
      }
    })
  }
  let finished = @async.handle_cancellation(run)
  // Give ETW one flush period to deliver the tail, then stop.
  @async.sleep(1200)
  drain()
  let loss = @etw.session_loss()
  @etw.stop()
  drain()
  rec.flush(file)
  let stats = @etw.stats()
  println(if finished is None { "stopped by Ctrl+C" } else { "finished" })
  println("wrote \{opts.out}")
  let keys = rec.counts.keys().collect()
  keys.sort()
  println("records: " + keys.map(k => "\{k}=\{rec.counts[k]}").join(" "))
  println("mihomo link: \{rec.core_link}")
  let per_event = if stats.events > 0L {
    stats.callback_ns / stats.events
  } else {
    0L
  }
  println(
    "etw: events=\{stats.events} net=\{stats.net} dns=\{stats.dns} process=\{stats.process} skipped=\{stats.skipped} dropped=\{stats.dropped} decode_fail=\{stats.decode_fail} stale_sessions=\{stats.stale_sessions}",
  )
  println(
    "etw decoding (\{@debug.to_string(opts.decoder)}): \{per_event} ns/event, fast_fields=\{stats.fast_fields} slow_fields=\{stats.slow_fields} shadow_checked=\{stats.shadow_checked} shadow_mismatch=\{stats.shadow_mismatch}",
  )
  match loss {
    Some(l) =>
      println(
        "etw session: events_lost=\{l.events_lost} realtime_buffers_lost=\{l.realtime_buffers_lost}",
      )
    None => ()
  }
  if stats.shadow_mismatch > 0L || stats.dropped > 0L || stats.decode_fail > 0L {
    1
  } else {
    0
  }
}
