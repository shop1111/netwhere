///|
/// Counters for records the replay could not use.
#derive(Eq, Debug)
pub(all) struct ReplayStats {
  net_ignored : Int32
  dns_ignored : Int32
  core_frames_bad : Int32
  core_log_other : Int32
}

///|
/// Feeds a recording through a fresh engine. Route facts and listener
/// tables are gathered from the whole recording first, because the recorder
/// writes a route fact after the first event that needed it.
pub fn replay(rec : Recording) -> (Engine, ReplayStats) {
  let routes : Map[@netaddr.IpAddr, Bool] = Map([])
  let listeners : Map[(@netaddr.IpAddr, Int32), Int32] = Map([])
  for l in rec.header.listeners {
    listeners[(l.addr, l.port)] = l.pid
  }
  for r in rec.records {
    match r {
      Route(f) => routes[f.dst] = f.via_tun
      Listeners(_, items) =>
        for l in items {
          listeners[(l.addr, l.port)] = l.pid
        }
      _ => ()
    }
  }
  let tun_prefixes = []
  for t in rec.header.tun {
    for p in t.prefixes {
      tun_prefixes.push(p)
    }
  }
  let env : EngineEnv = {
    via_tun: ip => {
      match routes.get(ip) {
        Some(v) => v
        // Without a recorded fact, only addresses inside a TUN prefix (fake-ip
        // ranges) are known to enter TUN.
        None => tun_prefixes.iter().any(p => p.contains(ip))
      }
    },
    listener_pid: (ip, port) => {
      match listeners.get((ip, port)) {
        Some(pid) => Some(pid)
        None =>
          // A wildcard listener also accepts loopback connections.
          listeners.get(
            (
              if ip.is_v4() {
                @netaddr.IpAddr::v4(0, 0, 0, 0)
              } else {
                V6(0, 0)
              },
              port,
            ),
          )
      }
    },
  }
  let engine = Engine::new(
    env,
    cores=rec.header.cores.map(c => (c.pid, c.name)),
    tun_prefixes~,
  )
  for p in rec.header.procs {
    engine.seed_process(p.pid, p.image)
    engine.seed_parent(p.pid, p.ppid)
  }
  let mut net_ignored = 0
  let mut dns_ignored = 0
  let mut core_frames_bad = 0
  let mut core_log_other = 0
  for r in rec.records {
    match r {
      Net(raw) =>
        match normalize_net(raw) {
          Some(e) => engine.on_net(e)
          None => net_ignored += 1
        }
      Dns(raw) =>
        match normalize_dns(raw) {
          Some(a) => engine.on_dns(a)
          None => dns_ignored += 1
        }
      ProcStart(raw) =>
        engine.on_proc_start(normalize_proc_start(raw, rec.header.devices))
      ProcStop(_) => ()
      MihomoSnapshot(t, body) =>
        engine.on_core_snapshot(t, @mihomo.decode_snapshot(body)) catch {
          _ => core_frames_bad += 1
        }
      MihomoLog(t, line) =>
        match @mihomo.parse_conn_log(line) {
          Some(l) => engine.on_core_log(t, l)
          None => core_log_other += 1
        }
      Route(_) | Listeners(_, _) => ()
    }
  }
  (engine, { net_ignored, dns_ignored, core_frames_bad, core_log_other, })
}
