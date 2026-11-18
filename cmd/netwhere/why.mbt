// `trace`'s explanation of bypassing connections: gathers what the
// diagnosis needs (the command's proxy variables, the system proxy, git's
// proxy, TUN state, current routes) and prints the candidate causes, then
// what the trace may have missed. All of this runs unprivileged.

///|
let inet_settings : String = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

///|
/// git's global config files, in the order git reads them.
fn git_config_paths() -> Array[String] {
  let out = []
  match @sys.getenv("GIT_CONFIG_GLOBAL") {
    Some(p) => out.push(p)
    None => {
      match @sys.getenv("XDG_CONFIG_HOME") {
        Some(x) => out.push(x + "\\git\\config")
        None =>
          match @sys.getenv("USERPROFILE") {
            Some(h) => out.push(h + "\\.config\\git\\config")
            None => ()
          }
      }
      match @sys.getenv("USERPROFILE") {
        Some(h) => out.push(h + "\\.gitconfig")
        None => ()
      }
    }
  }
  out
}

///|
async fn git_proxy() -> String {
  let mut found = ""
  for p in git_config_paths() {
    let text = @fs.read_file(p).text() catch { _ => continue }
    let v = @diagnose.git_config_proxy(text)
    if v != "" {
      // Later files override earlier ones.
      found = v
    }
  }
  found
}

///|
/// The TUN adapters of the core, per its /configs (same rule as the
/// collector: device name or an address inside a configured TUN prefix).
async fn tun_adapters(
  controller : @client.Controller,
) -> Array[@route.Interface] {
  let config = @async.with_timeout_opt(2000, () => controller.configs()) catch {
    _ => None
  }
  guard config is Some(c) && c.tun_enabled else { return [] }
  let ifs = @route.interfaces() catch { _ => [] }
  ifs.filter(i => {
    let by_name = c.tun_device != "" && i.name == c.tun_device
    let by_prefix = i.prefixes
      .iter()
      .any(p => c.tun_prefixes.iter().any(t => t.contains(p.addr)))
    i.up && (by_name || by_prefix)
  })
}

///|
/// What the diagnosis needs to know about this machine and this terminal.
/// The command inherited this process's environment, so its variables are
/// the ones read here.
async fn diag_context(
  controller : @client.Controller,
  flows : Array[@store.TraceFlow],
) -> @diagnose.Context {
  let env : Array[(String, String)] = []
  for
    name in [
      "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
      "all_proxy", "no_proxy",
    ] {
    match @sys.getenv(name) {
      // Windows variables are case-insensitive: keep the first spelling.
      Some(v) if !env.iter().any(kv => kv.0.to_upper() == name.to_upper()) =>
        env.push((name, v))
      _ => ()
    }
  }
  let tun = tun_adapters(controller)
  {
    system_proxy: @sys.reg_user_value(inet_settings, "ProxyEnable") == Some("1"),
    system_proxy_server: @sys.reg_user_value(inet_settings, "ProxyServer").unwrap_or(
      "",
    ),
    system_proxy_override: @sys.reg_user_value(inet_settings, "ProxyOverride").unwrap_or(
      "",
    ),
    env,
    git_proxy: git_proxy(),
    // A flow that entered TUN proves it is on even if /configs failed.
    tun_enabled: tun.length() > 0 || flows.iter().any(f => f.entry == "tun"),
    tun_has_v6: tun
    .iter()
    .any(i => {
      i.prefixes.iter().any(p => !p.addr.is_v4() && !p.addr.is_link_local())
    }),
    route_if: ip => {
      let r = @route.best_route(ip) catch { _ => return None }
      Some(r.if_name)
    },
  }
}

///|
/// "1.2.3.4:443" or "[2001:db8::1]:443".
fn parse_peer(s : String) -> (@netaddr.IpAddr, Int32)? {
  guard s.rev_find(":") is Some(i) else { return None }
  let host = s[:i].to_owned()
  let host = if host.has_prefix("[") && host.has_suffix("]") {
    host[1:host.length() - 1].to_owned()
  } else {
    host
  }
  let mut port = 0
  for c in s[i + 1:] {
    guard c >= '0' && c <= '9' && port < 65536 else { return None }
    port = port * 10 + (c.to_int() - '0'.to_int())
  }
  match @netaddr.IpAddr::parse(host) {
    Some(a) => Some((a, port))
    None => None
  }
}

///|
fn facts_of(f : @store.TraceFlow) -> @diagnose.FlowFacts? {
  guard parse_peer(f.peer) is Some((addr, _)) else { return None }
  Some({
    process: @ledger.base_name(f.process),
    proto: f.proto,
    peer: addr,
    port: f.target_port,
    domain: f.domain,
    entry: f.entry,
    bound_off_tun: f.bound_off_tun,
  })
}

///|
/// The "why" section: each distinct cause once, with the destinations it
/// explains. Empty when nothing bypassed the core.
fn why_text(flows : Array[@store.TraceFlow], ctx : @diagnose.Context) -> String {
  let facts = flows.filter_map(facts_of)
  let causes : Array[@diagnose.Cause] = []
  let dests : Map[String, Array[String]] = Map([])
  for f in facts {
    let same = facts.filter(o => o.process == f.process)
    for c in @diagnose.diagnose(f, same, ctx) {
      let key = @diagnose.cause_text(c)
      if !dests.contains(key) {
        causes.push(c)
        dests[key] = []
      }
      let addr = if f.peer.is_v4() { "\{f.peer}" } else { "[\{f.peer}]" }
      let d = if f.domain == "" {
        "\{f.process} \{f.proto} \{addr}:\{f.port}"
      } else {
        "\{f.process} \{f.proto} \{f.domain}:\{f.port}"
      }
      if !dests[key].contains(d) {
        dests[key].push(d)
      }
    }
  }
  if causes.length() == 0 {
    return ""
  }
  let buf = StringBuilder()
  buf.write_string(
    "why it bypassed the core (candidate causes; \"likely\" depends on what the program does internally):\n",
  )
  for c in causes {
    let key = @diagnose.cause_text(c)
    buf.write_string(key)
    buf.write_string("      applies to: \{dests[key].join(", ")}\n")
  }
  buf.to_string()
}

///|
/// What a trace may have missed: Mihomo stream outages and lost events in
/// the minutes it spans. Empty when nothing is known to be missing.
fn trace_gaps_text(rows : Array[@report.Coverage]) -> String {
  let mut core = 0L
  let mut link = 0L
  let mut lost = 0L
  let mut dropped = 0L
  for r in rows {
    core += r.core_ticks
    link += r.link_ticks
    lost += r.etw_lost
    dropped += r.dropped
  }
  let buf = StringBuilder()
  if link < core {
    buf.write_string(
      "  Mihomo connection stream was down for \{@report.human_duration(core - link)} around this trace: exits shown as ? may be connections the core did carry\n",
    )
  }
  if lost > 0L || dropped > 0L {
    buf.write_string(
      "  \{lost} events lost by ETW and \{dropped} by the collector queue around this trace: byte counts are a lower bound\n",
    )
  }
  buf.to_string()
}

///|
/// Footnotes for the marks in the exit column, when any is used.
fn marks_text(flows : Array[@store.TraceFlow]) -> String {
  let buf = StringBuilder()
  if flows.iter().any(f => f.match_kind == "ambiguous") {
    buf.write_string(
      "~ exit ambiguous: several core records matched this connection and named different outbounds; the closest one is shown\n",
    )
  }
  if flows.iter().any(f => f.inconsistent) {
    buf.write_string(
      "! entered TUN but the proxy core never reported the connection\n",
    )
  }
  if flows.iter().any(f => f.exit_kind == "unknown") {
    buf.write_string(
      "? entered the core but no core record matched (source port, process, 5 s window)\n",
    )
  }
  buf.to_string()
}
