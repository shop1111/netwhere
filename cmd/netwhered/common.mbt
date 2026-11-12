// Helpers shared by `record` and `run`.

///|
/// TUN adapters per the core's /configs: matched by device name or by an
/// address inside a configured TUN prefix.
fn find_tun(config : @mihomo.CoreConfig?) -> Array[@route.Interface] {
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
/// Pids listening on the core's configured inbound ports.
fn core_listener_pids(
  config : @mihomo.CoreConfig?,
  ls : Array[@route.TcpListener],
) -> Array[Int32] {
  guard config is Some(c) else { return [] }
  let out = []
  for l in ls {
    if (l.addr.is_loopback() || l.addr.is_unspecified()) &&
      c.ports.contains(l.port) &&
      !out.contains(l.pid) {
      out.push(l.pid)
    }
  }
  out
}

///|
/// Default data directory: %ProgramData%\netwhere.
fn default_data_dir() -> String {
  match @sys.getenv("ProgramData") {
    Some(p) => p + "\\netwhere"
    None => "C:\\ProgramData\\netwhere"
  }
}
