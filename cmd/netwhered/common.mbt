// Helpers shared by `record` and `run`.

///|
/// TUN adapters of the core (see @route.find_tun).
fn find_tun(config : @mihomo.CoreConfig?) -> Array[@route.Interface] {
  let ifs = @route.interfaces() catch { _ => [] }
  @route.find_tun(config, ifs, @route.internet_route_if())
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
