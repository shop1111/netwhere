// Diagnostic: show interfaces, the best route for each argument address, and
// loopback listeners with their owning pids. Needs no elevation.
//
//   nw-route [ip ...]

///|
fn main {
  try {
    println("interfaces:")
    for i in @route.interfaces() {
      if i.up {
        let ps = i.prefixes.map(p => p.to_string()).join(", ")
        println(
          "  #\{i.if_index} \{i.name} (\{i.description}) type=\{i.if_type}: \{ps}",
        )
      }
    }
    let args = @env.args()
    let targets = if args.length() > 1 {
      args[1:].to_owned()
    } else {
      [
        "127.0.0.1", "8.8.8.8", "2606:4700:4700::1111", "198.18.0.13", "192.168.1.1",
      ]
    }
    println("best routes:")
    for t in targets {
      match @netaddr.IpAddr::parse(t) {
        Some(ip) => {
          let r = @route.best_route(ip)
          let src = match r.source {
            Some(s) => s.to_string()
            None => "-"
          }
          println(
            "  \{t} -> #\{r.if_index} \{r.if_name} (source \{src}, prefix /\{r.prefix_len})",
          )
        }
        None => println("  \{t}: not an IP address")
      }
    }
    println("loopback / wildcard TCP listeners:")
    for l in @route.tcp_listeners() {
      if l.addr.is_loopback() || l.addr.is_unspecified() {
        println("  \{l.addr}:\{l.port} pid \{l.pid}")
      }
    }
  } catch {
    e => println("error: \{e}")
  }
}
