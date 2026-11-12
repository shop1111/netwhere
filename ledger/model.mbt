// Normalized events: what the accounting engine consumes.
//
// Raw ETW fields are converted here once (see normalize.mbt) so that the
// rules learned in the M0 probe live in one tested place:
//   * the owning process is the event's PID property, not the header pid;
//   * TCP events: saddr/sport is the local socket (sock), daddr/dport the peer;
//   * UDP receive events record the packet direction, so daddr is the local side.

///|
/// Time in FILETIME ticks (100 ns since 1601-01-01 UTC).
pub type Ticks = Int64

///|
pub let ticks_per_second : Int64 = 10_000_000L

///|
#derive(Eq, Hash, Debug)
pub(all) enum Proto {
  Tcp
  Udp
}

///|
pub impl Show for Proto with fn output(self, logger) {
  logger.write_string(
    match self {
      Tcp => "tcp"
      Udp => "udp"
    },
  )
}

///|
#derive(Eq, Hash, Debug)
pub(all) enum NetKind {
  Send
  Recv
  Connect
  Accept
  Disconnect
  Retransmit
  Reconnect
}

///|
#derive(Eq, Hash, Compare, Debug)
pub(all) struct Endpoint {
  addr : @netaddr.IpAddr
  port : Int32
}

///|
pub impl Show for Endpoint with fn output(self, logger) {
  if self.addr.is_v4() {
    logger.write_string("\{self.addr}:\{self.port}")
  } else {
    logger.write_string("[\{self.addr}]:\{self.port}")
  }
}

///|
/// One Kernel-Network event, owned by `pid`, seen from its local socket (sock).
#derive(Eq, Debug)
pub(all) struct NetEvent {
  t : Ticks
  pid : Int32
  proto : Proto
  kind : NetKind
  sock : Endpoint
  peer : Endpoint
  size : Int32
}

///|
#derive(Eq, Debug)
pub(all) struct ProcStart {
  t : Ticks
  pid : Int32
  ppid : Int32
  /// Process creation time; (pid, create_time) identifies a process even
  /// when the pid is reused.
  create_time : Ticks
  /// Drive-letter path when the device could be mapped, else the raw path.
  image : String
}

///|
#derive(Eq, Debug)
pub(all) struct ProcStop {
  t : Ticks
  pid : Int32
  create_time : Ticks
  exit_code : Int32
}

///|
/// A successful DNS answer attributed to the process that asked.
#derive(Eq, Debug)
pub(all) struct DnsAnswer {
  t : Ticks
  pid : Int32
  name : String
  cnames : Array[String]
  addrs : Array[@netaddr.IpAddr]
}

///|
/// Last path component of a Windows path ("C:\\x\\curl.exe" -> "curl.exe").
pub fn base_name(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[i + 1:].to_owned()
    None =>
      match path.rev_find("/") {
        Some(i) => path[i + 1:].to_owned()
        None => path
      }
  }
}
