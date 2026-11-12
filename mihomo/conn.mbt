// Decoding of the Mihomo external-controller API (pure; no I/O).
//
//   GET /connections (or its WebSocket stream): Snapshot
//   GET /logs stream:                           one LogMessage per frame
//   GET /configs:                               CoreConfig

///|
#derive(Debug)
pub(all) suberror DecodeError {
  DecodeError(String)
}

///|
pub impl Show for DecodeError with fn output(self, logger) {
  let DecodeError(msg) = self
  logger.write_string("mihomo: " + msg)
}

///|
/// One connection tracked by the core.
#derive(Eq, Debug)
pub(all) struct Conn {
  id : String
  /// "tcp" or "udp".
  network : String
  /// Inbound kind: "HTTP", "Socks5", "Mixed", "Tun", ...
  inbound_type : String
  source : @netaddr.IpAddr?
  source_port : Int32
  dest_ip : @netaddr.IpAddr?
  dest_port : Int32
  /// Requested or sniffed host name; empty when the app connected by IP.
  host : String
  process : String
  process_path : String
  upload : Int64
  download : Int64
  /// FILETIME ticks; None when "start" could not be parsed.
  start : Int64?
  /// Outbound first, outermost group last: ["HK 01", "Auto", "Proxy"].
  chains : Array[String]
  rule : String
  rule_payload : String
}

///|
/// The proxy or DIRECT/REJECT outbound that actually carried the
/// connection (first element of the chain).
pub fn Conn::outbound(self : Conn) -> String {
  match self.chains {
    [first, ..] => first
    [] => ""
  }
}

///|
#derive(Eq, Debug)
pub(all) struct Snapshot {
  download_total : Int64
  upload_total : Int64
  conns : Array[Conn]
}

///|
fn field(m : Map[String, Json], key : String) -> Json raise DecodeError {
  match m.get(key) {
    Some(v) => v
    None => raise DecodeError("missing field \"\{key}\"")
  }
}

///|
fn str_or_empty(m : Map[String, Json], key : String) -> String {
  match m.get(key) {
    Some(String(s)) => s
    _ => ""
  }
}

///|
fn int64_of(j : Json) -> Int64? {
  match j {
    Number(d, ..) => Some(d.to_int64())
    String(s) => {
      if s.length() == 0 {
        return None
      }
      let mut v = 0L
      for c in s {
        guard c is ('0'..<='9') else { return None }
        v = v * 10L + (c.to_int() - '0'.to_int()).to_int64()
      }
      Some(v)
    }
    _ => None
  }
}

///|
fn int_field(m : Map[String, Json], key : String) -> Int32 {
  match m.get(key) {
    Some(j) =>
      match int64_of(j) {
        Some(v) => v.to_int()
        None => 0
      }
    None => 0
  }
}

///|
fn int64_field(m : Map[String, Json], key : String) -> Int64 {
  match m.get(key) {
    Some(j) =>
      match int64_of(j) {
        Some(v) => v
        None => 0L
      }
    None => 0L
  }
}

///|
fn decode_conn(j : Json) -> Conn raise DecodeError {
  guard j is Object(c) else { raise DecodeError("connection is not an object") }
  guard field(c, "metadata") is Object(md) else {
    raise DecodeError("connection metadata is not an object")
  }
  let chains = match c.get("chains") {
    Some(Array(xs)) =>
      xs.filter_map(x => {
        match x {
          String(s) => Some(s)
          _ => None
        }
      })
    _ => []
  }
  // Mihomo reports the requested host in "host" and a sniffed name in
  // "sniffHost"; either may be empty.
  let host = match str_or_empty(md, "host") {
    "" => str_or_empty(md, "sniffHost")
    h => h
  }
  {
    id: str_or_empty(c, "id"),
    network: str_or_empty(md, "network"),
    inbound_type: str_or_empty(md, "type"),
    source: @netaddr.IpAddr::parse(str_or_empty(md, "sourceIP")).map(a => {
      a.unmap()
    }),
    source_port: int_field(md, "sourcePort"),
    dest_ip: @netaddr.IpAddr::parse(str_or_empty(md, "destinationIP")).map(a => {
      a.unmap()
    }),
    dest_port: int_field(md, "destinationPort"),
    host: host.to_lower(),
    process: str_or_empty(md, "process"),
    process_path: str_or_empty(md, "processPath"),
    upload: int64_field(c, "upload"),
    download: int64_field(c, "download"),
    start: parse_rfc3339(str_or_empty(c, "start")),
    chains,
    rule: str_or_empty(c, "rule"),
    rule_payload: str_or_empty(c, "rulePayload"),
  }
}

///|
/// Decodes a /connections body. "connections" may be null when the core has
/// no live connections.
pub fn decode_snapshot(j : Json) -> Snapshot raise DecodeError {
  guard j is Object(m) else { raise DecodeError("snapshot is not an object") }
  let conns = match m.get("connections") {
    Some(Array(xs)) => xs.map(decode_conn)
    Some(Null) | None => []
    _ => raise DecodeError("\"connections\" is not an array")
  }
  {
    download_total: int64_field(m, "downloadTotal"),
    upload_total: int64_field(m, "uploadTotal"),
    conns,
  }
}

///|
/// Decodes a snapshot from text (one WebSocket frame or HTTP body).
pub fn parse_snapshot(text : StringView) -> Snapshot raise DecodeError {
  let j = @json.parse(text) catch {
    e => raise DecodeError("invalid JSON: \{e}")
  }
  decode_snapshot(j)
}

///|
/// Inbound settings that tell which loopback ports and TUN prefixes belong
/// to the core.
#derive(Eq, Debug)
pub(all) struct CoreConfig {
  /// Non-zero values of port, socks-port, mixed-port, redir-port, tproxy-port.
  ports : Array[Int32]
  tun_enabled : Bool
  tun_device : String
  tun_prefixes : Array[@netaddr.Cidr]
}

///|
pub fn decode_configs(j : Json) -> CoreConfig raise DecodeError {
  guard j is Object(m) else { raise DecodeError("configs is not an object") }
  let ports = []
  for key in ["mixed-port", "port", "socks-port", "redir-port", "tproxy-port"] {
    let p = int_field(m, key)
    if p > 0 && !ports.contains(p) {
      ports.push(p)
    }
  }
  let (tun_enabled, tun_device, tun_prefixes) = match m.get("tun") {
    Some(Object(t)) => {
      let prefixes = []
      for key in ["inet4-address", "inet6-address"] {
        if t.get(key) is Some(Array(xs)) {
          for x in xs {
            if x is String(s) && @netaddr.Cidr::parse(s) is Some(c) {
              prefixes.push(c)
            }
          }
        }
      }
      (t.get("enable") is Some(True), str_or_empty(t, "device"), prefixes)
    }
    _ => (false, "", [])
  }
  { ports, tun_enabled, tun_device, tun_prefixes, }
}
