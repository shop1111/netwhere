// Mihomo /logs stream: each frame is {"type":"info","payload":"..."}.
//
// At info level the core logs one line per connection when it is routed
// (tunnel.go), in one of these shapes:
//
//   [TCP] 127.0.0.1:63010(curl.exe) --> www.baidu.com:443 match DomainSuffix(baidu.com) using Group[Node]
//   [TCP] 127.0.0.1:63010(curl.exe) --> 1.2.3.4:443 match Match using Node
//   [UDP] 198.18.0.1:5353 --> x.test:53 using GLOBAL
//   [TCP] 127.0.0.1:1(app.exe, uid=0) --> x.test:443 doesn't match any rule using DIRECT
//
// A chain prints as its single element, or as "Last[First]": outermost
// group, then the outbound in brackets. These lines are the fallback for
// connections that start and end between two /connections snapshots.

///|
#derive(Eq, Debug)
pub(all) struct LogMessage {
  level : String
  payload : String
}

///|
pub fn decode_log_message(j : Json) -> LogMessage raise DecodeError {
  guard j is Object(m) else { raise DecodeError("log frame is not an object") }
  { level: str_or_empty(m, "type"), payload: str_or_empty(m, "payload"), }
}

///|
pub fn parse_log_message(text : StringView) -> LogMessage raise DecodeError {
  let j = @json.parse(text) catch {
    e => raise DecodeError("invalid JSON: \{e}")
  }
  decode_log_message(j)
}

///|
/// One routed-connection log line.
#derive(Eq, Debug)
pub(all) struct ConnLog {
  network : String
  source : @netaddr.IpAddr
  source_port : Int32
  process : String
  dest_host : String
  dest_port : Int32
  /// Rule type ("DomainSuffix", "Match", ...); "" for GLOBAL/DIRECT modes
  /// and when no rule matched.
  rule : String
  rule_payload : String
  /// Outermost group, or the outbound itself when the chain has one element.
  group : String
  /// The outbound that carried the connection (node, DIRECT, REJECT, ...).
  outbound : String
  /// Protocol of that outbound when the log says it (sing-box: "direct",
  /// "vless", ...); "" for Mihomo, whose DIRECT/REJECT are fixed names.
  outbound_type : String
}

///|
/// Splits "host:port" or "[v6]:port" at the last colon.
fn split_host_port(s : StringView) -> (StringView, Int32)? {
  guard s.rev_find(":") is Some(i) else { return None }
  let host = s[:i]
  let port_text = s[i + 1:]
  if port_text.length() == 0 || port_text.length() > 5 {
    return None
  }
  let mut port = 0
  for c in port_text {
    guard c is ('0'..<='9') else { return None }
    port = port * 10 + (c.to_int() - '0'.to_int())
  }
  let host = if host.has_prefix("[") && host.has_suffix("]") {
    host[1:host.length() - 1]
  } else {
    host
  }
  Some((host, port))
}

///|
/// "Group[Node]" -> ("Group", "Node"); "DIRECT" -> ("DIRECT", "DIRECT").
/// Splits at the first '[' so node names that contain brackets
/// ("Proxy[[SS] HK 01]") survive; a group name containing '[' would be
/// misread, which is why snapshots are preferred over logs.
pub fn split_chain(s : StringView) -> (String, String) {
  if s.has_suffix("]") {
    match s.find("[") {
      Some(i) if i > 0 => {
        let group = s[:i].to_owned()
        let outbound = s[i + 1:s.length() - 1].to_owned()
        return (group, outbound)
      }
      _ => ()
    }
  }
  (s.to_owned(), s.to_owned())
}

///|
/// Parses a routed-connection log payload; other log lines yield None.
pub fn parse_conn_log(payload : StringView) -> ConnLog? {
  guard payload.has_prefix("[") else { return None }
  guard payload.find("] ") is Some(close) else { return None }
  let network = payload[1:close].to_lower()
  if network != "tcp" && network != "udp" {
    return None
  }
  let rest = payload[close + 2:]
  guard rest.find(" --> ") is Some(arrow) else { return None }
  let src = rest[:arrow]
  let after = rest[arrow + 5:]
  // Source: "addr:port" optionally followed by "(process[, uid=N])".
  let (src_addr, process) = match src.find("(") {
    Some(p) if src.has_suffix(")") => {
      let inner = src[p + 1:src.length() - 1]
      let name = match inner.find(", uid=") {
        Some(u) => inner[:u]
        None => if inner.has_prefix("uid=") { inner[0:0] } else { inner }
      }
      (src[:p], name.to_owned())
    }
    _ => (src, "")
  }
  guard split_host_port(src_addr) is Some((sh, sp)) else { return None }
  guard @netaddr.IpAddr::parse(sh) is Some(source) else { return None }
  guard after.find(" ") is Some(sp2) else { return None }
  guard split_host_port(after[:sp2]) is Some((dh, dp)) else { return None }
  let tail = after[sp2 + 1:]
  let (rule_text, chain) = if tail.strip_prefix("match ") is Some(m) {
    guard m.rev_find(" using ") is Some(u) else { return None }
    (m[:u], m[u + 7:])
  } else if tail.strip_prefix("using ") is Some(c) {
    (tail[0:0], c)
  } else if tail.strip_prefix("doesn't match any rule using ") is Some(c) {
    (tail[0:0], c)
  } else {
    return None
  }
  let (rule, rule_payload) = match rule_text.find("(") {
    Some(p) if rule_text.has_suffix(")") =>
      (
        rule_text[:p].to_owned(),
        rule_text[p + 1:rule_text.length() - 1].to_owned(),
      )
    _ => (rule_text.to_owned(), "")
  }
  let (group, outbound) = split_chain(chain)
  Some({
    network: network.to_owned(),
    source: source.unmap(),
    source_port: sp,
    process,
    dest_host: dh.to_lower().to_owned(),
    dest_port: dp,
    rule,
    rule_payload,
    group,
    outbound,
    outbound_type: "",
  })
}
