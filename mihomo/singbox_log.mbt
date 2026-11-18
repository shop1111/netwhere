// sing-box's Clash API /logs stream. Unlike Mihomo, sing-box spreads one
// connection over several info lines that share a "[id duration]" prefix
// (log/format.go FormatSimple), for example:
//
//   [3392193542 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:51234
//   [3392193542 0ms] inbound/mixed[mixed-in]: inbound connection to example.com:443
//   [3392193542 2ms] outbound/vless[hk-01]: outbound connection to example.com:443
//
// UDP uses "inbound packet connection ..." and "outbound packet connection
// [to ...]". Lines are joined by id; the outbound line completes the record.
// The rule is only logged at debug level and the process never, so both
// stay empty: the join then relies on the source port and the time window.

///|
priv struct Partial {
  mut network : String
  mut source : @netaddr.IpAddr?
  mut source_port : Int32
  mut dest_host : String
  mut dest_port : Int32
}

///|
/// Turns /logs payloads (Mihomo or sing-box) into routed-connection records.
/// Keeps a little state for sing-box's multi-line connections.
pub struct ConnLogParser {
  priv pending : Map[String, Partial]
  priv order : Array[String]
}

///|
/// Pending sing-box connections kept at most (oldest dropped first).
let max_pending : Int32 = 4096

///|
pub fn ConnLogParser::new() -> ConnLogParser {
  { pending: Map([]), order: [], }
}

///|
/// One /logs payload: a ConnLog when it completes a routed connection.
pub fn ConnLogParser::feed(
  self : ConnLogParser,
  payload : StringView,
) -> ConnLog? {
  match parse_conn_log(payload) {
    Some(l) => Some(l)
    None => self.feed_singbox(payload)
  }
}

///|
/// A sing-box line split into (id, kind, type, tag, message), where kind is
/// "inbound" or "outbound": "[id dur] kind/type[tag]: message".
fn split_singbox(
  payload : StringView,
) -> (String, String, String, String, StringView)? {
  guard payload.has_prefix("[") else { return None }
  guard payload.find("] ") is Some(close) else { return None }
  let head = payload[1:close]
  guard head.find(" ") is Some(sp) else { return None }
  let id = head[:sp]
  guard id.length() > 0 && id.iter().all(c => c is ('0'..<='9')) else {
    return None
  }
  let rest = payload[close + 2:]
  guard rest.find("/") is Some(slash) else { return None }
  let kind = rest[:slash]
  guard kind == "inbound" || kind == "outbound" else { return None }
  let after = rest[slash + 1:]
  guard after.find("[") is Some(open) else { return None }
  guard after.find("]: ") is Some(end) && end > open else { return None }
  Some(
    (
      id.to_owned(),
      kind.to_owned(),
      after[:open].to_owned(),
      after[open + 1:end].to_owned(),
      after[end + 3:],
    ),
  )
}

///|
/// Is this payload part of a routed connection (worth recording)?
pub fn is_conn_log_line(payload : StringView) -> Bool {
  if parse_conn_log(payload) is Some(_) {
    return true
  }
  match split_singbox(payload) {
    Some((_, _, _, _, msg)) =>
      msg.contains("inbound connection ") ||
      msg.contains("inbound packet connection") ||
      msg.has_prefix("outbound connection to ") ||
      msg.has_prefix("outbound packet connection")
    None => false
  }
}

///|
fn ConnLogParser::partial(self : ConnLogParser, id : String) -> Partial {
  match self.pending.get(id) {
    Some(p) => p
    None => {
      let p : Partial = {
        network: "tcp",
        source: None,
        source_port: 0,
        dest_host: "",
        dest_port: 0,
      }
      self.pending[id] = p
      self.order.push(id)
      if self.order.length() > max_pending {
        let old = self.order.remove(0)
        self.pending.remove(old)
      }
      p
    }
  }
}

///|
fn ConnLogParser::forget(self : ConnLogParser, id : String) -> Unit {
  self.pending.remove(id)
  match self.order.search(id) {
    Some(i) => ignore(self.order.remove(i))
    None => ()
  }
}

///|
fn ConnLogParser::feed_singbox(
  self : ConnLogParser,
  payload : StringView,
) -> ConnLog? {
  guard split_singbox(payload) is Some((id, kind, typ, tag, msg)) else {
    return None
  }
  let msg = match msg.find("] ") {
    // "[user] inbound connection to ..." (authenticated inbounds)
    Some(i) if msg.has_prefix("[") => msg[i + 2:]
    _ => msg
  }
  if kind == "inbound" {
    let (udp, rest) = if msg.strip_prefix("inbound connection ") is Some(r) {
      (false, r)
    } else if msg.strip_prefix("inbound packet connection ") is Some(r) {
      (true, r)
    } else if msg.strip_prefix("inbound redirect connection ") is Some(r) {
      (false, r)
    } else {
      return None
    }
    let p = self.partial(id)
    if udp {
      p.network = "udp"
    }
    if rest.strip_prefix("from ") is Some(src) {
      if split_host_port(src) is Some((h, port)) &&
        @netaddr.IpAddr::parse(h) is Some(a) {
        p.source = Some(a.unmap())
        p.source_port = port
      }
    } else if rest.strip_prefix("to ") is Some(dst) {
      if split_host_port(dst) is Some((h, port)) {
        p.dest_host = h.to_lower().to_owned()
        p.dest_port = port
      }
    }
    return None
  }
  // Outbound: the route is decided, the record is complete.
  let (udp, dst) = if msg.strip_prefix("outbound connection to ") is Some(d) {
    (false, Some(d))
  } else if msg.strip_prefix("outbound packet connection to ") is Some(d) {
    (true, Some(d))
  } else if msg.has_prefix("outbound packet connection") {
    (true, None)
  } else {
    return None
  }
  guard self.pending.get(id) is Some(p) else { return None }
  self.forget(id)
  guard p.source is Some(source) && p.source_port > 0 else { return None }
  let (host, port) = match dst.bind(d => split_host_port(d)) {
    Some((h, port)) if p.dest_host == "" => (h.to_lower().to_owned(), port)
    _ => (p.dest_host, p.dest_port)
  }
  Some({
    network: if udp {
      "udp"
    } else {
      p.network
    },
    source,
    source_port: p.source_port,
    process: "",
    dest_host: host,
    dest_port: port,
    rule: "",
    rule_payload: "",
    group: "",
    outbound: tag,
    outbound_type: typ,
  })
}
