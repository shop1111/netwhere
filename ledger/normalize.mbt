// Raw event shapes (as decoded from ETW and as stored in recordings) and
// their conversion into the normalized model.

///|
/// Microsoft-Windows-Kernel-Network event as decoded, before normalization.
/// `pid` is the event's PID property.
#derive(Eq, Debug)
pub(all) struct RawNet {
  t : Ticks
  id : Int32
  pid : Int32
  size : Int32
  saddr : String
  sport : Int32
  daddr : String
  dport : Int32
}

///|
/// Microsoft-Windows-DNS-Client query-completed event. Event 3008 carries
/// the asking process in the header pid; the v2 dnscache events (3020) carry
/// it in ClientPID.
#derive(Eq, Debug)
pub(all) struct RawDns {
  t : Ticks
  id : Int32
  header_pid : Int32
  client_pid : Int32?
  name : String
  status : Int32
  results : String
}

///|
/// Microsoft-Windows-Kernel-Process ProcessStart (1) with the image still
/// in NT device form ("\\Device\\HarddiskVolume3\\Windows\\curl.exe").
#derive(Eq, Debug)
pub(all) struct RawProcStart {
  t : Ticks
  pid : Int32
  ppid : Int32
  create_time : Ticks
  image : String
}

///|
/// Kernel-Network event ids: (protocol, kind, IPv6?). Ids not listed here
/// (copy, failure, UDP connection-less events) carry no accounting value.
fn net_id(id : Int32) -> (Proto, NetKind)? {
  match id {
    10 | 26 => Some((Tcp, Send))
    11 | 27 => Some((Tcp, Recv))
    12 | 28 => Some((Tcp, Connect))
    13 | 29 => Some((Tcp, Disconnect))
    14 | 30 => Some((Tcp, Retransmit))
    15 | 31 => Some((Tcp, Accept))
    16 | 32 => Some((Tcp, Reconnect))
    42 | 58 => Some((Udp, Send))
    43 | 59 => Some((Udp, Recv))
    _ => None
  }
}

///|
/// Converts a raw Kernel-Network event. Returns None for event ids without
/// accounting value and for unparseable addresses.
pub fn normalize_net(raw : RawNet) -> NetEvent? {
  guard @netaddr.IpAddr::parse(raw.saddr) is Some(s) else { return None }
  guard @netaddr.IpAddr::parse(raw.daddr) is Some(d) else { return None }
  net_event(raw.t, raw.id, raw.pid, raw.size, s, raw.sport, d, raw.dport)
}

///|
/// The normalization rules on already-parsed addresses; the collector's
/// live path calls this directly and skips the text round trip.
pub fn net_event(
  t : Ticks,
  id : Int32,
  pid : Int32,
  size : Int32,
  saddr : @netaddr.IpAddr,
  sport : Int32,
  daddr : @netaddr.IpAddr,
  dport : Int32,
) -> NetEvent? {
  guard net_id(id) is Some((proto, kind)) else { return None }
  let src = { addr: saddr.unmap(), port: sport, }
  let dst = { addr: daddr.unmap(), port: dport, }
  // UDP receive is recorded in packet direction: the packet's destination is
  // this machine. Every TCP event is already written from the local side.
  let (sock, peer) = if proto == Udp && kind == Recv {
    (dst, src)
  } else {
    (src, dst)
  }
  Some({ t, pid, proto, kind, sock, peer, size, })
}

///|
/// Splits a DNS-Client QueryResults string such as
/// "type: 5 a.example.net;type: 5 b.example.net;48.200.63.27;" into CNAME
/// targets and addresses. Unknown record types are skipped.
pub fn parse_query_results(
  results : String,
) -> (Array[String], Array[@netaddr.IpAddr]) {
  let cnames = []
  let addrs = []
  for part in results.split(";") {
    let part = part.trim()
    if part.length() == 0 {
      continue
    }
    match part.strip_prefix("type:") {
      Some(rest) => {
        let rest = rest.trim()
        match rest.strip_prefix("5 ") {
          Some(name) => cnames.push(name.trim().to_owned())
          None => ()
        }
      }
      None =>
        match @netaddr.IpAddr::parse(part) {
          Some(a) => addrs.push(a.unmap())
          None => ()
        }
    }
  }
  (cnames, addrs)
}

///|
/// Converts a DNS completion event into an answer for the asking process.
/// Failed queries and answers without addresses yield None.
pub fn normalize_dns(raw : RawDns) -> DnsAnswer? {
  if raw.status != 0 {
    return None
  }
  let (cnames, addrs) = parse_query_results(raw.results)
  if addrs.length() == 0 {
    return None
  }
  let pid = match raw.client_pid {
    Some(p) => p
    None => raw.header_pid
  }
  Some({ t: raw.t, pid, name: raw.name.to_lower(), cnames, addrs, })
}

///|
/// Maps NT device prefixes to drive letters, e.g.
/// "\\Device\\HarddiskVolume3" -> "C:". Built from QueryDosDevice at record
/// time and stored in the recording header.
#derive(Eq, Debug)
pub(all) struct DeviceMap {
  entries : Array[(String, String)]
}

///|
pub fn DeviceMap::new(entries : Array[(String, String)]) -> DeviceMap {
  { entries, }
}

///|
/// Converts an NT path to a drive-letter path when a device prefix matches
/// (case-insensitively, at a path-component boundary). "\\??\\C:\\x" style
/// paths lose their prefix. Unmatched paths are returned unchanged.
pub fn DeviceMap::to_dos_path(self : DeviceMap, path : String) -> String {
  match path.strip_prefix("\\??\\") {
    Some(rest) => return rest.to_owned()
    None => ()
  }
  let lower = path.to_lower()
  for entry in self.entries {
    let (device, drive) = entry
    let dev = device.to_lower()
    if lower.has_prefix(dev) {
      let rest = path[device.length():]
      if rest.length() == 0 || rest.has_prefix("\\") {
        return drive + rest.to_owned()
      }
    }
  }
  path
}

///|
pub fn normalize_proc_start(
  raw : RawProcStart,
  devices : DeviceMap,
) -> ProcStart {
  {
    t: raw.t,
    pid: raw.pid,
    ppid: raw.ppid,
    create_time: raw.create_time,
    image: devices.to_dos_path(raw.image),
  }
}
