// Recording format v1 (NDJSON).
//
// Line 1 is the header; every further line is one record. Times are written
// as tick offsets from the header's t0, because absolute FILETIME values
// exceed 2^53 and would lose precision as JSON numbers; absolute 64-bit
// values that are not offsets (process create times, t0) are strings.
//
// Records keep the raw shapes (RawNet, RawDns, RawProcStart, raw Mihomo JSON
// and log lines) so that replay tests also exercise normalization and the
// Mihomo decoders.

///|
pub let record_version : Int32 = 1

///|
/// A process that is a proxy core (its loopback/TUN traffic mirrors apps).
#derive(Eq, Debug)
pub(all) struct CoreProc {
  pid : Int32
  name : String
}

///|
/// A TCP listening socket and its owning process (GetExtendedTcpTable).
#derive(Eq, Debug)
pub(all) struct Listener {
  addr : @netaddr.IpAddr
  port : Int32
  pid : Int32
}

///|
/// A TUN adapter and the prefixes assigned to it.
#derive(Eq, Debug)
pub(all) struct TunInfo {
  if_index : Int32
  if_name : String
  prefixes : Array[@netaddr.Cidr]
}

///|
/// Result of a GetBestRoute2 lookup for one destination.
#derive(Eq, Debug)
pub(all) struct RouteFact {
  t : Ticks
  dst : @netaddr.IpAddr
  if_index : Int32
  if_name : String
  via_tun : Bool
}

///|
/// A process already running when the recording started.
#derive(Eq, Debug)
pub(all) struct ProcInfo {
  pid : Int32
  ppid : Int32
  /// Full image path when it could be read, else the executable name.
  image : String
}

///|
#derive(Eq, Debug)
pub(all) struct Header {
  version : Int32
  t0 : Ticks
  note : String
  devices : DeviceMap
  cores : Array[CoreProc]
  tun : Array[TunInfo]
  listeners : Array[Listener]
  /// Optional in the file; missing means no snapshot was taken.
  procs : Array[ProcInfo]
}

///|
#derive(Eq, Debug)
pub(all) enum Record {
  Net(RawNet)
  Dns(RawDns)
  ProcStart(RawProcStart)
  ProcStop(ProcStop)
  MihomoSnapshot(Ticks, Json)
  MihomoLog(Ticks, String)
  Route(RouteFact)
  Listeners(Ticks, Array[Listener])
}

///|
#derive(Debug)
pub(all) struct Recording {
  header : Header
  records : Array[Record]
}

///|
#derive(Debug)
pub(all) suberror RecordError {
  RecordError(line~ : Int32, msg~ : String)
}

///|
pub impl Show for RecordError with fn output(self, logger) {
  let RecordError(line~, msg~) = self
  logger.write_string("recording line \{line}: \{msg}")
}

// ---------------------------------------------------------------- encoding

///|
fn num(x : Int32) -> Json {
  Json::number(x.to_double())
}

///|
fn num64(x : Int64) -> Json {
  Json::number(x.to_double())
}

///|
fn obj(pairs : Array[(String, Json)]) -> Json {
  let m = Map([])
  for p in pairs {
    m[p.0] = p.1
  }
  Json::object(m)
}

///|
fn listener_json(l : Listener) -> Json {
  obj([
    ("addr", Json::string(l.addr.to_text())),
    ("port", num(l.port)),
    ("pid", num(l.pid)),
  ])
}

///|
pub fn Header::to_line(self : Header) -> String {
  obj([
    ("k", Json::string("hdr")),
    ("v", num(self.version)),
    ("t0", Json::string(self.t0.to_string())),
    ("note", Json::string(self.note)),
    (
      "devices",
      Json::array(
        self.devices.entries.map(e => {
          Json::array([Json::string(e.0), Json::string(e.1)])
        }),
      ),
    ),
    (
      "cores",
      Json::array(
        self.cores.map(c => {
          obj([("pid", num(c.pid)), ("name", Json::string(c.name))])
        }),
      ),
    ),
    (
      "tun",
      Json::array(
        self.tun.map(t => {
          obj([
            ("if", num(t.if_index)),
            ("ifname", Json::string(t.if_name)),
            (
              "prefixes",
              Json::array(t.prefixes.map(p => Json::string(p.to_string()))),
            ),
          ])
        }),
      ),
    ),
    ("listeners", Json::array(self.listeners.map(listener_json))),
    (
      "procs",
      Json::array(
        self.procs.map(p => {
          Json::array([num(p.pid), num(p.ppid), Json::string(p.image)])
        }),
      ),
    ),
  ]).stringify()
}

///|
pub fn Record::to_line(self : Record, t0 : Ticks) -> String {
  let off = fn(t : Ticks) { num64(t - t0) }
  let j = match self {
    Net(r) =>
      obj([
        ("k", Json::string("net")),
        ("t", off(r.t)),
        ("id", num(r.id)),
        ("pid", num(r.pid)),
        ("size", num(r.size)),
        ("sa", Json::string(r.saddr)),
        ("sp", num(r.sport)),
        ("da", Json::string(r.daddr)),
        ("dp", num(r.dport)),
      ])
    Dns(r) => {
      let pairs = [
        ("k", Json::string("dns")),
        ("t", off(r.t)),
        ("id", num(r.id)),
        ("hpid", num(r.header_pid)),
        ("name", Json::string(r.name)),
        ("status", num(r.status)),
        ("res", Json::string(r.results)),
      ]
      if r.client_pid is Some(c) {
        pairs.push(("cpid", num(c)))
      }
      obj(pairs)
    }
    ProcStart(r) =>
      obj([
        ("k", Json::string("pstart")),
        ("t", off(r.t)),
        ("pid", num(r.pid)),
        ("ppid", num(r.ppid)),
        ("ctime", Json::string(r.create_time.to_string())),
        ("image", Json::string(r.image)),
      ])
    ProcStop(r) =>
      obj([
        ("k", Json::string("pstop")),
        ("t", off(r.t)),
        ("pid", num(r.pid)),
        ("ctime", Json::string(r.create_time.to_string())),
        ("code", num(r.exit_code)),
      ])
    MihomoSnapshot(t, body) =>
      obj([("k", Json::string("msnap")), ("t", off(t)), ("body", body)])
    MihomoLog(t, line) =>
      obj([
        ("k", Json::string("mlog")),
        ("t", off(t)),
        ("line", Json::string(line)),
      ])
    Route(r) =>
      obj([
        ("k", Json::string("route")),
        ("t", off(r.t)),
        ("dst", Json::string(r.dst.to_text())),
        ("if", num(r.if_index)),
        ("ifname", Json::string(r.if_name)),
        ("tun", Json::boolean(r.via_tun)),
      ])
    Listeners(t, items) =>
      obj([
        ("k", Json::string("listen")),
        ("t", off(t)),
        ("items", Json::array(items.map(listener_json))),
      ])
  }
  j.stringify()
}

///|
pub fn Recording::to_text(self : Recording) -> String {
  let buf = StringBuilder()
  buf.write_string(self.header.to_line())
  buf.write_char('\n')
  for r in self.records {
    buf.write_string(r.to_line(self.header.t0))
    buf.write_char('\n')
  }
  buf.to_string()
}

// ---------------------------------------------------------------- decoding

///|
priv struct Fields {
  line : Int32
  map : Map[String, Json]
}

///|
fn Fields::fail(self : Fields, msg : String) -> RecordError {
  RecordError(line=self.line, msg~)
}

///|
fn Fields::get(self : Fields, key : String) -> Json raise RecordError {
  match self.map.get(key) {
    Some(v) => v
    None => raise self.fail("missing field \"\{key}\"")
  }
}

///|
fn Fields::int(self : Fields, key : String) -> Int32 raise RecordError {
  match self.get(key) {
    Number(d, ..) if d == d.floor() && d.abs() < 2147483648.0 => d.to_int()
    _ => raise self.fail("field \"\{key}\" is not an integer")
  }
}

///|
fn Fields::off(
  self : Fields,
  key : String,
  t0 : Ticks,
) -> Ticks raise RecordError {
  match self.get(key) {
    Number(d, ..) if d == d.floor() => t0 + d.to_int64()
    _ => raise self.fail("field \"\{key}\" is not a tick offset")
  }
}

///|
fn Fields::str(self : Fields, key : String) -> String raise RecordError {
  match self.get(key) {
    String(s) => s
    _ => raise self.fail("field \"\{key}\" is not a string")
  }
}

///|
fn Fields::int64_str(self : Fields, key : String) -> Int64 raise RecordError {
  let s = self.str(key)
  let mut v = 0L
  let mut neg = false
  for i, c in s {
    if i == 0 && c == '-' {
      neg = true
      continue
    }
    guard c is ('0'..<='9') else {
      raise self.fail("field \"\{key}\" is not a decimal integer")
    }
    v = v * 10L + (c.to_int() - '0'.to_int()).to_int64()
  }
  if s.length() == 0 || (neg && s.length() == 1) {
    raise self.fail("field \"\{key}\" is empty")
  }
  if neg {
    -v
  } else {
    v
  }
}

///|
fn Fields::bool(self : Fields, key : String) -> Bool raise RecordError {
  match self.get(key) {
    True => true
    False => false
    _ => raise self.fail("field \"\{key}\" is not a boolean")
  }
}

///|
fn Fields::array(self : Fields, key : String) -> Array[Json] raise RecordError {
  match self.get(key) {
    Array(a) => a
    _ => raise self.fail("field \"\{key}\" is not an array")
  }
}

///|
fn Fields::sub(self : Fields, j : Json) -> Fields raise RecordError {
  match j {
    Object(map) => { line: self.line, map, }
    _ => raise self.fail("expected an object")
  }
}

///|
fn Fields::ip(self : Fields, key : String) -> @netaddr.IpAddr raise RecordError {
  let s = self.str(key)
  match @netaddr.IpAddr::parse(s) {
    Some(a) => a
    None => raise self.fail("field \"\{key}\" is not an IP address: \{s}")
  }
}

///|
fn Fields::listener(self : Fields, j : Json) -> Listener raise RecordError {
  let f = self.sub(j)
  { addr: f.ip("addr"), port: f.int("port"), pid: f.int("pid"), }
}

///|
fn parse_object(text : StringView, line : Int32) -> Fields raise RecordError {
  let j = @json.parse(text) catch {
    e => raise RecordError(line~, msg="invalid JSON: \{e}")
  }
  match j {
    Object(map) => { line, map, }
    _ => raise RecordError(line~, msg="expected a JSON object")
  }
}

///|
fn parse_header(f : Fields) -> Header raise RecordError {
  if f.str("k") != "hdr" {
    raise f.fail("first line must be the header")
  }
  let version = f.int("v")
  if version != record_version {
    raise f.fail("unsupported recording version \{version}")
  }
  let devices = []
  for d in f.array("devices") {
    match d {
      [String(dev), String(drive)] => devices.push((dev, drive))
      _ => raise f.fail("devices entries are [device, drive] pairs")
    }
  }
  let cores = []
  for c in f.array("cores") {
    let c = f.sub(c)
    cores.push({ pid: c.int("pid"), name: c.str("name"), })
  }
  let tun = []
  for t in f.array("tun") {
    let t = f.sub(t)
    let prefixes = []
    for p in t.array("prefixes") {
      match p {
        String(s) =>
          match @netaddr.Cidr::parse(s) {
            Some(c) => prefixes.push(c)
            None => raise f.fail("bad TUN prefix \{s}")
          }
        _ => raise f.fail("TUN prefixes are strings")
      }
    }
    tun.push({ if_index: t.int("if"), if_name: t.str("ifname"), prefixes, })
  }
  let listeners = []
  for l in f.array("listeners") {
    listeners.push(f.listener(l))
  }
  let procs = []
  if f.map.contains("procs") {
    for p in f.array("procs") {
      match p {
        [Number(pid, ..), Number(ppid, ..), String(image)] =>
          procs.push({ pid: pid.to_int(), ppid: ppid.to_int(), image, })
        _ => raise f.fail("procs entries are [pid, ppid, image]")
      }
    }
  }
  {
    version,
    t0: f.int64_str("t0"),
    note: f.str("note"),
    devices: DeviceMap::new(devices),
    cores,
    tun,
    listeners,
    procs,
  }
}

///|
fn parse_record(f : Fields, t0 : Ticks) -> Record raise RecordError {
  match f.str("k") {
    "net" =>
      Net({
        t: f.off("t", t0),
        id: f.int("id"),
        pid: f.int("pid"),
        size: f.int("size"),
        saddr: f.str("sa"),
        sport: f.int("sp"),
        daddr: f.str("da"),
        dport: f.int("dp"),
      })
    "dns" =>
      Dns({
        t: f.off("t", t0),
        id: f.int("id"),
        header_pid: f.int("hpid"),
        client_pid: if f.map.contains("cpid") {
          Some(f.int("cpid"))
        } else {
          None
        },
        name: f.str("name"),
        status: f.int("status"),
        results: f.str("res"),
      })
    "pstart" =>
      ProcStart({
        t: f.off("t", t0),
        pid: f.int("pid"),
        ppid: f.int("ppid"),
        create_time: f.int64_str("ctime"),
        image: f.str("image"),
      })
    "pstop" =>
      ProcStop({
        t: f.off("t", t0),
        pid: f.int("pid"),
        create_time: f.int64_str("ctime"),
        exit_code: f.int("code"),
      })
    "msnap" => MihomoSnapshot(f.off("t", t0), f.get("body"))
    "mlog" => MihomoLog(f.off("t", t0), f.str("line"))
    "route" =>
      Route({
        t: f.off("t", t0),
        dst: f.ip("dst"),
        if_index: f.int("if"),
        if_name: f.str("ifname"),
        via_tun: f.bool("tun"),
      })
    "listen" => {
      let items = []
      for l in f.array("items") {
        items.push(f.listener(l))
      }
      Listeners(f.off("t", t0), items)
    }
    other => raise f.fail("unknown record kind \"\{other}\"")
  }
}

///|
/// Parses a whole recording. Blank lines are ignored; any malformed line is
/// an error that names its 1-based line number.
pub fn parse_recording(text : StringView) -> Recording raise RecordError {
  let mut header : Header? = None
  let records = []
  let mut line = 0
  for raw in text.split("\n") {
    line += 1
    let raw = raw.trim(chars=" \t\r")
    if raw.length() == 0 {
      continue
    }
    let f = parse_object(raw, line)
    match header {
      None => header = Some(parse_header(f))
      Some(h) => records.push(parse_record(f, h.t0))
    }
  }
  match header {
    Some(header) => { header, records, }
    None => raise RecordError(line=0, msg="empty recording")
  }
}
