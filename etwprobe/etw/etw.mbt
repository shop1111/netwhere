// Thin MoonBit binding over etw_stub.c plus a decoder for its record queue.

///|
pub const ProviderNet : Int32 = 1

///|
pub const ProviderDns : Int32 = 2

///|
pub const ProviderProcess : Int32 = 3

///|
pub fn provider_name(p : Int32) -> String {
  match p {
    1 => "Kernel-Network"
    2 => "DNS-Client"
    3 => "Kernel-Process"
    _ => "provider\{p}"
  }
}

///|
pub(all) suberror EtwError {
  StartFailed(stage~ : String, code~ : Int32)
}

///|
pub fn EtwError::message(self : EtwError) -> String {
  match self {
    StartFailed(stage~, code~) => "\{stage} failed: Win32 error \{code}"
  }
}

///|
pub(all) enum Value {
  UInt(UInt64)
  Int(Int64)
  Str(String)
  Raw(Bytes)
  Ip(String)
  Port(Int32)
  Bool(Bool)
  FileTime(Int64)
  Guid(Bytes)
  Missing(Int32)
}

///|
pub fn Value::render(self : Value) -> String {
  match self {
    UInt(v) => v.to_string()
    Int(v) => v.to_string()
    Str(s) => s.escape()
    Raw(b) => "raw[\{b.length()}]"
    Ip(s) => s
    Port(p) => p.to_string()
    Bool(b) => b.to_string()
    FileTime(t) => "filetime:\{t}"
    Guid(b) => "guid[\{b.length()}]"
    Missing(tag) => "missing(tag \{tag})"
  }
}

///|
pub fn Value::as_int(self : Value) -> Int64? {
  match self {
    UInt(v) => Some(v.reinterpret_as_int64())
    Int(v) => Some(v)
    Port(p) => Some(p.to_int64())
    Bool(b) => Some(if b { 1 } else { 0 })
    _ => None
  }
}

///|
pub fn Value::as_string(self : Value) -> String? {
  match self {
    Str(s) | Ip(s) => Some(s)
    _ => None
  }
}

///|
pub(all) struct Schema {
  task : String
  opcode : String
  names : Array[String]
}

///|
pub(all) struct Event {
  provider : Int32
  id : Int32
  version : Int32
  opcode : Int32
  pid : Int32
  tid : Int32
  timestamp : Int64
  schema : Schema
  values : Array[Value]
}

///|
pub fn Event::get(self : Event, name : String) -> Value? {
  for i, n in self.schema.names {
    if n == name && i < self.values.length() {
      return Some(self.values[i])
    }
  }
  None
}

///|
pub fn Event::int(self : Event, name : String) -> Int64? {
  match self.get(name) {
    Some(v) => v.as_int()
    None => None
  }
}

///|
pub fn Event::str(self : Event, name : String) -> String? {
  match self.get(name) {
    Some(v) => v.as_string()
    None => None
  }
}

///|
pub fn Event::key(self : Event) -> String {
  "\{provider_name(self.provider)}/\{self.id}/v\{self.version}"
}

// ------------------------------------------------------------------ FFI

///|
#borrow(name)
extern "C" fn ffi_start(name : String, flags : Int32) -> Int32 = "etwprobe_start"

///|
extern "C" fn ffi_stop() -> Int32 = "etwprobe_stop"

///|
extern "C" fn ffi_abandon() -> Unit = "etwprobe_abandon"

///|
#borrow(name)
extern "C" fn ffi_session_exists(name : String) -> Int32 = "etwprobe_session_exists"

///|
extern "C" fn ffi_stage() -> String = "etwprobe_stage"

///|
#borrow(out)
extern "C" fn ffi_drain(out : FixedArray[Byte], cap : Int32) -> Int32 = "etwprobe_drain"

///|
#borrow(out)
extern "C" fn ffi_stats(out : FixedArray[Int64]) -> Unit = "etwprobe_stats"

///|
#borrow(out)
extern "C" fn ffi_query(out : FixedArray[Int64]) -> Int32 = "etwprobe_query"

///|
#borrow(out)
extern "C" fn ffi_self_usage(out : FixedArray[Int64]) -> Unit = "etwprobe_self_usage"

///|
pub extern "C" fn image_name(pid : Int32) -> String = "etwprobe_image_name"

///|
#borrow(cmdline)
pub extern "C" fn spawn(cmdline : String) -> Int32 = "etwprobe_spawn"

///|
pub extern "C" fn child_wait(ms : Int32) -> Int32 = "etwprobe_child_wait"

///|
pub extern "C" fn child_exit_code() -> Int32 = "etwprobe_child_exit_code"

///|
pub extern "C" fn is_elevated() -> Int32 = "etwprobe_is_elevated"

///|
pub extern "C" fn sleep_ms(ms : Int32) -> Unit = "etwprobe_sleep_ms"

///|
pub extern "C" fn now_ms() -> Double = "etwprobe_now_ms"

// ------------------------------------------------------------------ session API

///|
pub fn start(
  name : String,
  net~ : Bool = true,
  dns~ : Bool = true,
  process~ : Bool = true,
) -> Unit raise EtwError {
  let flags = (if net { 1 } else { 0 }) |
    (if dns { 2 } else { 0 }) |
    (if process { 4 } else { 0 })
  let code = ffi_start(name, flags)
  if code != 0 {
    let stage = ffi_stage()
    ignore(ffi_stop())
    raise StartFailed(stage~, code~)
  }
}

///|
pub fn stop() -> Int32 {
  ffi_stop()
}

///|
/// Marks the session as not owned so `stop` will not end it; the ETW session keeps
/// running after this process exits.
pub fn abandon() -> Unit {
  ffi_abandon()
}

///|
/// 1 = running, 0 = not found, negative = -(Win32 error).
pub fn session_exists(name : String) -> Int32 {
  ffi_session_exists(name)
}

///|
pub(all) struct Stats {
  events : Int64
  net : Int64
  dns : Int64
  process : Int64
  dropped : Int64
  queued_bytes : Int64
  callback_ns : Int64
  max_queue : Int64
  decode_fail : Int64
  stale_sessions : Int64
  other : Int64
}

///|
pub fn stats() -> Stats {
  let a = FixedArray::make(11, 0L)
  ffi_stats(a)
  {
    events: a[0],
    net: a[1],
    dns: a[2],
    process: a[3],
    dropped: a[4],
    queued_bytes: a[5],
    callback_ns: a[6],
    max_queue: a[7],
    decode_fail: a[8],
    stale_sessions: a[9],
    other: a[10],
  }
}

///|
/// EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost, NumberOfBuffers, FreeBuffers.
pub fn query() -> FixedArray[Int64]? {
  let a = FixedArray::make(6, 0L)
  if ffi_query(a) == 0 {
    Some(a)
  } else {
    None
  }
}

///|
/// cpu ms, private bytes, working set, peak working set.
pub fn self_usage() -> FixedArray[Int64] {
  let a = FixedArray::make(4, 0L)
  ffi_self_usage(a)
  a
}

// ------------------------------------------------------------------ decoder

///|
pub struct Reader {
  buf : FixedArray[Byte]
  schemas : Map[Int32, Schema]
  mut unknown_schema : Int32
}

///|
pub fn Reader::new(capacity~ : Int32 = 4 * 1024 * 1024) -> Reader {
  { buf: FixedArray::make(capacity, b'\x00'), schemas: {}, unknown_schema: 0, }
}

///|
pub fn Reader::unknown_schema(self : Reader) -> Int32 {
  self.unknown_schema
}

///|
fn u8(b : FixedArray[Byte], i : Int32) -> Int32 {
  b[i].to_int()
}

///|
fn u16(b : FixedArray[Byte], i : Int32) -> Int32 {
  b[i].to_int() | (b[i + 1].to_int() << 8)
}

///|
fn u32(b : FixedArray[Byte], i : Int32) -> Int32 {
  b[i].to_int() |
  (b[i + 1].to_int() << 8) |
  (b[i + 2].to_int() << 16) |
  (b[i + 3].to_int() << 24)
}

///|
fn le_u64(b : FixedArray[Byte], i : Int32, n : Int32) -> UInt64 {
  let mut v = 0UL
  for k in 0..<n {
    v = v | (b[i + k].to_uint64() << (8 * k))
  }
  v
}

///|
fn le_i64(b : FixedArray[Byte], i : Int32, n : Int32) -> Int64 {
  let v = le_u64(b, i, n).reinterpret_as_int64()
  if n >= 8 || n <= 0 {
    v
  } else {
    let shift = 64 - 8 * n
    v << shift >> shift
  }
}

///|
fn slice(b : FixedArray[Byte], i : Int32, n : Int32) -> Bytes {
  Bytes::makei(n, k => b[i + k])
}

///|
fn utf8(b : FixedArray[Byte], i : Int32, n : Int32) -> String {
  @utf8.decode_lossy(slice(b, i, n)[:])
}

///|
fn ipv4(b : FixedArray[Byte], i : Int32) -> String {
  "\{u8(b, i)}.\{u8(b, i + 1)}.\{u8(b, i + 2)}.\{u8(b, i + 3)}"
}

///|
fn ipv6(b : FixedArray[Byte], i : Int32) -> String {
  let parts : Array[String] = []
  for k in 0..<8 {
    let v = (u8(b, i + 2 * k) << 8) | u8(b, i + 2 * k + 1)
    parts.push(v.to_string(radix=16))
  }
  // IPv4-mapped (::ffff:a.b.c.d) is common for dual-stack sockets.
  if parts[0:5].iter().all(p => p == "0") && parts[5] == "ffff" {
    return "::ffff:" + ipv4(b, i + 12)
  }
  parts.join(":")
}

///|
fn decode_value(
  b : FixedArray[Byte],
  tag : Int32,
  i : Int32,
  n : Int32,
) -> Value {
  match tag {
    0 => UInt(le_u64(b, i, n))
    1 => Int(le_i64(b, i, n))
    2 => Str(utf8(b, i, n))
    4 => if n == 4 { Ip(ipv4(b, i)) } else { Raw(slice(b, i, n)) }
    5 => if n == 16 { Ip(ipv6(b, i)) } else { Raw(slice(b, i, n)) }
    // Ports are stored in network byte order.
    6 =>
      if n == 2 {
        Port((u8(b, i) << 8) | u8(b, i + 1))
      } else {
        Raw(slice(b, i, n))
      }
    7 => Bool(le_u64(b, i, n) != 0UL)
    8 => FileTime(le_i64(b, i, n))
    9 => Guid(slice(b, i, n))
    3 | 10 => Raw(slice(b, i, n))
    _ => Missing(tag)
  }
}

///|
/// Drains everything currently queued by the consumer thread.
pub fn Reader::drain(self : Reader) -> Array[Event] {
  let out : Array[Event] = []
  let b = self.buf
  let total = ffi_drain(b, b.length())
  let mut off = 0
  while off + 4 <= total {
    let len = u32(b, off)
    let base = off + 4
    off = base + len
    let provider = u8(b, base)
    let version = u8(b, base + 1)
    let id = u16(b, base + 2)
    let opcode = u8(b, base + 4)
    let flags = u8(b, base + 5)
    let nprops = u16(b, base + 6)
    let pid = u32(b, base + 8)
    let tid = u32(b, base + 12)
    let ts = le_i64(b, base + 16, 8)
    let mut p = base + 24
    let key = (provider << 24) | (id << 8) | version
    if (flags & 1) != 0 {
      let strs : Array[String] = []
      for _ in 0..<(nprops + 2) {
        let n = u16(b, p)
        strs.push(utf8(b, p + 2, n))
        p = p + 2 + n
      }
      self.schemas[key] = {
        task: strs[0],
        opcode: strs[1],
        names: strs[2:].to_owned(),
      }
    }
    let schema = match self.schemas.get(key) {
      Some(s) => s
      None => {
        self.unknown_schema += 1
        { task: "?", opcode: "?", names: [], }
      }
    }
    let values : Array[Value] = []
    for _ in 0..<nprops {
      let tag = u8(b, p)
      let n = u16(b, p + 1)
      values.push(decode_value(b, tag, p + 3, n))
      p = p + 3 + n
    }
    out.push({
      provider,
      id,
      version,
      opcode,
      pid,
      tid,
      timestamp: ts,
      schema,
      values,
    })
  }
  out
}
