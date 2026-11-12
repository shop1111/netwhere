// Real-time ETW session for Kernel-Network, DNS-Client and Kernel-Process.
// Scope is fixed on purpose: this is netwhere's collector, not a general
// ETW library. The C side extracts only the fields netwhere uses; this file
// turns its records into ledger raw records.

///|
#borrow(name)
extern "c" fn nw_etw_start(
  name : String,
  flags : Int32,
  mode : Int32,
  queue_kb : Int32,
) -> Int32 = "nw_etw_start"

///|
extern "c" fn nw_etw_stop() -> Int32 = "nw_etw_stop"

///|
#borrow(name)
extern "c" fn nw_etw_session_exists(name : String) -> Int32 = "nw_etw_session_exists"

///|
#borrow(name)
extern "c" fn nw_etw_stop_session(name : String) -> Int32 = "nw_etw_stop_session"

///|
extern "c" fn nw_etw_stage() -> String = "nw_etw_stage"

///|
#borrow(out)
extern "c" fn nw_etw_drain(out : FixedArray[Byte], cap : Int32) -> Int32 = "nw_etw_drain"

///|
#borrow(out)
extern "c" fn nw_etw_stats(out : FixedArray[Int64]) = "nw_etw_stats"

///|
#borrow(out)
extern "c" fn nw_etw_query(out : FixedArray[Int64]) -> Int32 = "nw_etw_query"

///|
/// How the C callback extracts fields (see etw_stub.c).
#derive(Eq, Debug)
pub(all) enum Decoder {
  /// TdhGetProperty by name: the path verified in the M0 probe.
  Tdh
  /// Fixed offsets derived from the TDH schema where possible.
  Fast
  /// Fast, plus Tdh for comparison; mismatches are counted in Stats.
  Shadow
}

///|
#derive(Debug)
pub(all) suberror EtwError {
  StartFailed(stage~ : String, code~ : Int32)
}

///|
pub impl Show for EtwError with fn output(self, logger) {
  let StartFailed(stage~, code~) = self
  let hint = if code == 5 {
    " (access denied: Kernel-Network and Kernel-Process need an elevated process)"
  } else {
    ""
  }
  logger.write_string("\{stage} failed: Win32 error \{code}\{hint}")
}

///|
#derive(Eq, Debug)
pub(all) struct Providers {
  net : Bool
  dns : Bool
  process : Bool
}

///|
pub let all_providers : Providers = { net: true, dns: true, process: true, }

///|
/// What an unelevated process can still collect.
pub let unelevated_providers : Providers = {
  net: false,
  dns: true,
  process: false,
}

///|
/// Starts the session, stopping a stale session of the same name first.
/// Only one session per process.
pub fn start(
  name : String,
  providers~ : Providers = all_providers,
  decoder~ : Decoder = Shadow,
  queue_kb~ : Int32 = 1024,
) -> Unit raise EtwError {
  let flags = (if providers.net { 1 } else { 0 }) |
    (if providers.dns { 2 } else { 0 }) |
    (if providers.process { 4 } else { 0 })
  let mode = match decoder {
    Tdh => 0
    Fast => 1
    Shadow => 2
  }
  let code = nw_etw_start(name, flags, mode, queue_kb)
  if code != 0 {
    let stage = nw_etw_stage()
    ignore(nw_etw_stop())
    raise StartFailed(stage~, code~)
  }
}

///|
pub fn stop() -> Unit {
  ignore(nw_etw_stop())
}

///|
pub fn session_exists(name : String) -> Bool {
  nw_etw_session_exists(name) == 1
}

///|
/// Stops a session by name (cleanup of a session left by a crashed
/// collector). Returns the Win32 status.
pub fn stop_session(name : String) -> Int32 {
  nw_etw_stop_session(name)
}

///|
#derive(Eq, Debug)
pub(all) struct Stats {
  events : Int64
  net : Int64
  dns : Int64
  process : Int64
  /// Records dropped because the queue was full.
  dropped : Int64
  queued_bytes : Int64
  callback_ns : Int64
  max_queue : Int64
  decode_fail : Int64
  stale_sessions : Int64
  other : Int64
  fast_fields : Int64
  slow_fields : Int64
  shadow_checked : Int64
  shadow_mismatch : Int64
  /// Events of a known provider with an id netwhere does not use.
  skipped : Int64
}

///|
pub fn stats() -> Stats {
  let a = FixedArray::make(16, 0L)
  nw_etw_stats(a)
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
    fast_fields: a[11],
    slow_fields: a[12],
    shadow_checked: a[13],
    shadow_mismatch: a[14],
    skipped: a[15],
  }
}

///|
/// Losses reported by the kernel for this session.
#derive(Eq, Debug)
pub(all) struct SessionLoss {
  events_lost : Int64
  buffers_written : Int64
  log_buffers_lost : Int64
  realtime_buffers_lost : Int64
}

///|
pub fn session_loss() -> SessionLoss? {
  let a = FixedArray::make(4, 0L)
  if nw_etw_query(a) != 0 {
    return None
  }
  Some({
    events_lost: a[0],
    buffers_written: a[1],
    log_buffers_lost: a[2],
    realtime_buffers_lost: a[3],
  })
}

// ---------------------------------------------------------------- decoding

///|
pub struct Reader {
  priv buf : FixedArray[Byte]
}

///|
pub fn Reader::new(capacity~ : Int32 = 1024 * 1024) -> Reader {
  { buf: FixedArray::make(capacity, b'\x00'), }
}

///|
priv struct Cursor {
  b : FixedArray[Byte]
  mut p : Int32
}

///|
fn Cursor::u8(self : Cursor) -> Int32 {
  let v = self.b[self.p].to_int()
  self.p += 1
  v
}

///|
fn Cursor::u16(self : Cursor) -> Int32 {
  let v = self.b[self.p].to_int() | (self.b[self.p + 1].to_int() << 8)
  self.p += 2
  v
}

///|
fn Cursor::u32(self : Cursor) -> Int32 {
  let b = self.b
  let p = self.p
  self.p += 4
  b[p].to_int() |
  (b[p + 1].to_int() << 8) |
  (b[p + 2].to_int() << 16) |
  (b[p + 3].to_int() << 24)
}

///|
fn Cursor::i64(self : Cursor) -> Int64 {
  let mut v = 0L
  for k in 0..<8 {
    v = v | (self.b[self.p + k].to_int64() << (8 * k))
  }
  self.p += 8
  v
}

///|
fn Cursor::str(self : Cursor) -> String {
  let n = self.u16()
  let bytes = Bytes::makei(n, i => self.b[self.p + i])
  self.p += n
  @utf8.decode_lossy(bytes)
}

///|
fn Cursor::ip(self : Cursor, family : Int32) -> @netaddr.IpAddr {
  let b = self.b
  let p = self.p
  self.p += 16
  if family == 4 {
    V4(
      (b[p].to_uint() << 24) |
      (b[p + 1].to_uint() << 16) |
      (b[p + 2].to_uint() << 8) |
      b[p + 3].to_uint(),
    )
  } else {
    let mut hi : UInt64 = 0
    let mut lo : UInt64 = 0
    for i in 0..<8 {
      hi = (hi << 8) | b[p + i].to_uint64()
      lo = (lo << 8) | b[p + 8 + i].to_uint64()
    }
    V6(hi, lo)
  }
}

///|
/// What the live collector consumes: network events already normalized
/// (no address text round trip), everything else as raw records.
pub(all) enum LiveEvent {
  NetE(@ledger.NetEvent)
  OtherE(@ledger.Record)
}

///|
/// Decodes the record at `off`; returns it (if known) and the next offset.
/// `live` turns network records into normalized events directly.
fn decode_at(
  b : FixedArray[Byte],
  off : Int32,
  live : Bool,
) -> (LiveEvent?, Int32) {
  let c : Cursor = { b, p: off, }
  let len = c.u32()
  let next = off + 4 + len
  let kind = c.u8()
  let _version = c.u8()
  let id = c.u16()
  let header_pid = c.u32()
  let t = c.i64()
  let ev : LiveEvent? = match kind {
    1 => {
      let pid = c.u32()
      let size = c.u32()
      let family = c.u8()
      let s = c.ip(family)
      let d = c.ip(family)
      let sport = c.u16()
      let dport = c.u16()
      if live {
        @ledger.net_event(t, id, pid, size, s, sport, d, dport).map(e => NetE(e))
      } else {
        Some(
          OtherE(
            Net({
              t,
              id,
              pid,
              size,
              saddr: s.to_text(),
              sport,
              daddr: d.to_text(),
              dport,
            }),
          ),
        )
      }
    }
    2 => {
      let client = c.u32()
      let status = c.u32()
      let name = c.str()
      let results = c.str()
      Some(
        OtherE(
          Dns({
            t,
            id,
            header_pid,
            client_pid: if client == -1 {
              None
            } else {
              Some(client)
            },
            name,
            status,
            results,
          }),
        ),
      )
    }
    3 => {
      let pid = c.u32()
      let ppid = c.u32()
      let create_time = c.i64()
      let image = c.str()
      Some(OtherE(ProcStart({ t, pid, ppid, create_time, image, })))
    }
    4 => {
      let pid = c.u32()
      let create_time = c.i64()
      let exit_code = c.u32()
      Some(OtherE(ProcStop({ t, pid, create_time, exit_code, })))
    }
    _ => None
  }
  (ev, next)
}

///|
/// Decodes a buffer of length-prefixed records (the C queue format) into
/// recording records. Exposed for tests and `record`.
pub fn decode_records(
  b : FixedArray[Byte],
  total : Int32,
) -> Array[@ledger.Record] {
  let out = []
  let mut off = 0
  while off + 4 <= total {
    let (ev, next) = decode_at(b, off, false)
    if ev is Some(OtherE(r)) {
      out.push(r)
    }
    off = next
  }
  out
}

///|
/// Live-path decoding (see LiveEvent).
pub fn decode_live(b : FixedArray[Byte], total : Int32) -> Array[LiveEvent] {
  let out = []
  let mut off = 0
  while off + 4 <= total {
    let (ev, next) = decode_at(b, off, true)
    if ev is Some(e) {
      out.push(e)
    }
    off = next
  }
  out
}

///|
/// Takes everything the callback thread has queued so far.
pub fn Reader::drain(self : Reader) -> Array[@ledger.Record] {
  let n = nw_etw_drain(self.buf, self.buf.length())
  decode_records(self.buf, n)
}

///|
/// Live-path drain (see LiveEvent).
pub fn Reader::drain_live(self : Reader) -> Array[LiveEvent] {
  let n = nw_etw_drain(self.buf, self.buf.length())
  decode_live(self.buf, n)
}
