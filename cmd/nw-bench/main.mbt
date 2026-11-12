// nw-bench: per-event cost of the MoonBit side of the collector (queue
// record decoding, normalization, accounting). The C callback cost is
// reported separately by `netwhered record` (ns/event).
//
//   nw-bench [EVENTS] [FLOWS]

///|
fn put_u8(b : FixedArray[Byte], p : Int32, v : Int32) -> Int32 {
  b[p] = (v & 0xff).to_byte()
  p + 1
}

///|
fn put_u16(b : FixedArray[Byte], p : Int32, v : Int32) -> Int32 {
  put_u8(b, put_u8(b, p, v), v >> 8)
}

///|
fn put_u32(b : FixedArray[Byte], p : Int32, v : Int32) -> Int32 {
  put_u16(b, put_u16(b, p, v & 0xffff), (v >> 16) & 0xffff)
}

///|
/// Queue bytes for `n` TCP receive events spread over `flows` sockets.
fn synth(n : Int32, flows : Int32, t0 : Int64) -> (FixedArray[Byte], Int32) {
  let rec_len = 16 + 4 + 4 + 1 + 16 + 16 + 2 + 2
  let b = FixedArray::make(n * (rec_len + 4), b'\x00')
  let mut p = 0
  for i in 0..<n {
    let flow = i % flows
    p = put_u32(b, p, rec_len)
    p = put_u8(b, p, 1)
    p = put_u8(b, p, 0)
    p = put_u16(b, p, 11)
    p = put_u32(b, p, 4)
    let t = t0 + i.to_int64() * 1000L
    for k in 0..<8 {
      p = put_u8(b, p, (t >> (8 * k)).to_int())
    }
    p = put_u32(b, p, 1000 + flow % 50)
    p = put_u32(b, p, 1460)
    p = put_u8(b, p, 4)
    for x in [10, 0, 0, 5] {
      p = put_u8(b, p, x)
    }
    p += 12
    for x in [93, 184, flow / 256 % 256, flow % 256] {
      p = put_u8(b, p, x)
    }
    p += 12
    p = put_u16(b, p, 40000 + flow % 20000)
    p = put_u16(b, p, 443)
  }
  (b, p)
}

///|
fn per_event(ticks : Int64, n : Int32) -> String {
  // ticks are 100 ns
  let ns = ticks * 100L / n.to_int64()
  "\{ns} ns/event"
}

///|
fn main {
  let args = @env.args()
  let parse = fn(i : Int32, d : Int32) {
    if args.length() > i {
      let mut v = 0
      for c in args[i] {
        v = v * 10 + (c.to_int() - '0'.to_int())
      }
      v
    } else {
      d
    }
  }
  let n = parse(1, 1_000_000)
  let flows = parse(2, 2000)
  let t0 = @sys.now()
  let (buf, len) = synth(n, flows, t0)
  let a = @sys.now()
  let records = @etw.decode_records(buf, len)
  let b = @sys.now()
  let events = []
  for r in records {
    if r is Net(raw) && @ledger.normalize_net(raw) is Some(e) {
      events.push(e)
    }
  }
  let c = @sys.now()
  // The collector's path: bytes straight to normalized events.
  let live = @etw.decode_live(buf, len)
  let c2 = @sys.now()
  ignore(live)
  let engine = @ledger.Engine::new({
    via_tun: _ => false,
    listener_pid: (_, _) => None,
  })
  for e in events {
    engine.on_net(e)
  }
  let d = @sys.now()
  let rows = engine.take_usage(@rules.RuleSet::new(), t0 + 600_000_000_000L)
  let e = @sys.now()
  println("\{n} events over \{flows} flows")
  println("  decode queue records: \{per_event(b - a, n)}")
  println("  normalize:            \{per_event(c - b, n)}")
  println("  account:              \{per_event(d - c2, n)}")
  println(
    "  usage rows:           \{rows.length()} rows in \{(e - d) / 10_000L} ms",
  )
  println("  recording path total: \{per_event(c - a + (d - c2), n)}")
  println("  live decode (direct): \{per_event(c2 - c, n)}")
  println("  live path total:      \{per_event(c2 - c + (d - c2), n)}")
  let u = @sys.self_usage()
  println(
    "  process: private \{u.private_bytes / 1048576L} MB, peak working set \{u.peak_working_set / 1048576L} MB",
  )
}
