// Decoding of the C queue format; the session itself is exercised by
// `netwhered record` (it needs elevation for Kernel-Network).

///|
priv struct W {
  b : FixedArray[Byte]
  mut n : Int32
}

///|
fn W::u8(self : W, v : Int32) -> Unit {
  self.b[self.n] = (v & 0xff).to_byte()
  self.n += 1
}

///|
fn W::u16(self : W, v : Int32) -> Unit {
  self.u8(v)
  self.u8(v >> 8)
}

///|
fn W::u32(self : W, v : Int32) -> Unit {
  self.u16(v & 0xffff)
  self.u16((v >> 16) & 0xffff)
}

///|
fn W::i64(self : W, v : Int64) -> Unit {
  for k in 0..<8 {
    self.u8((v >> (8 * k)).to_int())
  }
}

///|
fn W::str(self : W, s : String) -> Unit {
  let b = @utf8.encode(s)
  self.u16(b.length())
  for x in b {
    self.u8(x.to_int())
  }
}

///|
/// Writes one record: header then body, back-patching the length prefix.
fn W::record(
  self : W,
  kind : Int32,
  id : Int32,
  hpid : Int32,
  t : Int64,
  body : (W) -> Unit,
) -> Unit {
  let at = self.n
  self.u32(0)
  self.u8(kind)
  self.u8(0)
  self.u16(id)
  self.u32(hpid)
  self.i64(t)
  body(self)
  let len = self.n - at - 4
  let save = self.n
  self.n = at
  self.u32(len)
  self.n = save
}

///|
test "queue records decode to ledger raw records" {
  let w : W = { b: FixedArray::make(4096, b'\x00'), n: 0, }
  // TCP recv over IPv4, ports already in host order.
  w.record(1, 11, 4, 100L, w => {
    w.u32(14948)
    w.u32(4380)
    w.u8(4)
    for x in [10, 0, 0, 5] {
      w.u8(x)
    }
    for _ in 0..<12 {
      w.u8(0)
    }
    for x in [172, 215, 188, 225] {
      w.u8(x)
    }
    for _ in 0..<12 {
      w.u8(0)
    }
    w.u16(55738)
    w.u16(443)
  })
  // TCP disconnect over IPv6.
  w.record(1, 29, 4, 101L, w => {
    w.u32(24372)
    w.u32(0)
    w.u8(6)
    for x in [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] {
      w.u8(x)
    }
    for x in [0x26, 0x03, 0x10, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x3a] {
      w.u8(x)
    }
    w.u16(53795)
    w.u16(443)
  })
  w.record(2, 3020, 2504, 102L, w => {
    w.u32(24372)
    w.u32(0)
    w.str("speed.cloudflare.com")
    w.str("198.18.0.13;")
  })
  w.record(2, 3008, 7, 103L, w => {
    w.u32(-1)
    w.u32(87)
    w.str("x.test")
    w.str("")
  })
  w.record(3, 1, 20008, 104L, w => {
    w.u32(17716)
    w.u32(20008)
    w.i64(134389774848293434L)
    w.str("\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe")
  })
  w.record(4, 2, 17716, 105L, w => {
    w.u32(17716)
    w.i64(134389774848293434L)
    w.u32(0)
  })
  // Unknown kind: skipped without disturbing what follows.
  w.record(9, 0, 0, 106L, w => w.u32(1))
  let rs = @etw.decode_records(w.b, w.n)
  assert_eq(rs.length(), 6)
  let t0 = 0L
  inspect(
    rs.map(r => r.to_line(t0)).join("\n"),
    content=(
      #|{"k":"net","t":100,"id":11,"pid":14948,"size":4380,"sa":"10.0.0.5","sp":55738,"da":"172.215.188.225","dp":443}
      #|{"k":"net","t":101,"id":29,"pid":24372,"size":0,"sa":"2001:db8::2","sp":53795,"da":"2603:1030::43a","dp":443}
      #|{"k":"dns","t":102,"id":3020,"hpid":2504,"name":"speed.cloudflare.com","status":0,"res":"198.18.0.13;","cpid":24372}
      #|{"k":"dns","t":103,"id":3008,"hpid":7,"name":"x.test","status":87,"res":""}
      #|{"k":"pstart","t":104,"pid":17716,"ppid":20008,"ctime":"134389774848293434","image":"\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe"}
      #|{"k":"pstop","t":105,"pid":17716,"ctime":"134389774848293434","code":0}
    ),
  )
}
