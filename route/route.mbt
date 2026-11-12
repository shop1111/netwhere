// Route and socket-owner queries (IP Helper API, no elevation needed).
//
//   best_route(dst)   which interface the OS would use for a destination
//   tcp_listeners()   listening TCP sockets and their owning pids
//   interfaces()      adapters with their unicast prefixes
//   dos_devices()     NT device -> drive letter map
//
// Decision rule (PLAN.md §4.4): a flow "entered TUN" when the best route for
// its peer leaves through the TUN adapter; this catches the IPv6 default
// route that bypasses TUN on the probe machine.

///|
#borrow(addr, out)
extern "c" fn nw_best_route(
  family : Int32,
  addr : FixedArray[Byte],
  out : FixedArray[Byte],
  cap : Int32,
) -> Int32 = "nw_best_route"

///|
#borrow(out)
extern "c" fn nw_tcp_listeners(out : FixedArray[Byte], cap : Int32) -> Int32 = "nw_tcp_listeners"

///|
#borrow(out)
extern "c" fn nw_interfaces(out : FixedArray[Byte], cap : Int32) -> Int32 = "nw_interfaces"

///|
#borrow(out)
extern "c" fn nw_dos_devices(out : FixedArray[Byte], cap : Int32) -> Int32 = "nw_dos_devices"

///|
#derive(Debug)
pub(all) suberror RouteError {
  RouteError(op~ : String, code~ : Int32)
}

///|
pub impl Show for RouteError with fn output(self, logger) {
  let RouteError(op~, code~) = self
  logger.write_string("\{op} failed with Win32 error \{code}")
}

///|
/// Calls a buffer-filling stub, growing the buffer on
/// ERROR_INSUFFICIENT_BUFFER (122).
fn call_filling(
  op : String,
  initial : Int32,
  f : (FixedArray[Byte], Int32) -> Int32,
) -> (FixedArray[Byte], Int32) raise RouteError {
  let mut cap = initial
  for _ in 0..<6 {
    let buf = FixedArray::make(cap, b'\x00')
    let n = f(buf, cap)
    if n >= 0 {
      return (buf, n)
    }
    if n != -122 {
      raise RouteError(op~, code=-n)
    }
    cap = cap * 4
  }
  raise RouteError(op~, code=122)
}

///|
priv struct Reader {
  buf : FixedArray[Byte]
  mut pos : Int32
}

///|
fn Reader::u8(self : Reader) -> Int32 {
  let v = self.buf[self.pos].to_int()
  self.pos += 1
  v
}

///|
fn Reader::u16(self : Reader) -> Int32 {
  let v = self.buf[self.pos].to_int() | (self.buf[self.pos + 1].to_int() << 8)
  self.pos += 2
  v
}

///|
fn Reader::u32(self : Reader) -> Int32 {
  let v = self.buf[self.pos].to_int() |
    (self.buf[self.pos + 1].to_int() << 8) |
    (self.buf[self.pos + 2].to_int() << 16) |
    (self.buf[self.pos + 3].to_int() << 24)
  self.pos += 4
  v
}

///|
fn Reader::str(self : Reader) -> String {
  let n = self.u16()
  let bytes = Bytes::makei(n, i => self.buf[self.pos + i])
  self.pos += n
  @utf8.decode_lossy(bytes)
}

///|
/// family byte + 16 address bytes (network order); None for family 0.
fn Reader::addr(self : Reader) -> @netaddr.IpAddr? {
  let family = self.u8()
  let start = self.pos
  self.pos += 16
  match family {
    4 => {
      let b = fn(i : Int32) { self.buf[start + i].to_uint() }
      Some(V4((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)))
    }
    6 => {
      let mut hi : UInt64 = 0
      let mut lo : UInt64 = 0
      for i in 0..<8 {
        hi = (hi << 8) | self.buf[start + i].to_uint64()
        lo = (lo << 8) | self.buf[start + 8 + i].to_uint64()
      }
      Some(V6(hi, lo))
    }
    _ => None
  }
}

///|
fn addr_bytes(ip : @netaddr.IpAddr) -> (Int32, FixedArray[Byte]) {
  let out = FixedArray::make(16, b'\x00')
  match ip {
    V4(bits) => {
      for i in 0..<4 {
        out[i] = ((bits >> ((3 - i) * 8)) & 0xff).to_byte()
      }
      (4, out)
    }
    V6(hi, lo) => {
      for i in 0..<8 {
        out[i] = ((hi >> ((7 - i) * 8)) & 0xff).to_byte()
        out[8 + i] = ((lo >> ((7 - i) * 8)) & 0xff).to_byte()
      }
      (6, out)
    }
  }
}

///|
#derive(Eq, Debug)
pub(all) struct BestRoute {
  if_index : Int32
  if_name : String
  prefix_len : Int32
  next_hop : @netaddr.IpAddr?
  source : @netaddr.IpAddr?
}

///|
pub fn best_route(dst : @netaddr.IpAddr) -> BestRoute raise RouteError {
  let (family, bytes) = addr_bytes(dst)
  let (buf, _) = call_filling("GetBestRoute2", 512, (out, cap) => {
    nw_best_route(family, bytes, out, cap)
  })
  let r : Reader = { buf, pos: 0, }
  let if_index = r.u32()
  let prefix_len = r.u8()
  let next_hop = r.addr()
  let source = r.addr()
  let if_name = r.str()
  { if_index, if_name, prefix_len, next_hop, source, }
}

///|
#derive(Eq, Debug)
pub(all) struct TcpListener {
  addr : @netaddr.IpAddr
  port : Int32
  pid : Int32
}

///|
pub fn tcp_listeners() -> Array[TcpListener] raise RouteError {
  let (buf, _) = call_filling("GetExtendedTcpTable", 64 * 1024, (out, cap) => {
    nw_tcp_listeners(out, cap)
  })
  let r : Reader = { buf, pos: 0, }
  let count = r.u32()
  let out = []
  for _ in 0..<count {
    let addr = r.addr()
    let port = r.u16()
    let pid = r.u32()
    if addr is Some(a) {
      out.push({ addr: a, port, pid, })
    }
  }
  out
}

///|
#derive(Eq, Debug)
pub(all) struct Interface {
  if_index : Int32
  if_type : Int32
  up : Bool
  name : String
  description : String
  prefixes : Array[@netaddr.Cidr]
}

///|
pub fn interfaces() -> Array[Interface] raise RouteError {
  let (buf, _) = call_filling("GetAdaptersAddresses", 64 * 1024, (out, cap) => {
    nw_interfaces(out, cap)
  })
  let r : Reader = { buf, pos: 0, }
  let count = r.u32()
  let out = []
  for _ in 0..<count {
    let if_index = r.u32()
    let if_type = r.u32()
    let up = r.u8() == 1
    let name = r.str()
    let description = r.str()
    let k = r.u8()
    let prefixes = []
    for _ in 0..<k {
      let a = r.addr()
      let len = r.u8()
      if a is Some(addr) {
        prefixes.push(@netaddr.Cidr::{ addr, len, })
      }
    }
    out.push({ if_index, if_type, up, name, description, prefixes, })
  }
  out
}

///|
/// ("\\Device\\HarddiskVolume3", "C:") pairs for every mapped drive letter.
pub fn dos_devices() -> Array[(String, String)] raise RouteError {
  let (buf, _) = call_filling("QueryDosDevice", 4096, (out, cap) => {
    nw_dos_devices(out, cap)
  })
  let r : Reader = { buf, pos: 0, }
  let count = r.u32()
  let out = []
  for _ in 0..<count {
    let letter = r.u8().unsafe_to_char()
    let device = r.str()
    out.push((device, "\{letter}:"))
  }
  out
}
