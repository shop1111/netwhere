///|
/// An address prefix such as "198.18.0.0/15" or "fc00::/7".
#derive(Eq, Hash, Debug)
pub(all) struct Cidr {
  addr : IpAddr
  len : Int32
}

///|
pub impl Show for Cidr with fn output(self, logger) {
  logger.write_string("\{self.addr}/\{self.len}")
}

///|
pub fn Cidr::parse(s : StringView) -> Cidr? {
  guard s.split_once("/") is Some((a, l)) else {
    // A bare address is a host prefix.
    return match IpAddr::parse(s) {
      Some(addr) => Some({ addr, len: if addr.is_v4() { 32 } else { 128 }, })
      None => None
    }
  }
  guard IpAddr::parse(a) is Some(addr) else { return None }
  if l.length() == 0 || l.length() > 3 {
    return None
  }
  let mut len = 0
  for c in l {
    guard c is ('0'..<='9') else { return None }
    len = len * 10 + (c.to_int() - '0'.to_int())
  }
  let max = if addr.is_v4() { 32 } else { 128 }
  if len > max {
    return None
  }
  Some({ addr, len, })
}

///|
fn mask64(bits : UInt64, keep : Int32) -> UInt64 {
  if keep <= 0 {
    0
  } else if keep >= 64 {
    bits
  } else {
    bits >> (64 - keep) << (64 - keep)
  }
}

///|
pub fn Cidr::contains(self : Cidr, ip : IpAddr) -> Bool {
  match (self.addr, ip.unmap()) {
    (V4(net), V4(a)) =>
      if self.len == 0 {
        true
      } else {
        let shift = 32 - self.len
        net >> shift == a >> shift
      }
    (V6(nh, nl), V6(ah, al)) =>
      mask64(nh, self.len) == mask64(ah, self.len) &&
      mask64(nl, self.len - 64) == mask64(al, self.len - 64)
    _ => false
  }
}
