// IP addresses in one canonical form.
//
// ETW prints IPv6 uncompressed ("2603:1030:807:14:0:0:0:43a"), DNS-Client and
// Mihomo print it compressed; every component joins on IpAddr values (or on
// their RFC 5952 text), never on the raw strings.

///|
/// An IPv4 address (host byte order) or an IPv6 address as two 64-bit halves.
#derive(Eq, Hash, Compare, Debug)
pub(all) enum IpAddr {
  V4(UInt32)
  V6(UInt64, UInt64)
}

///|
pub impl Show for IpAddr with fn output(self, logger) {
  logger.write_string(self.to_text())
}

///|
pub fn IpAddr::v4(a : Int32, b : Int32, c : Int32, d : Int32) -> IpAddr {
  V4(
    (a.reinterpret_as_uint() << 24) |
    (b.reinterpret_as_uint() << 16) |
    (c.reinterpret_as_uint() << 8) |
    d.reinterpret_as_uint(),
  )
}

///|
fn hex_value(c : Char) -> Int32? {
  match c {
    '0'..<='9' => Some(c.to_int() - '0'.to_int())
    'a'..<='f' => Some(c.to_int() - 'a'.to_int() + 10)
    'A'..<='F' => Some(c.to_int() - 'A'.to_int() + 10)
    _ => None
  }
}

///|
fn parse_v4_bits(s : StringView) -> UInt32? {
  let mut acc : UInt32 = 0
  let mut parts = 0
  for part in s.split(".") {
    let n = part.length()
    if n == 0 || n > 3 {
      return None
    }
    let mut v = 0
    for c in part {
      guard c is ('0'..<='9') else { return None }
      v = v * 10 + (c.to_int() - '0'.to_int())
    }
    if v > 255 {
      return None
    }
    acc = (acc << 8) | v.reinterpret_as_uint()
    parts += 1
  }
  if parts == 4 {
    Some(acc)
  } else {
    None
  }
}

///|
/// Parses the hex groups of one side of an IPv6 address (no "::" inside).
/// A trailing dotted quad counts as two groups when allow_v4 is set.
fn parse_v6_groups(s : StringView, allow_v4 : Bool) -> Array[Int32]? {
  let groups = []
  if s.length() == 0 {
    return Some(groups)
  }
  let parts = s.split(":").collect()
  for i, part in parts {
    if allow_v4 && i == parts.length() - 1 && part.contains(".") {
      guard parse_v4_bits(part) is Some(bits) else { return None }
      groups.push((bits >> 16).reinterpret_as_int())
      groups.push((bits & 0xffff).reinterpret_as_int())
      continue
    }
    let n = part.length()
    if n == 0 || n > 4 {
      return None
    }
    let mut v = 0
    for c in part {
      guard hex_value(c) is Some(h) else { return None }
      v = v * 16 + h
    }
    groups.push(v)
  }
  Some(groups)
}

///|
fn groups_to_v6(g : Array[Int32]) -> IpAddr {
  let mut hi : UInt64 = 0
  let mut lo : UInt64 = 0
  for i in 0..<4 {
    hi = (hi << 16) | g[i].to_uint64()
    lo = (lo << 16) | g[i + 4].to_uint64()
  }
  V6(hi, lo)
}

///|
fn parse_v6(s : StringView) -> IpAddr? {
  // Drop a zone id such as "fe80::1%12".
  let s = match s.find("%") {
    Some(i) => s[:i]
    None => s
  }
  match s.find("::") {
    Some(i) => {
      let head = s[:i]
      let tail = s[i + 2:]
      if tail.contains("::") {
        return None
      }
      guard parse_v6_groups(head, false) is Some(h) else { return None }
      guard parse_v6_groups(tail, true) is Some(t) else { return None }
      if h.length() + t.length() > 7 {
        return None
      }
      let g = h.copy()
      for _ in 0..<(8 - h.length() - t.length()) {
        g.push(0)
      }
      for x in t {
        g.push(x)
      }
      Some(groups_to_v6(g))
    }
    None => {
      guard parse_v6_groups(s, true) is Some(g) else { return None }
      if g.length() != 8 {
        return None
      }
      Some(groups_to_v6(g))
    }
  }
}

///|
/// Parses dotted IPv4 or any textual IPv6 form (compressed, uncompressed,
/// embedded IPv4, zone id). Surrounding brackets ("[::1]") are accepted.
pub fn IpAddr::parse(s : StringView) -> IpAddr? {
  let s = s.trim()
  let s = if s.has_prefix("[") && s.has_suffix("]") {
    s[1:s.length() - 1]
  } else {
    s
  }
  if s.contains(":") {
    parse_v6(s)
  } else {
    match parse_v4_bits(s) {
      Some(bits) => Some(V4(bits))
      None => None
    }
  }
}

///|
fn v6_groups(hi : UInt64, lo : UInt64) -> Array[Int32] {
  let g = []
  for i in 0..<4 {
    g.push(((hi >> ((3 - i) * 16)) & 0xffff).to_int())
  }
  for i in 0..<4 {
    g.push(((lo >> ((3 - i) * 16)) & 0xffff).to_int())
  }
  g
}

///|
fn v4_text(bits : UInt32) -> String {
  "\{bits >> 24}.\{(bits >> 16) & 0xff}.\{(bits >> 8) & 0xff}.\{bits & 0xff}"
}

///|
let hex_digits : Array[Char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]

///|
fn hex_group(v : Int32) -> String {
  if v == 0 {
    return "0"
  }
  let buf = StringBuilder()
  let mut started = false
  for shift in [12, 8, 4, 0] {
    let d = (v >> shift) & 0xf
    if d != 0 || started {
      started = true
      buf.write_char(hex_digits[d])
    }
  }
  buf.to_string()
}

///|
/// Canonical text: dotted IPv4, RFC 5952 IPv6 (lowercase, longest zero run
/// compressed, IPv4-mapped addresses as "::ffff:a.b.c.d").
pub fn IpAddr::to_text(self : IpAddr) -> String {
  match self {
    V4(bits) => v4_text(bits)
    V6(hi, lo) => {
      if hi == 0 && lo >> 32 == 0xffff {
        return "::ffff:" + v4_text((lo & 0xffffffff).to_uint())
      }
      let g = v6_groups(hi, lo)
      // Longest run of zero groups, length >= 2, first one wins ties.
      let mut best_start = -1
      let mut best_len = 0
      let mut i = 0
      while i < 8 {
        if g[i] == 0 {
          let mut j = i
          while j < 8 && g[j] == 0 {
            j += 1
          }
          if j - i > best_len && j - i >= 2 {
            best_start = i
            best_len = j - i
          }
          i = j
        } else {
          i += 1
        }
      }
      let buf = StringBuilder()
      let mut k = 0
      while k < 8 {
        if k == best_start {
          buf.write_string("::")
          k += best_len
          continue
        }
        if k > 0 && k != best_start + best_len {
          buf.write_char(':')
        }
        buf.write_string(hex_group(g[k]))
        k += 1
      }
      buf.to_string()
    }
  }
}

///|
/// IPv4-mapped IPv6 (::ffff:a.b.c.d) becomes the IPv4 address; anything
/// else is returned unchanged.
pub fn IpAddr::unmap(self : IpAddr) -> IpAddr {
  match self {
    V6(0, lo) if lo >> 32 == 0xffff => V4((lo & 0xffffffff).to_uint())
    other => other
  }
}

///|
pub fn IpAddr::is_v4(self : IpAddr) -> Bool {
  self is V4(_)
}

///|
pub fn IpAddr::is_loopback(self : IpAddr) -> Bool {
  match self.unmap() {
    V4(bits) => bits >> 24 == 127
    V6(hi, lo) => hi == 0 && lo == 1
  }
}

///|
pub fn IpAddr::is_unspecified(self : IpAddr) -> Bool {
  match self {
    V4(bits) => bits == 0
    V6(hi, lo) => hi == 0 && lo == 0
  }
}

///|
/// RFC 1918 private IPv4 and IPv6 unique local addresses (fc00::/7).
pub fn IpAddr::is_private(self : IpAddr) -> Bool {
  match self.unmap() {
    V4(bits) => bits >> 24 == 10 || bits >> 20 == 0xac1 || bits >> 16 == 0xc0a8
    V6(hi, _) => hi >> 57 == 0x7e
  }
}

///|
/// 169.254.0.0/16 and fe80::/10.
pub fn IpAddr::is_link_local(self : IpAddr) -> Bool {
  match self.unmap() {
    V4(bits) => bits >> 16 == 0xa9fe
    V6(hi, _) => hi >> 54 == 0x3fa
  }
}

///|
/// 224.0.0.0/4 and ff00::/8.
pub fn IpAddr::is_multicast(self : IpAddr) -> Bool {
  match self.unmap() {
    V4(bits) => bits >> 28 == 0xe
    V6(hi, _) => hi >> 56 == 0xff
  }
}
