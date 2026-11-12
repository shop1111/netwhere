///|
/// Days from 1970-01-01 to the given proleptic Gregorian date
/// (H. Hinnant's days_from_civil).
fn days_from_civil(y : Int32, m : Int32, d : Int32) -> Int64 {
  let y = if m <= 2 { y - 1 } else { y }
  let era = (if y >= 0 { y } else { y - 399 }) / 400
  let yoe = y - era * 400
  let mp = (m + 9) % 12
  let doy = (153 * mp + 2) / 5 + d - 1
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
  era.to_int64() * 146097L + doe.to_int64() - 719468L
}

///|
/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
let filetime_unix_offset : Int64 = 11644473600L

///|
fn digits(s : StringView, from : Int32, n : Int32) -> Int32? {
  if from + n > s.length() {
    return None
  }
  let mut v = 0
  for i in from..<(from + n) {
    let c = s.code_unit_at(i).to_int()
    if c < 48 || c > 57 {
      return None
    }
    v = v * 10 + (c - 48)
  }
  Some(v)
}

///|
/// Parses an RFC 3339 timestamp as Mihomo prints it
/// ("2026-11-13T01:33:22.4691446+08:00", or with "Z") into FILETIME ticks.
/// Fractions beyond 100 ns are truncated.
pub fn parse_rfc3339(s : StringView) -> Int64? {
  guard digits(s, 0, 4) is Some(year) else { return None }
  guard digits(s, 5, 2) is Some(month) else { return None }
  guard digits(s, 8, 2) is Some(day) else { return None }
  guard digits(s, 11, 2) is Some(hour) else { return None }
  guard digits(s, 14, 2) is Some(minute) else { return None }
  guard digits(s, 17, 2) is Some(second) else { return None }
  if s.length() < 20 ||
    s.code_unit_at(4) != '-' ||
    s.code_unit_at(7) != '-' ||
    (s.code_unit_at(10) != 'T' && s.code_unit_at(10) != ' ') ||
    s.code_unit_at(13) != ':' ||
    s.code_unit_at(16) != ':' {
    return None
  }
  if month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 60 {
    return None
  }
  let mut i = 19
  let mut frac = 0L
  if s.code_unit_at(i) == '.' {
    i += 1
    let mut scale = 0
    while i < s.length() && s.code_unit_at(i) >= '0' && s.code_unit_at(i) <= '9' {
      if scale < 7 {
        frac = frac * 10L + (s.code_unit_at(i).to_int() - 48).to_int64()
        scale += 1
      }
      i += 1
    }
    while scale < 7 {
      frac = frac * 10L
      scale += 1
    }
  }
  guard i < s.length() else { return None }
  let offset_seconds = match s.code_unit_at(i) {
    'Z' | 'z' => if i + 1 == s.length() { 0 } else { return None }
    '+' | '-' as sign => {
      guard digits(s, i + 1, 2) is Some(oh) else { return None }
      guard digits(s, i + 4, 2) is Some(om) else { return None }
      if i + 6 != s.length() || s.code_unit_at(i + 3) != ':' {
        return None
      }
      let v = oh * 3600 + om * 60
      if sign == '+' {
        v
      } else {
        -v
      }
    }
    _ => return None
  }
  let days = days_from_civil(year, month, day)
  let unix = days * 86400L +
    (hour * 3600 + minute * 60 + second).to_int64() -
    offset_seconds.to_int64()
  Some((unix + filetime_unix_offset) * 10_000_000L + frac)
}
