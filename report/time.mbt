// Local-time helpers on FILETIME ticks; the UTC offset is passed in so the
// functions stay pure.

///|
let ticks_per_day : Int64 = 864_000_000_000L

///|
let ticks_per_minute : Int64 = 600_000_000L

///|
/// Start of the local day containing `t`.
pub fn local_day_start(t : Int64, offset_minutes : Int32) -> Int64 {
  let shift = offset_minutes.to_int64() * ticks_per_minute
  let lt = t + shift
  lt - lt % ticks_per_day - shift
}

///|
/// (year, month, day) from days since 1601-01-01.
fn civil_from_days_1601(days : Int64) -> (Int32, Int32, Int32) {
  // Shift to days since 1970-01-01, then H. Hinnant's civil_from_days.
  let z = days - 134774L + 719468L
  let era = (if z >= 0L { z } else { z - 146096L }) / 146097L
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let y = yoe + era * 400L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let d = doy - (153L * mp + 2L) / 5L + 1L
  let m = if mp < 10L { mp + 3L } else { mp - 9L }
  ((if m <= 2L { y + 1L } else { y }).to_int(), m.to_int(), d.to_int())
}

///|
fn two(n : Int32) -> String {
  if n < 10 {
    "0\{n}"
  } else {
    n.to_string()
  }
}

///|
/// "2026-11-13 14:05" in local time.
pub fn format_local(t : Int64, offset_minutes : Int32) -> String {
  let lt = t + offset_minutes.to_int64() * ticks_per_minute
  let (y, m, d) = civil_from_days_1601(lt / ticks_per_day)
  let in_day = lt % ticks_per_day / ticks_per_minute
  "\{y}-\{two(m)}-\{two(d)} \{two((in_day / 60L).to_int())}:\{two((in_day % 60L).to_int())}"
}

///|
/// "2026-11-13" in local time.
pub fn format_local_date(t : Int64, offset_minutes : Int32) -> String {
  format_local(t, offset_minutes)[:10].to_owned()
}
