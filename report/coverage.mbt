// What the ledger did not see, and how far the numbers can be trusted.
// Pure; the collector writes Coverage rows, the CLI reads and renders them.

///|
let ticks_per_second : Int64 = 10_000_000L

///|
/// One minute of collector coverage (deltas are added up per minute).
#derive(Eq, Debug)
pub(all) struct Coverage {
  /// Minute index (ticks / one minute).
  minute : Int64
  /// Time the collector was running and not paused.
  collector_ticks : Int64
  /// Of that, time a proxy core was known to be running.
  core_ticks : Int64
  /// Of that, time the Mihomo connection stream was connected.
  link_ticks : Int64
  /// Events the kernel reported as lost for the ETW session.
  etw_lost : Int64
  /// Events dropped because the collector's queue was full.
  dropped : Int64
}

///|
/// Coverage over a period.
#derive(Eq, Debug)
pub(all) struct CoverageSummary {
  span_ticks : Int64
  collector_ticks : Int64
  core_ticks : Int64
  link_ticks : Int64
  etw_lost : Int64
  dropped : Int64
}

///|
/// Adds up the rows of [from, to) minutes. `to` should not be past the
/// current minute, or the future counts as not covered.
pub fn summarize_coverage(
  rows : Array[Coverage],
  from : Int64,
  to : Int64,
) -> CoverageSummary {
  let mut collector_ticks = 0L
  let mut core_ticks = 0L
  let mut link_ticks = 0L
  let mut etw_lost = 0L
  let mut dropped = 0L
  for r in rows {
    if r.minute < from || r.minute >= to {
      continue
    }
    collector_ticks += r.collector_ticks
    core_ticks += r.core_ticks
    link_ticks += r.link_ticks
    etw_lost += r.etw_lost
    dropped += r.dropped
  }
  let span = if to > from { (to - from) * ticks_per_minute } else { 0L }
  {
    span_ticks: span,
    collector_ticks: if collector_ticks > span {
      span
    } else {
      collector_ticks
    },
    core_ticks,
    link_ticks,
    etw_lost,
    dropped,
  }
}

///|
/// Is every byte of the period accounted for?
pub fn CoverageSummary::complete(self : CoverageSummary) -> Bool {
  self.collector_ticks >= self.span_ticks &&
  self.link_ticks >= self.core_ticks &&
  self.etw_lost == 0L &&
  self.dropped == 0L
}

///|
/// "2 h 05 min", "3 min 10 s", "12 s".
pub fn human_duration(ticks : Int64) -> String {
  let s = ticks / ticks_per_second
  if s >= 3600L {
    let m = s / 60L % 60L
    "\{s / 3600L} h \{if m < 10L { "0" } else { "" }}\{m} min"
  } else if s >= 60L {
    "\{s / 60L} min \{s % 60L} s"
  } else {
    "\{s} s"
  }
}

///|
fn percent(part : Int64, whole : Int64) -> String {
  if whole <= 0L {
    return "0.0%"
  }
  let tenths = (part.to_double() * 1000.0 / whole.to_double()).to_int64()
  "\{tenths / 10L}.\{tenths % 10L}%"
}

///|
/// What the period's numbers miss, one line each; empty when complete.
pub fn coverage_text(c : CoverageSummary) -> String {
  let buf = StringBuilder()
  if c.collector_ticks < c.span_ticks {
    buf.write_string(
      "  collector ran \{human_duration(c.collector_ticks)} of \{human_duration(c.span_ticks)} (\{percent(c.collector_ticks, c.span_ticks)}); traffic outside that time is not counted\n",
    )
  }
  if c.link_ticks < c.core_ticks {
    buf.write_string(
      "  Mihomo connection stream down for \{human_duration(c.core_ticks - c.link_ticks)}; traffic entering the core then has exit unknown\n",
    )
  }
  if c.etw_lost > 0L || c.dropped > 0L {
    buf.write_string(
      "  events lost: \{c.etw_lost} by ETW, \{c.dropped} by the collector queue; byte counts are a lower bound\n",
    )
  }
  buf.to_string()
}

///|
/// Plan usage as a range: the low end counts only bytes with a known node;
/// the high end adds bytes whose exit is unknown or ambiguous at the highest
/// multiplier in play (they may or may not have used a node).
#derive(Eq, Debug)
pub(all) struct PlanEstimate {
  low : Int64
  high : Int64
  /// Bytes behind the gap between low and high.
  uncertain : Int64
}

///|
/// `rows` are (exit_kind, node, bytes) as stored in the usage table.
pub fn plan_estimate(
  rows : Array[(String, String, Int64)],
  multiplier : (String) -> Double,
) -> PlanEstimate {
  let mut low = 0.0
  let mut uncertain = 0L
  let mut max_mult = 1.0
  for r in rows {
    let (kind, node, bytes) = r
    match kind {
      "node" => {
        let m = multiplier(node)
        low += bytes.to_double() * m
        if m > max_mult {
          max_mult = m
        }
      }
      "unknown" | "ambiguous" => uncertain += bytes
      _ => ()
    }
  }
  let low_i = low.to_int64()
  {
    low: low_i,
    high: low_i + (uncertain.to_double() * max_mult).to_int64(),
    uncertain,
  }
}
