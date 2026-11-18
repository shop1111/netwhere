///|
test "human bytes" {
  inspect(@report.human_bytes(0L), content="0 B")
  inspect(@report.human_bytes(1023L), content="1023 B")
  inspect(@report.human_bytes(1024L), content="1.0 KB")
  inspect(@report.human_bytes(20_035_300L), content="19.1 MB")
  inspect(@report.human_bytes(5_000_000_000L), content="4.7 GB")
}

///|
test "table aligns wide characters" {
  inspect(
    @report.table(["a", "b"], [["台湾 03", "x"], ["hk", "yy"]]),
    content=(
      #|a        b
      #|台湾 03  x
      #|hk       yy
      #|
    ),
  )
}

///|
test "labels" {
  inspect(@report.entry_label(Direct, true), content="bypass")
  inspect(@report.entry_label(Direct, false), content="direct")
  inspect(@report.exit_label(Node("HK 01")), content="HK 01")
  inspect(@report.exit_label(CoreDirect), content="DIRECT (core)")
}

///|
test "local time formatting and day boundaries" {
  // 2026-11-13T06:05:30Z
  let t = 134390235300000000L
  inspect(@report.format_local(t, 0), content="2026-11-13 06:05")
  inspect(@report.format_local(t, 480), content="2026-11-13 14:05")
  inspect(@report.format_local(t, -420), content="2026-11-12 23:05")
  inspect(
    @report.format_local_date(133537247400000000L, 0),
    content="2024-02-29",
  )
  // Local midnight of 2026-11-13 at UTC+8 is 2026-11-12T16:00Z.
  assert_eq(@report.local_day_start(t, 480), 134389728000000000L)
  assert_eq(
    @report.local_day_start(134389728000000000L, 480),
    134389728000000000L,
  )
}

///|
test "coverage: complete period prints nothing" {
  let m = 600_000_000L
  let rows : Array[@report.Coverage] = [
    {
      minute: 0L,
      collector_ticks: m,
      core_ticks: m,
      link_ticks: m,
      etw_lost: 0L,
      dropped: 0L,
    },
    {
      minute: 1L,
      collector_ticks: m,
      core_ticks: m,
      link_ticks: m,
      etw_lost: 0L,
      dropped: 0L,
    },
  ]
  let c = @report.summarize_coverage(rows, 0L, 2L)
  assert_true(c.complete())
  inspect(@report.coverage_text(c), content="")
}

///|
test "coverage: missing minutes, link down and lost events are reported" {
  let m = 600_000_000L
  let rows : Array[@report.Coverage] = [
    // minute 0: full, core link down for 40 s
    {
      minute: 0L,
      collector_ticks: m,
      core_ticks: m,
      link_ticks: m / 3L,
      etw_lost: 3L,
      dropped: 0L,
    },
    // minute 1: no row, collector not running
    {
      minute: 2L,
      collector_ticks: m,
      core_ticks: 0L,
      link_ticks: 0L,
      etw_lost: 0L,
      dropped: 0L,
    },
    // outside the period
    {
      minute: 9L,
      collector_ticks: m,
      core_ticks: 0L,
      link_ticks: 0L,
      etw_lost: 99L,
      dropped: 0L,
    },
  ]
  let c = @report.summarize_coverage(rows, 0L, 3L)
  assert_false(c.complete())
  inspect(
    @report.coverage_text(c),
    content=(
      #|  collector ran 2 min 0 s of 3 min 0 s (66.6%); traffic outside that time is not counted
      #|  Mihomo connection stream down for 40 s; traffic entering the core then has exit unknown
      #|  events lost: 3 by ETW, 0 by the collector queue; byte counts are a lower bound
      #|
    ),
  )
}

///|
test "plan estimate is a range over unknown and ambiguous exits" {
  let mult = fn(n : String) { if n == "US 2x" { 2.0 } else { 1.0 } }
  let e = @report.plan_estimate(
    [
      ("node", "HK 01", 1000L),
      ("node", "US 2x", 500L),
      ("unknown", "", 300L),
      ("ambiguous", "HK 01", 200L),
      ("core-direct", "", 9999L),
      ("-", "", 9999L),
    ],
    mult,
  )
  assert_eq(e, { low: 2000L, high: 3000L, uncertain: 500L, })
  // Nothing uncertain: a point estimate.
  let p = @report.plan_estimate([("node", "HK 01", 1000L)], mult)
  assert_eq(p.low, p.high)
}
