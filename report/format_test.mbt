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
