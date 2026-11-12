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
