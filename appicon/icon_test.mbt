///|
fn u16_at(b : Bytes, i : Int32) -> Int32 {
  b[i].to_int() | (b[i + 1].to_int() << 8)
}

///|
fn u32_at(b : Bytes, i : Int32) -> Int32 {
  u16_at(b, i) | (u16_at(b, i + 2) << 16)
}

///|
test "ico header, directory and images agree" {
  let b = @appicon.icon_file("running")
  assert_eq(u16_at(b, 0), 0)
  assert_eq(u16_at(b, 2), 1) // icon
  let n = u16_at(b, 4)
  assert_eq(n, @appicon.icon_sizes.length())
  let mut expect_offset = 6 + 16 * n
  for i, s in @appicon.icon_sizes {
    let e = 6 + 16 * i
    assert_eq(b[e].to_int(), s)
    assert_eq(u16_at(b, e + 6), 32) // bits per pixel
    let size = u32_at(b, e + 8)
    let offset = u32_at(b, e + 12)
    assert_eq(offset, expect_offset)
    // BITMAPINFOHEADER, BGRA pixels, AND mask rows padded to 4 bytes.
    assert_eq(size, 40 + s * s * 4 + (s + 31) / 32 * 4 * s)
    assert_eq(u32_at(b, offset + 4), s)
    assert_eq(u32_at(b, offset + 8), 2 * s)
    expect_offset += size
  }
  assert_eq(b.length(), expect_offset)
}

///|
test "states differ only in colour" {
  let run = @appicon.icon_file("running")
  let stop = @appicon.icon_file("stopped")
  assert_eq(run.length(), stop.length())
  assert_true(run != stop)
}
