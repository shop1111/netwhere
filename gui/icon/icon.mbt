// The tray icon, drawn here rather than shipped as a file: a rounded square
// in the state's colour with a white arrow leaving towards the top right
// ("where does the traffic go"). Several sizes go into one .ico so Windows
// picks a sharp one at any display scale.

///|
/// sRGB colour of the square per state.
fn state_rgb(state : String) -> (Int32, Int32, Int32) {
  match state {
    "running" => (0x2f, 0x7d, 0xe1)
    "paused" => (0xd9, 0x8e, 0x1e)
    _ => (0x86, 0x8b, 0x94)
  }
}

///|
fn dist_to_segment(
  px : Double,
  py : Double,
  ax : Double,
  ay : Double,
  bx : Double,
  by : Double,
) -> Double {
  let dx = bx - ax
  let dy = by - ay
  let t0 = ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)
  let t = if t0 < 0.0 { 0.0 } else if t0 > 1.0 { 1.0 } else { t0 }
  let qx = ax + t * dx - px
  let qy = ay + t * dy - py
  (qx * qx + qy * qy).sqrt()
}

///|
/// Is (x, y), in units of the icon size, on the rounded square?
fn in_square(x : Double, y : Double) -> Bool {
  let r = 0.22
  let lo = 0.04
  let hi = 0.96
  if x < lo || x > hi || y < lo || y > hi {
    return false
  }
  let cx = if x < lo + r { lo + r } else if x > hi - r { hi - r } else { x }
  let cy = if y < lo + r { lo + r } else if y > hi - r { hi - r } else { y }
  (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r
}

///|
/// Is (x, y) on the arrow (shaft plus head, tip at the top right)?
fn in_arrow(x : Double, y : Double) -> Bool {
  if dist_to_segment(x, y, 0.27, 0.73, 0.62, 0.38) < 0.085 {
    return true
  }
  // Head: the triangle (0.75, 0.25), (0.40, 0.25), (0.75, 0.60).
  x <= 0.75 && y >= 0.25 && x - y >= 0.15
}

///|
fn put_u16(b : Array[Byte], v : Int32) -> Unit {
  b.push((v & 0xff).to_byte())
  b.push(((v >> 8) & 0xff).to_byte())
}

///|
fn put_u32(b : Array[Byte], v : Int32) -> Unit {
  put_u16(b, v & 0xffff)
  put_u16(b, (v >> 16) & 0xffff)
}

///|
/// One 32-bit BMP image (as stored in an .ico) of size s × s.
fn icon_image(s : Int32, rgb : (Int32, Int32, Int32)) -> Array[Byte] {
  let b = []
  // BITMAPINFOHEADER; the height counts the colour and mask halves.
  put_u32(b, 40)
  put_u32(b, s)
  put_u32(b, 2 * s)
  put_u16(b, 1)
  put_u16(b, 32)
  for _ in 0..<6 {
    put_u32(b, 0)
  }
  let n = 4 // 4 × 4 samples per pixel
  let (r, g, bl) = rgb
  // Rows bottom-up, pixels BGRA, colour premultiplied by nothing (straight).
  for row in 0..<s {
    let py = s - 1 - row
    for px in 0..<s {
      let mut cover = 0
      let mut white = 0
      for sy in 0..<n {
        for sx in 0..<n {
          let x = (px.to_double() + (sx.to_double() + 0.5) / n.to_double()) /
            s.to_double()
          let y = (py.to_double() + (sy.to_double() + 0.5) / n.to_double()) /
            s.to_double()
          if in_square(x, y) {
            cover += 1
            if in_arrow(x, y) {
              white += 1
            }
          }
        }
      }
      let a = cover * 255 / (n * n)
      let mix = fn(c : Int32) {
        if cover == 0 {
          0
        } else {
          (c * (cover - white) + 255 * white) / cover
        }
      }
      b.push(mix(bl).to_byte())
      b.push(mix(g).to_byte())
      b.push(mix(r).to_byte())
      b.push(a.to_byte())
    }
  }
  // AND mask: all zero (the alpha channel decides), rows padded to 4 bytes.
  let mask_row = (s + 31) / 32 * 4
  for _ in 0..<(mask_row * s) {
    b.push(b'\x00')
  }
  b
}

///|
pub let icon_sizes : Array[Int32] = [16, 20, 24, 32, 40, 48]

///|
/// A complete .ico file for the state ("running", "paused", other).
pub fn icon_file(state : String) -> Bytes {
  let rgb = state_rgb(state)
  let images = icon_sizes.map(s => icon_image(s, rgb))
  let b = []
  put_u16(b, 0)
  put_u16(b, 1)
  put_u16(b, images.length())
  let mut offset = 6 + 16 * images.length()
  for i, s in icon_sizes {
    b.push(s.to_byte())
    b.push(s.to_byte())
    b.push(b'\x00')
    b.push(b'\x00')
    put_u16(b, 1)
    put_u16(b, 32)
    put_u32(b, images[i].length())
    put_u32(b, offset)
    offset += images[i].length()
  }
  for img in images {
    for x in img {
      b.push(x)
    }
  }
  Bytes::from_array(b)
}

///|
/// %LOCALAPPDATA%\netwhere: per-user files of the tray and the window.
pub fn user_dir() -> String {
  let base = match @sys.getenv("LOCALAPPDATA") {
    Some(d) => d
    None => @sys.getenv("TEMP").unwrap_or(".")
  }
  ignore(@sys.make_dir(base + "\\netwhere"))
  base + "\\netwhere"
}

///|
/// Writes the three state icons into user_dir() and returns their paths
/// by state ("running", "paused", "stopped").
pub fn write_icons() -> Map[String, String] {
  let base = user_dir()
  let out = Map([])
  for state in ["running", "paused", "stopped"] {
    let path = base + "\\tray-" + state + ".ico"
    if @sys.write_file_atomic(path, icon_file(state)) == 0 {
      out[state] = path
    }
  }
  out
}
