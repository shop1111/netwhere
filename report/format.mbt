// Text rendering shared by `netwhere trace`, `netwhere replay` and
// `netwhere report`. Pure; no I/O.

///|
/// "1.5 KB", "19.1 MB" (binary units, one decimal).
pub fn human_bytes(n : Int64) -> String {
  let units = ["B", "KB", "MB", "GB", "TB"]
  if n < 1024L {
    return "\{n} B"
  }
  let mut v = n.to_double()
  let mut u = 0
  while v >= 1024.0 && u < units.length() - 1 {
    v = v / 1024.0
    u += 1
  }
  let tenths = (v * 10.0 + 0.5).to_int64()
  "\{tenths / 10L}.\{tenths % 10L} \{units[u]}"
}

///|
/// Entry label; a direct flow on a machine with a running core is reported
/// as having bypassed it, which is exactly what `trace` is for.
pub fn entry_label(e : @ledger.Entry, core_present : Bool) -> String {
  match e {
    ProxyPort => "proxy-port"
    Tun => "tun"
    Direct => if core_present { "bypass" } else { "direct" }
    Lan => "lan"
  }
}

///|
pub fn exit_label(x : @ledger.Exit) -> String {
  match x {
    Node(n) => n
    CoreDirect => "DIRECT (core)"
    CoreReject => "REJECT (core)"
    Unknown => "?"
    NotProxied => "-"
  }
}

///|
fn pad(s : String, w : Int32) -> String {
  let n = display_width(s)
  if n >= w {
    s
  } else {
    s + " ".repeat(w - n)
  }
}

///|
/// Terminal width: CJK and emoji count as two columns.
pub fn display_width(s : String) -> Int32 {
  let mut w = 0
  for c in s {
    let cp = c.to_int()
    w += if cp >= 0x1100 &&
      (
        cp <= 0x115f ||
        (cp >= 0x2e80 && cp <= 0xa4cf) ||
        (cp >= 0xac00 && cp <= 0xd7a3) ||
        (cp >= 0xf900 && cp <= 0xfaff) ||
        (cp >= 0xfe30 && cp <= 0xfe4f) ||
        (cp >= 0xff00 && cp <= 0xff60) ||
        (cp >= 0xffe0 && cp <= 0xffe6) ||
        cp >= 0x1f300
      ) {
      2
    } else {
      1
    }
  }
  w
}

///|
/// Renders rows as aligned columns separated by two spaces.
pub fn table(header : Array[String], rows : Array[Array[String]]) -> String {
  let widths = header.map(display_width)
  for r in rows {
    for i, cell in r {
      if i < widths.length() && display_width(cell) > widths[i] {
        widths[i] = display_width(cell)
      }
    }
  }
  let buf = StringBuilder()
  let line = fn(cells : Array[String]) {
    let parts = []
    for i, c in cells {
      parts.push(if i == cells.length() - 1 { c } else { pad(c, widths[i]) })
    }
    buf.write_string(parts.join("  ").trim_end().to_owned())
    buf.write_char('\n')
  }
  line(header)
  for r in rows {
    line(r)
  }
  buf.to_string()
}

///|
/// Flows grouped by (process, destination, entry, exit), largest first.
pub fn flow_table(
  flows : Array[@ledger.FlowSummary],
  core_present : Bool,
) -> String {
  let groups : Map[
    (String, String, String, String, String),
    (Int64, Int64, Int32),
  ] = Map([])
  let order = []
  for f in flows {
    let dest = if f.domain != "" {
      "\{f.domain}:\{f.target_port}"
    } else {
      f.peer.to_string()
    }
    let k = (
      @ledger.base_name(f.process),
      "\{f.proto} \{dest}",
      entry_label(f.entry, core_present),
      exit_label(f.exit) + (if f.inconsistent { " !" } else { "" }),
      f.rule,
    )
    match groups.get(k) {
      Some((u, d, n)) => groups[k] = (u + f.up, d + f.down, n + 1)
      None => {
        groups[k] = (f.up, f.down, 1)
        order.push(k)
      }
    }
  }
  order.sort_by((a, b) => {
    let (ua, da, _) = groups[a]
    let (ub, db, _) = groups[b]
    (ub + db).compare(ua + da)
  })
  let rows = order.map(k => {
    let (u, d, n) = groups[k]
    [k.0, k.1, k.2, k.3, human_bytes(u), human_bytes(d), n.to_string(), k.4]
  })
  table(
    ["process", "destination", "entry", "exit", "up", "down", "conns", "rule"],
    rows,
  )
}

///|
/// Totals per entry, the unknown-exit share and the reconciliation figures.
pub fn totals_text(t : @ledger.Totals, core_present : Bool) -> String {
  let buf = StringBuilder()
  let mut all = 0L
  for e in [@ledger.Entry::ProxyPort, Tun, Direct, Lan] {
    match t.by_entry.get(e) {
      Some((u, d)) => {
        all += u + d
        buf.write_string(
          "  \{pad(entry_label(e, core_present), 10)} up \{human_bytes(u)}, down \{human_bytes(d)}\n",
        )
      }
      None => ()
    }
  }
  if t.unknown_exit > 0L && all > 0L {
    let pct = t.unknown_exit.to_double() * 100.0 / all.to_double()
    let tenths = (pct * 10.0 + 0.5).to_int64()
    buf.write_string(
      "  exit unknown for \{human_bytes(t.unknown_exit)} (\{tenths / 10L}.\{tenths % 10L}% of traffic)\n",
    )
  }
  if t.core_outbound_up + t.core_outbound_down > 0L {
    buf.write_string(
      "  core outbound (not counted, for reconciliation): up \{human_bytes(t.core_outbound_up)}, down \{human_bytes(t.core_outbound_down)}\n",
    )
  }
  buf.to_string()
}
