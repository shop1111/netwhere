// netwhered: the elevated collector.

///|
let usage : String =
  #|usage:
  #|  netwhered record --out FILE [--secs N] [--controller HOST:PORT] [--secret S]
  #|                   [--decoder shadow|fast|tdh] [--snapshot-ms N] [--note TEXT]
  #|
  #|  record   write an NDJSON recording of ETW events, Mihomo snapshots and
  #|           log lines and route facts (Ctrl+C stops; --secs 0 = until Ctrl+C)

///|
async fn cmd_record(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(
    args,
    with_value=[
      "--out", "--secs", "--controller", "--secret", "--decoder", "--snapshot-ms",
      "--note",
    ],
    switches=[],
  ) catch {
    e => {
      println("record: \{e}\n\n\{usage}")
      return 2
    }
  }
  let decoder : @etw.Decoder = match a.get("--decoder", "shadow") {
    "shadow" => Shadow
    "fast" => Fast
    "tdh" => Tdh
    other => {
      println("record: unknown decoder \{other}")
      return 2
    }
  }
  guard a.options.get("--out") is Some(out) else {
    println("record: --out is required\n\n\{usage}")
    return 2
  }
  let (secs, snapshot_ms) = (a.int("--secs", 60), a.int("--snapshot-ms", 500)) catch {
    e => {
      println("record: \{e}")
      return 2
    }
  }
  record({
    out,
    secs,
    controller: a.get("--controller", "127.0.0.1:9090"),
    secret: a.get("--secret", ""),
    decoder,
    snapshot_ms,
    note: a.get("--note", ""),
  })
}

///|
async fn main {
  @signal.set_global_cancellation_signals([SIGINT, SIGBREAK])
  let args = @env.args()
  let code = if args.length() < 2 {
    println(usage)
    2
  } else {
    match args[1] {
      "record" => cmd_record(args[2:])
      _ => {
        println(usage)
        2
      }
    }
  }
  @sys.exit(code)
}
