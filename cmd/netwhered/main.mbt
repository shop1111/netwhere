// netwhered: the elevated collector.

///|
let usage : String =
  #|usage:
  #|  netwhered run [--data-dir DIR] [--secs N] [--decoder fast|shadow|tdh]
  #|  netwhered record --out FILE [--secs N] [--controller HOST:PORT] [--secret S]
  #|                   [--decoder shadow|fast|tdh] [--snapshot-ms N] [--note TEXT]
  #|                   [--stop-file PATH] [--ready-file PATH]
  #|
  #|  run      the collector (normally started at logon by a scheduled task);
  #|           data in %ProgramData%\netwhere unless --data-dir is given
  #|  record   write an NDJSON recording of ETW events, Mihomo snapshots and
  #|           log lines and route facts (Ctrl+C stops; --secs 0 = until Ctrl+C)

///|
async fn cmd_record(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(
    args,
    with_value=[
      "--out", "--secs", "--controller", "--secret", "--decoder", "--snapshot-ms",
      "--note", "--stop-file", "--ready-file",
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
    stop_file: a.get("--stop-file", ""),
    ready_file: a.get("--ready-file", ""),
  })
}

///|
async fn cmd_run(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir", "--secs", "--decoder"], switches=[
    "--detach",
  ]) catch {
    e => {
      println("run: \{e}")
      return 2
    }
  }
  // fast: two shadow recordings (2026-11-13) compared 103,671 fields with
  // no mismatch against TDH (PLAN 1.1).
  let decoder : @etw.Decoder = match a.get("--decoder", "fast") {
    "shadow" => Shadow
    "fast" => Fast
    "tdh" => Tdh
    other => {
      println("run: unknown decoder \{other}")
      return 2
    }
  }
  let secs = a.int("--secs", 0) catch {
    e => {
      println("run: \{e}")
      return 2
    }
  }
  if a.has("--detach") {
    // Started by the scheduled task: no console window.
    @sys.detach_console()
  }
  run_collector({
    data_dir: a.get("--data-dir", default_data_dir()),
    secs,
    decoder,
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
      "run" => cmd_run(args[2:])
      "install" => cmd_install(args[2:])
      "uninstall" => cmd_uninstall(args[2:])
      _ => {
        println(usage)
        2
      }
    }
  }
  @sys.exit(code)
}
