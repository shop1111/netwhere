// netwhere: unprivileged command-line client.

///|
let usage : String =
  #|netwhere: where does this machine's traffic go?
  #|
  #|usage:
  #|  netwhere status                         collector, proxy core, mode
  #|  netwhere trace -- COMMAND [ARGS...]      run a command, report where its traffic went
  #|  netwhere report [--today|--7d|--30d|--hours N] [--by app|domain|node|process|entry]
  #|                  [--app X] [--route ENTRY] [--limit N]
  #|  netwhere unknown                        unclassified traffic, largest first
  #|  netwhere classify <domain|process.exe> <app>
  #|  netwhere rules list | add --app A [--process P] [--domain D] | remove N
  #|  netwhere export --csv [period] [--out FILE]
  #|  netwhere install | uninstall [--purge]  register the collector (one UAC prompt)
  #|  netwhere replay FILE [--pid N] [--expect]   analyse a recording
  #|  netwhere verify MANIFEST                    check recorded scenarios
  #|
  #|All commands accept --data-dir DIR (default %ProgramData%\netwhere).
  #|
  #|Run `netwhered record` (elevated) to make a recording.

///|
async fn main {
  @signal.set_global_cancellation_signals([SIGINT, SIGBREAK])
  let args = @env.args()
  let code = if args.length() < 2 {
    println(usage)
    2
  } else {
    match args[1] {
      "status" => cmd_status(args[2:])
      "trace" => cmd_trace(args[2:])
      "report" => cmd_report(args[2:])
      "unknown" => cmd_unknown(args[2:])
      "export" => cmd_export(args[2:])
      "classify" => cmd_classify(args[2:])
      "rules" => cmd_rules(args[2:])
      "install" => cmd_install(args[2:])
      "uninstall" => cmd_uninstall(args[2:])
      "replay" => cmd_replay(args[2:])
      "verify" => cmd_verify(args[2:])
      "help" | "--help" | "-h" => {
        println(usage)
        0
      }
      other => {
        println("unknown command: \{other}\n")
        println(usage)
        2
      }
    }
  }
  @sys.exit(code)
}
