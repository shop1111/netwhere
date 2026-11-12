// netwhere: unprivileged command-line client.

///|
let usage : String =
  #|netwhere: where does this machine's traffic go?
  #|
  #|usage:
  #|  netwhere replay FILE [--pid N] [--expect]   analyse a recording
  #|  netwhere verify MANIFEST                    check recorded scenarios
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
