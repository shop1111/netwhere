// `netwhere verify MANIFEST`: check a scenario recording against the known
// outcomes written by scripts/record-scenarios.ps1.

///|
async fn cmd_verify(args : ArrayView[String]) -> Int32 {
  guard args is [path] else {
    println("usage: netwhere verify MANIFEST")
    return 2
  }
  let dir = match path.rev_find("\\") {
    Some(i) => path[:i + 1].to_owned()
    None =>
      match path.rev_find("/") {
        Some(i) => path[:i + 1].to_owned()
        None => ""
      }
  }
  let results = try {
    let m = @scenario.parse_manifest(@fs.read_file(path).text())
    let rec = @ledger.parse_recording(@fs.read_file(dir + m.recording).text())
    @scenario.check(m, rec)
  } catch {
    e => {
      println("verify: \{e}")
      return 1
    }
  }
  println(@scenario.outcome_text(results))
  if results.iter().any(r => r.1 is Fail(_)) {
    1
  } else {
    0
  }
}
