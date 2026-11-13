// `netwhere install` / `netwhere uninstall`: start the elevated half
// (netwhered.exe next to this program) through one UAC prompt.

///|
fn own_dir() -> String {
  let path = @sys.image_path(@sys.current_pid()).unwrap_or("")
  match path.rev_find("\\") {
    Some(i) => path[:i].to_owned()
    None => "."
  }
}

///|
/// Built-in rules: builtin-rules.txt next to this program (release
/// package), else rules\builtin.txt in an enclosing source tree.
async fn find_rules() -> String? {
  let next = own_dir() + "\\builtin-rules.txt"
  if @fs.exists(next) {
    return Some(next)
  }
  let mut dir = own_dir()
  for _ in 0..<8 {
    let candidate = dir + "\\rules\\builtin.txt"
    if @fs.exists(candidate) {
      return Some(@fs.realpath(candidate))
    }
    match dir.rev_find("\\") {
      Some(i) => dir = dir[:i].to_owned()
      None => break
    }
  }
  None
}

///|
async fn elevate(dir : String, verb : String, extra : Array[String]) -> Int32 {
  // Release packages ship both programs side by side; in a moon build tree
  // each executable has its own directory.
  let candidates = [
    own_dir() + "\\netwhered.exe",
    own_dir() + "\\..\\netwhered\\netwhered.exe",
  ]
  let mut found = ""
  for c in candidates {
    if found == "" && @fs.exists(c) {
      found = c
    }
  }
  if found == "" {
    println(
      "\{verb}: netwhered.exe not found next to netwhere.exe (\{candidates[0]})",
    )
    return 2
  }
  let exe = @fs.realpath(found)
  let params = @sys.join_command_line([verb, "--data-dir", dir, ..extra][:])
  println("\{verb}: approve the UAC prompt to continue")
  let code = match @sys.run_elevated(exe, params) {
    Ok(c) => c
    Err(1223) => {
      println("\{verb}: cancelled at the UAC prompt")
      return 1
    }
    Err(e) => {
      println("\{verb}: could not start netwhered (Win32 error \{e})")
      return 1
    }
  }
  let log = dir + "\\install.log"
  if @fs.exists(log) {
    println(@fs.read_file(log).text().trim_end()) catch {
      _ => ()
    }
  }
  code
}

///|
async fn cmd_install(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("install: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  let extra = ["--owner-sid", @sys.current_user_sid()]
  match find_rules() {
    Some(r) => {
      extra.push("--rules")
      extra.push(r)
    }
    None => ()
  }
  let code = elevate(dir, "install", extra)
  if code == 0 {
    // Give the task a moment to start, then show what it reports.
    @async.sleep(4000)
    println("")
    ignore(cmd_status(["--data-dir", dir][:]))
  }
  code
}

///|
async fn cmd_uninstall(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=["--purge"]) catch {
    e => {
      println("uninstall: \{e}")
      return 2
    }
  }
  elevate(
    data_dir_of(a),
    "uninstall",
    if a.has("--purge") {
      ["--purge"]
    } else {
      []
    },
  )
}
