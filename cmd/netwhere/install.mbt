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
  // A moon workspace build puts this program in
  // _build\native\release\build\shop1111\netwhere\cmd\netwhere, nine levels
  // below the source tree.
  for _ in 0..<12 {
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
/// One of the other programs: next to this one (release package), or in
/// its own directory in a moon build tree (build\shop1111\netwhere\cmd\X
/// for this module, build\shop1111\netwhere-gui\X for the gui module).
async fn find_program(name : String) -> String? {
  let candidates = [
    own_dir() + "\\" + name + ".exe",
    own_dir() + "\\..\\" + name + "\\" + name + ".exe",
    own_dir() + "\\..\\..\\..\\netwhere-gui\\" + name + "\\" + name + ".exe",
  ]
  for c in candidates {
    if @fs.exists(c) {
      return Some(@fs.realpath(c))
    }
  }
  None
}

///|
async fn elevate(dir : String, verb : String, extra : Array[String]) -> Int32 {
  guard find_program("netwhered") is Some(exe) else {
    println(
      "\{verb}: netwhered.exe not found next to netwhere.exe (\{own_dir()})",
    )
    return 2
  }
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
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[
    "--no-autostart",
  ]) catch {
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
  for gui in [("netwhere-tray", "--tray"), ("netwhere-ui", "--ui")] {
    if find_program(gui.0) is Some(path) {
      extra.push(gui.1)
      extra.push(path)
    }
  }
  // Stop a running collector cleanly first, so its ETW session goes too.
  ignore(@control.stop_and_wait(dir))
  let code = elevate(dir, "install", extra)
  let tray = @control.installed_tray(dir)
  if code == 0 && @fs.exists(tray) {
    if a.has("--no-autostart") {
      ignore(@control.set_autostart(None))
      println("start at login: off (turn on with `netwhere autostart on`)")
    } else if @control.set_autostart(Some(tray)) == 0 {
      println(
        "start at login: on (tray icon; turn off in its menu or with `netwhere autostart off`)",
      )
    }
    match @control.create_start_menu_entry(dir) {
      Ok(_) =>
        println(
          "Start menu: netwhere (opens the tray, or the window when the tray runs)",
        )
      Err(e) => println("Start menu: \{e}")
    }
    ignore(@sys.spawn_detached(tray, ["--background"]))
  }
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
  let dir = data_dir_of(a)
  ignore(@control.stop_and_wait(dir))
  if @control.autostart_command() is Some(_) {
    ignore(@control.set_autostart(None))
    println("start at login: removed")
  }
  if @control.start_menu_shortcut() is Some(lnk) && @fs.exists(lnk) {
    ignore(@control.remove_start_menu_entry())
    println("Start menu: removed")
  }
  elevate(dir, "uninstall", if a.has("--purge") { ["--purge"] } else { [] })
}
