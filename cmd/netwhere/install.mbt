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
async fn elevate(dir : String, verb : String, extra : Array[String]) -> Int32 {
  let exe = own_dir() + "\\netwhered.exe"
  if !@fs.exists(exe) {
    println("\{verb}: netwhered.exe not found next to netwhere.exe (\{exe})")
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
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("install: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  let code = elevate(dir, "install", ["--owner-sid", @sys.current_user_sid()])
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
