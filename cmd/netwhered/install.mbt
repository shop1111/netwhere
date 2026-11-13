// `netwhered install` / `netwhered uninstall`: the elevated half of
// `netwhere install`. Everything printed is also written to install.log in
// the data directory, because the elevated console closes when done.

///|
priv struct Out {
  buf : StringBuilder
}

///|
fn Out::say(self : Out, s : String) -> Unit {
  println(s)
  self.buf.write_string(s + "\n")
}

///|
fn system32() -> String {
  @sys.getenv("SystemRoot").unwrap_or("C:\\Windows") + "\\System32"
}

///|
fn parent_dir(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[:i].to_owned()
    None => "."
  }
}

///|
fn Out::run(self : Out, c : @installer.Command) -> Bool {
  match @sys.run_wait(c.program, c.args) {
    Ok(0) => true
    Ok(code) => {
      self.say(
        "  failed (exit \{code}): \{@ledger.base_name(c.program)} \{c.args.join(" ")}",
      )
      false
    }
    Err(e) => {
      self.say("  could not run \{c.program}: Win32 error \{e}")
      false
    }
  }
}

///|
async fn copy_file(from : String, to : String) -> Unit {
  let data = @fs.read_file(from).binary()
  let tmp = to + ".new"
  @fs.write_file(tmp, data)
  @fs.rename(tmp, to, replace=true)
}

///|
async fn cmd_install(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(
    args,
    with_value=["--owner-sid", "--data-dir", "--source", "--rules"],
    switches=[],
  ) catch {
    e => {
      println("install: \{e}")
      return 2
    }
  }
  let dir = a.get("--data-dir", default_data_dir())
  let out : Out = { buf: StringBuilder(), }
  let finish = async fn(code : Int32) -> Int32 {
    @fs.write_file(dir + "\\install.log", out.buf.to_string()) catch {
      _ => ()
    }
    code
  }
  if !@sys.is_elevated() {
    println("install: must run elevated (use `netwhere install`)")
    return 2
  }
  let sid = a.get("--owner-sid", "")
  if !@installer.valid_user_sid(sid) {
    println("install: --owner-sid must be the installing user's SID")
    return 2
  }
  let source = a.get(
    "--source",
    parent_dir(@sys.image_path(@sys.current_pid()).unwrap_or("")),
  )
  let schtasks = system32() + "\\schtasks.exe"
  let icacls = system32() + "\\icacls.exe"
  out.say("installing netwhere into \{dir}")
  // A running collector holds the binary open: stop the task first.
  ignore(@sys.run_wait(schtasks, ["/End", "/TN", @installer.task_name]))
  try {
    @fs.mkdir(dir + "\\bin", recursive=true, allow_exist=true)
    @fs.mkdir(dir + "\\requests", recursive=true, allow_exist=true)
    if !@fs.exists(dir + "\\config.json") {
      @fs.write_file(dir + "\\config.json", @config.default().to_text())
    }
    @fs.write_file(dir + "\\owner.sid", sid)
    let exe = dir + "\\bin\\netwhered.exe"
    // The task may need a moment to release the old binary.
    let mut copied = false
    for attempt in 0..<10 {
      if !copied {
        copy_file(source + "\\netwhered.exe", exe) catch {
          e =>
            if attempt == 9 {
              raise e
            } else {
              @async.sleep(500)
              continue
            }
        }
        copied = true
      }
    }
    out.say("  collector: \{exe}")
    let rules = a.get("--rules", source + "\\builtin-rules.txt")
    if @fs.exists(rules) {
      copy_file(rules, dir + "\\builtin-rules.txt")
      out.say("  built-in rules: copied from \{rules}")
    } else {
      out.say("  built-in rules: none found next to netwhered.exe")
    }
    out.say(
      "  permissions: user may read everything, write only requests\\ and config.json",
    )
    for c in @installer.acl_commands(icacls, dir, sid) {
      if !out.run(c) {
        return finish(1)
      }
    }
    let xml_path = dir + "\\task.xml"
    @fs.write_file(
      xml_path,
      @installer.utf16le_bom(@installer.task_xml(sid, exe)),
    )
    out.say(
      "  scheduled task \"\{@installer.task_name}\": at logon, highest privileges",
    )
    for c in @installer.register_commands(schtasks, xml_path) {
      if !out.run(c) {
        return finish(1)
      }
    }
  } catch {
    e => {
      out.say("install failed: \{e}")
      return finish(1)
    }
  }
  out.say("installed; the collector is starting")
  finish(0)
}

///|
async fn cmd_uninstall(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=["--purge"]) catch {
    e => {
      println("uninstall: \{e}")
      return 2
    }
  }
  if !@sys.is_elevated() {
    println("uninstall: must run elevated (use `netwhere uninstall`)")
    return 2
  }
  let dir = a.get("--data-dir", default_data_dir())
  let schtasks = system32() + "\\schtasks.exe"
  let out : Out = { buf: StringBuilder(), }
  for c in @installer.unregister_commands(schtasks) {
    ignore(out.run(c))
  }
  // A collector killed by /End leaves its ETW session behind.
  let session = session_name(dir)
  if @etw.session_exists(session) {
    ignore(@etw.stop_session(session))
    out.say("stopped the ETW session")
  }
  if a.has("--purge") {
    @fs.rmdir(dir, recursive=true, allow_missing=true) catch {
      e => {
        out.say("could not remove \{dir}: \{e}")
        return 1
      }
    }
    println("removed \{dir}")
  } else {
    out.say("uninstalled; data kept in \{dir} (use --purge to delete it)")
    @fs.write_file(dir + "\\install.log", out.buf.to_string()) catch {
      _ => ()
    }
  }
  0
}
