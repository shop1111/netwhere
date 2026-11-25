// What the unprivileged programs (CLI, tray, UI) do to the collector:
// read its state, start it, ask it to pause, resume or stop, and turn
// start-at-login on or off. Everything here is synchronous and needs no
// elevation:
//   - start: `schtasks /Run` of the installed on-demand task, which runs it
//     elevated without a UAC prompt (the task belongs to this user);
//   - pause / resume / stop: a request file in the mailbox;
//   - start at login: the tray's value under HKCU\...\Run.

///|
pub let task_name : String = "netwhere"

///|
pub let run_key : String = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

///|
pub let run_value : String = "netwhere"

///|
/// The tray as installed: bin\ in the data directory (admin-only write).
pub fn installed_tray(dir : String) -> String {
  dir + "\\bin\\netwhere-tray.exe"
}

///|
/// The UI window as installed.
pub fn installed_ui(dir : String) -> String {
  dir + "\\bin\\netwhere-ui.exe"
}

///|
fn schtasks() -> String {
  @sys.getenv("SystemRoot").unwrap_or("C:\\Windows") +
  "\\System32\\schtasks.exe"
}

///|
/// False only when the process list is readable and has no netwhered
/// process with this pid; any doubt counts as alive.
pub fn collector_alive(pid : Int32) -> Bool {
  let procs = @sys.process_list()
  procs.length() == 0 ||
  procs.iter().any(p => p.pid == pid && p.exe.to_lower() == "netwhered.exe")
}

///|
/// Collector state from the heartbeat: (running, description).
pub fn collector_state(h : @store.Heartbeat?, now : Int64) -> (Bool, String) {
  match h {
    None => (false, "never started")
    Some(h) => {
      let age = (now - h.updated) / 10_000_000L
      if h.state == "stopped" {
        (false, "stopped")
      } else if !collector_alive(h.pid) {
        // Killed (e.g. the task was ended) before it could say "stopped".
        (false, "not running (process has exited)")
      } else if age > 15L {
        (false, "not running (last heartbeat \{age} s ago)")
      } else {
        (true, h.state)
      }
    }
  }
}

///|
#derive(Eq, Debug)
pub(all) enum Phase {
  /// No ledger: never installed or never ran.
  NotInstalled
  Stopped
  Running
  Paused
}

///|
pub(all) struct Status {
  phase : Phase
  /// collector_state's description.
  detail : String
  heartbeat : @store.Heartbeat?
}

///|
/// The collector's state as the heartbeat in ledger.db tells it.
pub fn status(dir : String) -> Status {
  let db = @store.Db::open_reader(dir + "\\ledger.db") catch {
    _ => return { phase: NotInstalled, detail: "no ledger", heartbeat: None, }
  }
  let h = db.heartbeat() catch { _ => None }
  db.close()
  let (running, detail) = collector_state(h, @sys.now())
  let phase = if !running {
    Stopped
  } else if detail == "paused" {
    Paused
  } else {
    Running
  }
  { phase, detail, heartbeat: h, }
}

///|
/// Is the scheduled task registered?
pub fn installed() -> Bool {
  @sys.run_hidden(schtasks(), ["/Query", "/TN", task_name]) is Ok(0)
}

///|
/// Starts the collector through its scheduled task. A running collector is
/// left alone (the task ignores a second start).
pub fn start() -> Result[Unit, String] {
  match @sys.run_hidden(schtasks(), ["/Run", "/TN", task_name]) {
    Ok(0) => Ok(())
    Ok(code) =>
      Err("schtasks /Run failed (exit \{code}); is netwhere installed?")
    Err(e) => Err("could not run schtasks (Win32 error \{e})")
  }
}

///|
let request_seq : Ref[Int32] = Ref(0)

///|
/// Drops a pause, resume or stop request into the mailbox. Returns its id.
pub fn request(dir : String, kind : @mailbox.Kind) -> Result[String, String] {
  let name = match kind {
    Trace => return Err("trace requests are made by `netwhere trace`")
    Pause => "pause"
    Resume => "resume"
    Stop => "stop"
  }
  request_seq.val += 1
  let id = "\{name}-\{@sys.current_pid()}-\{@sys.now()}-\{request_seq.val}"
  let m : @mailbox.Message = {
    id,
    kind,
    op: Start,
    client_pid: @sys.current_pid(),
    root_pid: 0,
  }
  let path = "\{dir}\\requests\\\{id}.100.json"
  match @sys.write_file_atomic(path, @utf8.encode(m.to_json_text()[:])) {
    0 => Ok(id)
    e => Err("cannot write \{path} (Win32 error \{e})")
  }
}

///|
/// Asks the collector to stop and waits up to `timeout_ms` for its
/// heartbeat to say so. True when it stopped (or was not running).
pub fn stop_and_wait(dir : String, timeout_ms~ : Int32 = 8000) -> Bool {
  if status(dir).phase is (NotInstalled | Stopped) {
    return true
  }
  if request(dir, Stop) is Err(_) {
    return false
  }
  let mut waited = 0
  while waited < timeout_ms {
    @sys.sleep_ms(200)
    waited += 200
    if status(dir).phase is (NotInstalled | Stopped) {
      return true
    }
  }
  false
}

///|
/// The command line the Run value should hold for this tray.
/// At login the tray starts in the background: icon only, no window.
pub fn tray_command(tray_exe : String) -> String {
  @sys.quote_arg(tray_exe) + " --background"
}

///|
/// Start at login: the current Run value, if any.
pub fn autostart_command() -> String? {
  @sys.reg_user_value(run_key, run_value)
}

///|
/// Turns start at login on (the tray at `tray_exe` starts at login and
/// starts the collector) or off (`None`). 0 or a Win32 error.
pub fn set_autostart(tray_exe : String?) -> Int32 {
  match tray_exe {
    Some(exe) => @sys.reg_user_set(run_key, run_value, tray_command(exe))
    None => @sys.reg_user_delete(run_key, run_value)
  }
}
