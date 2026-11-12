// Process, token and clock helpers (Win32).

///|
extern "c" fn nw_image_path(pid : Int) -> String = "nw_image_path"

///|
extern "c" fn nw_is_elevated() -> Int = "nw_is_elevated"

///|
extern "c" fn nw_process_elevated(pid : Int) -> Int = "nw_process_elevated"

///|
extern "c" fn nw_process_user_sid(pid : Int) -> String = "nw_process_user_sid"

///|
extern "c" fn nw_process_create_time(pid : Int) -> Int64 = "nw_process_create_time"

///|
extern "c" fn nw_current_pid() -> Int = "nw_current_pid"

///|
extern "c" fn nw_now_filetime() -> Int64 = "nw_now_filetime"

///|
extern "c" fn nw_utc_offset_minutes() -> Int = "nw_utc_offset_minutes"

///|
extern "c" fn nw_sleep_ms(ms : Int) = "nw_sleep_ms"

///|
#borrow(out)
extern "c" fn nw_self_usage(out : FixedArray[Int64]) = "nw_self_usage"

///|
#borrow(cmdline)
extern "c" fn nw_spawn_suspended(cmdline : String) -> Int = "nw_spawn_suspended"

///|
extern "c" fn nw_resume_child() -> Int = "nw_resume_child"

///|
extern "c" fn nw_kill_child() = "nw_kill_child"

///|
extern "c" fn nw_child_wait(ms : Int) -> Int = "nw_child_wait"

///|
extern "c" fn nw_child_exit_code() -> Int = "nw_child_exit_code"

///|
extern "c" fn nw_command_line() -> String = "nw_command_line"

///|
#borrow(name)
extern "c" fn nw_getenv(name : String) -> String = "nw_getenv"

///|
/// Drive-letter image path of a running process; None when it cannot be
/// opened (exited, or protected).
pub fn image_path(pid : Int) -> String? {
  match nw_image_path(pid) {
    "" => None
    p => Some(p)
  }
}

///|
pub fn is_elevated() -> Bool {
  nw_is_elevated() == 1
}

///|
/// Some(true/false), or None when the process or its token cannot be opened.
pub fn process_elevated(pid : Int) -> Bool? {
  match nw_process_elevated(pid) {
    1 => Some(true)
    0 => Some(false)
    _ => None
  }
}

///|
/// String SID of a process owner; None when unavailable.
pub fn process_user_sid(pid : Int) -> String? {
  match nw_process_user_sid(pid) {
    "" => None
    s => Some(s)
  }
}

///|
pub fn current_user_sid() -> String {
  nw_process_user_sid(0)
}

///|
/// Creation time (FILETIME ticks) of a running process.
pub fn process_create_time(pid : Int) -> Int64? {
  match nw_process_create_time(pid) {
    0L => None
    t => Some(t)
  }
}

///|
pub fn current_pid() -> Int {
  nw_current_pid()
}

///|
/// UTC now, in FILETIME ticks.
pub fn now() -> Int64 {
  nw_now_filetime()
}

///|
pub fn utc_offset_minutes() -> Int {
  nw_utc_offset_minutes()
}

///|
pub fn sleep_ms(ms : Int) -> Unit {
  nw_sleep_ms(ms)
}

///|
#derive(Debug)
pub(all) struct Usage {
  cpu_ms : Int64
  private_bytes : Int64
  working_set : Int64
  peak_working_set : Int64
}

///|
pub fn self_usage() -> Usage {
  let a = FixedArray::make(4, 0L)
  nw_self_usage(a)
  { cpu_ms: a[0], private_bytes: a[1], working_set: a[2], peak_working_set: a[3] }
}

///|
#derive(Debug)
pub(all) suberror SpawnError {
  SpawnError(code~ : Int)
}

///|
pub impl Show for SpawnError with output(self, logger) {
  let SpawnError(code~) = self
  logger.write_string("CreateProcess failed with Win32 error \{code}")
}

///|
/// Starts a command line suspended, inheriting this process's environment
/// and console. Returns its pid; call `resume_child` to let it run.
pub fn spawn_suspended(cmdline : String) -> Int raise SpawnError {
  let r = nw_spawn_suspended(cmdline)
  if r < 0 {
    raise SpawnError(code=-r)
  }
  r
}

///|
pub fn resume_child() -> Bool {
  nw_resume_child() == 0
}

///|
pub fn kill_child() -> Unit {
  nw_kill_child()
}

///|
/// Waits up to `ms`; true when the child has exited.
pub fn child_wait(ms : Int) -> Bool {
  nw_child_wait(ms) == 0
}

///|
pub fn child_exit_code() -> Int {
  nw_child_exit_code()
}

///|
/// This process's raw command line.
pub fn command_line() -> String {
  nw_command_line()
}

///|
pub fn getenv(name : String) -> String? {
  match nw_getenv(name) {
    "" => None
    v => Some(v)
  }
}

///|
/// Quotes one argument for CreateProcess / CommandLineToArgvW parsing.
pub fn quote_arg(a : String) -> String {
  if a.length() > 0 &&
    !a.contains(" ") &&
    !a.contains("\t") &&
    !a.contains("\"") {
    return a
  }
  let buf = StringBuilder()
  buf.write_char('"')
  let mut backslashes = 0
  for c in a {
    if c == '\\' {
      backslashes += 1
      continue
    }
    if c == '"' {
      for _ in 0..<(backslashes * 2 + 1) {
        buf.write_char('\\')
      }
    } else {
      for _ in 0..<backslashes {
        buf.write_char('\\')
      }
    }
    backslashes = 0
    buf.write_char(c)
  }
  for _ in 0..<(backslashes * 2) {
    buf.write_char('\\')
  }
  buf.write_char('"')
  buf.to_string()
}

///|
/// Joins arguments into one command line.
pub fn join_command_line(args : ArrayView[String]) -> String {
  args.iter().map(quote_arg).collect().join(" ")
}
