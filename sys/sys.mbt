// Process, token and clock helpers (Win32).

///|
extern "c" fn nw_image_path(pid : Int32) -> String = "nw_image_path"

///|
extern "c" fn nw_is_elevated() -> Int32 = "nw_is_elevated"

///|
extern "c" fn nw_process_elevated(pid : Int32) -> Int32 = "nw_process_elevated"

///|
extern "c" fn nw_process_user_sid(pid : Int32) -> String = "nw_process_user_sid"

///|
extern "c" fn nw_process_create_time(pid : Int32) -> Int64 = "nw_process_create_time"

///|
extern "c" fn nw_current_pid() -> Int32 = "nw_current_pid"

///|
extern "c" fn nw_now_filetime() -> Int64 = "nw_now_filetime"

///|
extern "c" fn nw_utc_offset_minutes() -> Int32 = "nw_utc_offset_minutes"

///|
extern "c" fn nw_sleep_ms(ms : Int32) = "nw_sleep_ms"

///|
#borrow(out)
extern "c" fn nw_self_usage(out : FixedArray[Int64]) = "nw_self_usage"

///|
#borrow(cmdline)
extern "c" fn nw_spawn_suspended(cmdline : String) -> Int32 = "nw_spawn_suspended"

///|
extern "c" fn nw_resume_child() -> Int32 = "nw_resume_child"

///|
extern "c" fn nw_kill_child() = "nw_kill_child"

///|
extern "c" fn nw_child_wait(ms : Int32) -> Int32 = "nw_child_wait"

///|
extern "c" fn nw_child_exit_code() -> Int32 = "nw_child_exit_code"

///|
extern "c" fn nw_command_line() -> String = "nw_command_line"

///|
#borrow(name)
extern "c" fn nw_getenv(name : String) -> String = "nw_getenv"

///|
/// Drive-letter image path of a running process; None when it cannot be
/// opened (exited, or protected).
pub fn image_path(pid : Int32) -> String? {
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
pub fn process_elevated(pid : Int32) -> Bool? {
  match nw_process_elevated(pid) {
    1 => Some(true)
    0 => Some(false)
    _ => None
  }
}

///|
/// String SID of a process owner; None when unavailable.
pub fn process_user_sid(pid : Int32) -> String? {
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
pub fn process_create_time(pid : Int32) -> Int64? {
  match nw_process_create_time(pid) {
    0L => None
    t => Some(t)
  }
}

///|
pub fn current_pid() -> Int32 {
  nw_current_pid()
}

///|
/// UTC now, in FILETIME ticks.
pub fn now() -> Int64 {
  nw_now_filetime()
}

///|
pub fn utc_offset_minutes() -> Int32 {
  nw_utc_offset_minutes()
}

///|
pub fn sleep_ms(ms : Int32) -> Unit {
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
  {
    cpu_ms: a[0],
    private_bytes: a[1],
    working_set: a[2],
    peak_working_set: a[3],
  }
}

///|
#derive(Debug)
pub(all) suberror SpawnError {
  SpawnError(code~ : Int32)
}

///|
pub impl Show for SpawnError with fn output(self, logger) {
  let SpawnError(code~) = self
  logger.write_string("CreateProcess failed with Win32 error \{code}")
}

///|
/// Starts a command line suspended, inheriting this process's environment
/// and console. Returns its pid; call `resume_child` to let it run.
pub fn spawn_suspended(cmdline : String) -> Int32 raise SpawnError {
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
pub fn child_wait(ms : Int32) -> Bool {
  nw_child_wait(ms) == 0
}

///|
pub fn child_exit_code() -> Int32 {
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

///|
extern "c" fn nw_exit(code : Int32) = "nw_exit"

///|
/// Flushes standard output and ends the process with `code`.
pub fn exit(code : Int32) -> Unit {
  nw_exit(code)
}

///|
#borrow(out)
extern "c" fn nw_process_list(out : FixedArray[Byte], cap : Int32) -> Int32 = "nw_process_list"

///|
/// One running process (Toolhelp snapshot; needs no access to the process).
#derive(Eq, Debug)
pub(all) struct ProcessEntry {
  pid : Int32
  ppid : Int32
  /// Executable file name, e.g. "curl.exe".
  exe : String
}

///|
pub fn process_list() -> Array[ProcessEntry] {
  let mut cap = 256 * 1024
  for _ in 0..<5 {
    let b = FixedArray::make(cap, b'\x00')
    let n = nw_process_list(b, cap)
    if n == -122 {
      cap *= 4
      continue
    }
    if n < 4 {
      return []
    }
    let u32 = fn(i : Int32) {
      b[i].to_int() |
      (b[i + 1].to_int() << 8) |
      (b[i + 2].to_int() << 16) |
      (b[i + 3].to_int() << 24)
    }
    let count = u32(0)
    let out = []
    let mut p = 4
    for _ in 0..<count {
      let pid = u32(p)
      let ppid = u32(p + 4)
      let len = b[p + 8].to_int() | (b[p + 9].to_int() << 8)
      let bytes = Bytes::makei(len, k => b[p + 10 + k])
      out.push({ pid, ppid, exe: @utf8.decode_lossy(bytes), })
      p += 10 + len
    }
    return out
  }
  []
}

///|
/// Best available name for a process: full image path when the process can
/// be opened, else the executable name from a snapshot.
pub fn process_name(
  pid : Int32,
  snapshot~ : Array[ProcessEntry] = [],
) -> String? {
  match image_path(pid) {
    Some(p) => Some(p)
    None => {
      let list = if snapshot.length() > 0 { snapshot } else { process_list() }
      for e in list {
        if e.pid == pid {
          return Some(e.exe)
        }
      }
      None
    }
  }
}

///|
/// netwhere's data directory: %ProgramData%\netwhere.
pub fn data_dir() -> String {
  match getenv("ProgramData") {
    Some(p) => p + "\\netwhere"
    None => "C:\\ProgramData\\netwhere"
  }
}

///|
#borrow(file, params)
extern "c" fn nw_run_elevated(file : String, params : String) -> Int32 = "nw_run_elevated"

///|
#borrow(cmdline)
extern "c" fn nw_run_wait(cmdline : String) -> Int32 = "nw_run_wait"

///|
extern "c" fn nw_detach_console() = "nw_detach_console"

///|
/// Runs `file params` elevated through UAC and waits. Ok(exit code), or
/// Err(Win32 error) when it did not start (1223: the user declined).
pub fn run_elevated(file : String, params : String) -> Result[Int32, Int32] {
  let r = nw_run_elevated(file, params)
  if r < 0 {
    Err(-r)
  } else {
    Ok(r)
  }
}

///|
/// Runs a program with arguments in this console and waits for it.
pub fn run_wait(program : String, args : Array[String]) -> Result[Int32, Int32] {
  let line = join_command_line([program, ..args][:])
  let r = nw_run_wait(line)
  if r < 0 {
    Err(-r)
  } else {
    Ok(r)
  }
}

///|
pub fn detach_console() -> Unit {
  nw_detach_console()
}

///|
#borrow(subkey, name)
extern "c" fn nw_reg_user_value(subkey : String, name : String) -> String = "nw_reg_user_value"

///|
/// A value under HKEY_CURRENT_USER\<subkey> as text (DWORDs in decimal);
/// None when missing.
pub fn reg_user_value(subkey : String, name : String) -> String? {
  match nw_reg_user_value(subkey, name) {
    "" => None
    v => Some(v)
  }
}
