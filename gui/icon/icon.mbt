// Per-user icon files for the tray and the window (drawing: appicon).

///|
/// %LOCALAPPDATA%\netwhere: per-user files of the tray and the window.
pub fn user_dir() -> String {
  let base = match @sys.getenv("LOCALAPPDATA") {
    Some(d) => d
    None => @sys.getenv("TEMP").unwrap_or(".")
  }
  ignore(@sys.make_dir(base + "\\netwhere"))
  base + "\\netwhere"
}

///|
/// Writes the three state icons into user_dir() and returns their paths
/// by state ("running", "paused", "stopped").
pub fn write_icons() -> Map[String, String] {
  let base = user_dir()
  let out = Map([])
  for state in ["running", "paused", "stopped"] {
    let path = base + "\\tray-" + state + ".ico"
    if @sys.write_file_atomic(path, @appicon.icon_file(state)) == 0 {
      out[state] = path
    }
  }
  out
}
