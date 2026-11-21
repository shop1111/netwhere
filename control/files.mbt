// config.json and other user-readable files, synchronously (the tray and
// the UI run a Win32 message loop, not the async runtime).

///|
/// A UTF-8 text file, or None when it cannot be read.
pub fn read_text(path : String) -> String? {
  match @sys.read_file(path) {
    Ok(b) => Some(@utf8.decode_lossy(b[:]))
    Err(_) => None
  }
}

///|
/// config.json, or the defaults when it is missing. Raises when it exists
/// but does not parse.
pub fn load_config(dir : String) -> @config.Config raise @config.ConfigError {
  match read_text(dir + "\\config.json") {
    Some(text) => @config.parse(text)
    None => @config.default()
  }
}

///|
/// Writes config.json in place: the user may modify that file but not
/// create files next to it (see installer.acl_commands). The collector
/// reloads it within 5 s and keeps its previous configuration if it ever
/// reads a half-written file.
pub fn save_config(dir : String, c : @config.Config) -> Result[Unit, String] {
  let path = dir + "\\config.json"
  match @sys.write_file_in_place(path, @utf8.encode(c.to_text()[:])) {
    0 => Ok(())
    5 => Err("access denied writing \{path}")
    e => Err("cannot write \{path} (Win32 error \{e})")
  }
}
