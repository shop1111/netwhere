// The Start menu entry: %APPDATA%\Microsoft\Windows\Start Menu\Programs\
// netwhere.lnk, pointing at the installed tray. Starting the tray starts
// collection; starting it again while it runs opens the window, so the one
// entry serves both.

///|
/// The installed icon, written by the elevated installer.
pub fn installed_icon(dir : String) -> String {
  dir + "\\bin\\netwhere.ico"
}

///|
/// The shortcut's path, or None without %APPDATA%.
pub fn start_menu_shortcut() -> String? {
  match @sys.getenv("APPDATA") {
    Some(a) =>
      Some(a + "\\Microsoft\\Windows\\Start Menu\\Programs\\netwhere.lnk")
    None => None
  }
}

///|
/// Creates the Start menu entry for the installed tray.
pub fn create_start_menu_entry(dir : String) -> Result[String, String] {
  guard start_menu_shortcut() is Some(lnk) else {
    return Err("APPDATA is not set")
  }
  let icon = installed_icon(dir)
  match
    @sys.create_shortcut(
      lnk,
      installed_tray(dir),
      icon=if @sys.file_exists(icon) { icon } else { "" },
      description="netwhere：本机流量走向（打开即开始采集）",
    ) {
    0 => Ok(lnk)
    hr => Err("cannot create \{lnk} (HRESULT \{hr})")
  }
}

///|
/// Removes the Start menu entry; a missing one is fine.
pub fn remove_start_menu_entry() -> Bool {
  match start_menu_shortcut() {
    Some(lnk) => @sys.delete_file(lnk) == 0
    None => true
  }
}
