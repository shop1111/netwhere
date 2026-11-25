// netwhere-tray: the notification-area icon. Runs unprivileged.
//
// Starting the tray starts collection (the collector's on-demand task);
// quitting it stops collection. "Start at login" is the tray's own HKCU Run
// value. Every 5 s it reads the heartbeat and today's totals from
// ledger.db; it never writes there.
//
// usage: netwhere-tray.exe [--data-dir DIR] [--no-start] [--background]
//   --background  icon only (start at login, after install); without it, as
//                 from the Start menu, the window opens too

///|
extern "C" fn single_instance() -> Int32 = "nwt_single_instance"

///|
extern "C" fn host_create(timer_ms : Int32) -> Int32 = "nwt_host_create"

///|
extern "C" fn take_pending() -> Int32 = "nwt_take_pending"

///|
extern "C" fn allow_foreground() -> Unit = "nwt_allow_foreground"

///|
extern "C" fn close_ui() -> Int32 = "nwt_close_ui"

///|
#borrow(text)
extern "C" fn message_box(text : String) -> Unit = "nwt_message_box"

///|
let refresh_ms : Int32 = 5000

///|
fn own_path() -> String {
  @sys.image_path(@sys.current_pid()).unwrap_or("netwhere-tray.exe")
}

///|
fn dir_of(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[:i].to_owned()
    None => "."
  }
}

///|
/// The UI program: next to the tray (installed, release package) or in its
/// own directory beside the tray's (moon build tree).
fn ui_program() -> String? {
  let here = dir_of(own_path())
  for
    c in [
      here + "\\netwhere-ui.exe",
      here + "\\..\\netwhere-ui\\netwhere-ui.exe",
    ] {
    if @sys.file_exists(c) {
      return Some(c)
    }
  }
  None
}

///|
/// What the menu and tooltip show.
priv struct View {
  phase : @control.Phase
  degraded : Bool
  up : Int64
  down : Int64
  via_node : Int64
  bypass : Int64
  autostart : Bool
}

///|
fn read_view(dir : String) -> View {
  let st = @control.status(dir)
  let mut up = 0L
  let mut down = 0L
  let mut via_node = 0L
  let mut bypass = 0L
  if st.phase != NotInstalled {
    let p = @query.today(@sys.now(), @sys.utc_offset_minutes())
    let rows = try {
      let db = @store.Db::open_reader(dir + "\\ledger.db")
      let rows = db.usage_between(p.from, p.to) catch { _ => [] }
      db.close()
      rows
    } catch {
      _ => []
    }
    let t = @query.totals(rows, _ => 1.0)
    up = t.up
    down = t.down
    via_node = t.split.via_node
    bypass = t.split.bypass
  }
  {
    phase: st.phase,
    degraded: st.heartbeat is Some(h) && h.degraded,
    up,
    down,
    via_node,
    bypass,
    autostart: @control.autostart_command() is Some(_),
  }
}

///|
fn phase_text(v : View) -> String {
  match v.phase {
    NotInstalled => "未安装（运行 netwhere install）"
    Stopped => "已停止"
    Paused => "已暂停"
    Running =>
      if v.degraded {
        "运行中（未提权，直连流量不完整）"
      } else {
        "运行中"
      }
  }
}

///|
fn icon_state(v : View) -> String {
  match v.phase {
    Running => "running"
    Paused => "paused"
    _ => "stopped"
  }
}

///|
fn tooltip(v : View) -> String {
  let h = @report.human_bytes
  let t = "netwhere · \{phase_text(v)}\n今日 ↓\{h(v.down)} ↑\{h(v.up)}\n经节点 \{h(v.via_node)} · 绕过 \{h(v.bypass)}"
  // The notification area keeps at most 127 characters.
  if t.length() > 127 {
    t[:127].to_owned()
  } else {
    t
  }
}

///|
fn menu(v : View) -> Array[@tray.TrayMenuItem] {
  let h = @report.human_bytes
  let collect = match v.phase {
    Running => @tray.TrayMenuItem::normal(id="pause", label="暂停采集")
    Paused => @tray.TrayMenuItem::normal(id="resume", label="恢复采集")
    Stopped => @tray.TrayMenuItem::normal(id="start", label="启动采集")
    NotInstalled =>
      @tray.TrayMenuItem::normal(
        id="start",
        label="启动采集",
        enabled=false,
      )
  }
  [
    @tray.TrayMenuItem::normal(
      id="today",
      label="今日 ↓\{h(v.down)}  ↑\{h(v.up)}",
      enabled=false,
    ),
    @tray.TrayMenuItem::normal(
      id="split",
      label="经节点 \{h(v.via_node)}  ·  绕过 \{h(v.bypass)}",
      enabled=false,
    ),
    @tray.TrayMenuItem::normal(
      id="state",
      label="采集：\{phase_text(v)}",
      enabled=false,
    ),
    @tray.TrayMenuItem::separator(),
    @tray.TrayMenuItem::normal(id="open", label="打开 netwhere"),
    collect,
    @tray.TrayMenuItem::checkbox(
      id="autostart",
      label="登录时启动",
      checked=v.autostart,
    ),
    @tray.TrayMenuItem::separator(),
    @tray.TrayMenuItem::normal(id="quit", label="退出（停止采集）"),
  ]
}

///|
priv struct App {
  dir : String
  tray : @tray.Tray
  icons : Map[String, String]
  mut view : View
  mut shown_icon : String
  mut shown_menu : Array[@tray.TrayMenuItem]
  mut shown_tip : String
}

///|
/// Pushes the current view to the icon, tooltip and menu (only what changed).
fn App::render(self : App) -> Unit {
  let state = icon_state(self.view)
  if state != self.shown_icon {
    ignore(self.tray.set_icon(self.icons.get(state)))
    self.shown_icon = state
  }
  let tip = tooltip(self.view)
  if tip != self.shown_tip {
    ignore(self.tray.set_tooltip(tip))
    self.shown_tip = tip
  }
  let m = menu(self.view)
  if m != self.shown_menu {
    ignore(self.tray.set_menu(m))
    self.shown_menu = m
  }
}

///|
fn App::refresh(self : App) -> Unit {
  self.view = read_view(self.dir)
  self.render()
}

///|
fn App::open_ui(self : App) -> Unit {
  match ui_program() {
    Some(exe) => {
      allow_foreground()
      match @sys.spawn_detached(exe, ["--data-dir", self.dir]) {
        Ok(_) => ()
        Err(e) =>
          message_box("无法打开界面（Win32 错误 \{e}）：\{exe}")
      }
    }
    None => message_box("没有找到 netwhere-ui.exe")
  }
}

///|
fn App::start_collector(_self : App) -> Unit {
  match @control.start() {
    Ok(_) => ()
    Err(e) => message_box("无法启动采集：\{e}")
  }
}

///|
fn App::request(
  self : App,
  kind : @mailbox.Kind,
  optimistic : @control.Phase,
) -> Unit {
  match @control.request(self.dir, kind) {
    Ok(_) => {
      // The heartbeat catches up within 5 s; show the outcome now.
      self.view = { ..self.view, phase: optimistic, }
      self.render()
    }
    Err(e) => message_box("请求没有送达采集进程：\{e}")
  }
}

///|
fn App::toggle_autostart(self : App) -> Unit {
  let err = if self.view.autostart {
    @control.set_autostart(None)
  } else {
    @control.set_autostart(Some(own_path()))
  }
  if err != 0 {
    message_box("无法修改登录时启动（Win32 错误 \{err}）")
  }
  self.refresh()
}

///|
/// Quit: close the window, stop the collector, remove the icon.
fn App::quit(self : App) -> Unit {
  ignore(close_ui())
  ignore(self.tray.hide())
  if self.view.phase is (Running | Paused) &&
    !@control.stop_and_wait(self.dir, timeout_ms=10000) {
    message_box(
      "采集进程没有在 10 秒内退出，请用 netwhere status 查看。",
    )
  }
}

///|
fn arg_value(args : Array[String], name : String) -> String? {
  for i in 0..<(args.length() - 1) {
    if args[i] == name {
      return Some(args[i + 1])
    }
  }
  None
}

///|
fn main {
  let args = @env.args()
  let dir = arg_value(args, "--data-dir").unwrap_or(@sys.data_dir())
  if single_instance() == 0 {
    // Already running: a second launch (e.g. from the Start menu) just
    // opens the window.
    match ui_program() {
      Some(exe) => ignore(@sys.spawn_detached(exe, ["--data-dir", dir]))
      None => ()
    }
    return
  }
  if host_create(refresh_ms) == 0 {
    message_box("无法创建托盘窗口")
    return
  }
  let icons = @icon.write_icons()
  let view = read_view(dir)
  if view.phase == Stopped && !args.contains("--no-start") {
    // Opening the app means collecting.
    ignore(@control.start())
  }
  let tray = match
    @tray.create(
      identifier="netwhere",
      icon=icons.get(icon_state(view)),
      tooltip=tooltip(view),
    ) {
    Ok(t) => t
    Err(e) => {
      message_box("无法创建托盘图标：\{e}")
      return
    }
  }
  let app : App = {
    dir,
    tray,
    icons,
    view,
    shown_icon: icon_state(view),
    shown_menu: [],
    shown_tip: tooltip(view),
  }
  app.render()
  ignore(tray.show())
  if !args.contains("--background") {
    app.open_ui()
  }
  let mut running = true
  while running {
    match tray.pump(blocking=true) {
      Ok(true) => ()
      _ => break
    }
    let p = take_pending()
    if (p & 2) != 0 {
      // Explorer restarted: add the icon again.
      ignore(tray.hide())
      ignore(tray.show(tooltip=Some(app.shown_tip)))
      app.shown_icon = ""
      app.render()
    }
    if (p & 4) != 0 {
      // Logging off: leave the collector to the session's end.
      running = false
    }
    for ev in tray.drain_events() {
      match ev {
        Click => app.open_ui()
        MenuItemClick("open") => app.open_ui()
        MenuItemClick("pause") => app.request(Pause, Paused)
        MenuItemClick("resume") => app.request(Resume, Running)
        MenuItemClick("start") => {
          app.start_collector()
          app.refresh()
        }
        MenuItemClick("autostart") => app.toggle_autostart()
        MenuItemClick("quit") => {
          app.quit()
          running = false
        }
        _ => ()
      }
    }
    if running && (p & 1) != 0 {
      app.refresh()
    }
  }
  tray.destroy()
}
