// Probe for justjavac/tray: Chinese tooltip and menu, checkbox, periodic
// tooltip refresh driven by a thread timer, clean exit from the menu.
//
// usage: main.exe [--auto MS]   (--auto exits after MS ms)

///|
extern "C" fn start_timer(ms : Int) -> Unit = "nwt_start_timer"

///|
extern "C" fn now_ms() -> UInt64 = "nwt_now_ms"

///|
fn menu(autostart : Bool, paused : Bool) -> Array[@tray.TrayMenuItem] {
  [
    @tray.TrayMenuItem::normal(id="today", label="今日 ↑ 12.3 MB  ↓ 456.7 MB", enabled=false),
    @tray.TrayMenuItem::normal(id="state", label=if paused { "采集：已暂停" } else { "采集：运行中" }, enabled=false),
    @tray.TrayMenuItem::separator(),
    @tray.TrayMenuItem::normal(id="open", label="打开 netwhere"),
    @tray.TrayMenuItem::normal(id="pause", label=if paused { "恢复采集" } else { "暂停采集" }),
    @tray.TrayMenuItem::checkbox(id="autostart", label="登录时启动", checked=autostart),
    @tray.TrayMenuItem::separator(),
    @tray.TrayMenuItem::normal(id="quit", label="退出（停止采集）"),
  ]
}

///|
fn main {
  let args = @env.args()
  let auto_ms = if args.length() >= 3 && args[1] == "--auto" {
    @string.parse_int(args[2]) catch { _ => 0 }
  } else {
    0
  }
  let t0 = now_ms()
  let tray = match @tray.create(identifier="netwhere-probe", tooltip="netwhere 探针") {
    Ok(t) => t
    Err(e) => {
      println("create failed: \{e}")
      return
    }
  }
  let mut autostart = true
  let mut paused = false
  println("menu: \{tray.set_menu(menu(autostart, paused))}")
  println("show: \{tray.show()}")
  start_timer(1000)
  let mut ticks = 0
  let mut running = true
  while running {
    match tray.pump(blocking=true) {
      Ok(true) => ()
      Ok(false) => break
      Err(e) => {
        println("pump: \{e}")
        break
      }
    }
    for ev in tray.drain_events() {
      println("event: \{ev.event_name()} \{ev.item_id()}")
      match ev {
        MenuItemClick("quit") => running = false
        MenuItemClick("pause") => {
          paused = !paused
          ignore(tray.set_menu(menu(autostart, paused)))
        }
        MenuItemClick("autostart") => {
          autostart = !autostart
          ignore(tray.set_menu(menu(autostart, paused)))
        }
        _ => ()
      }
    }
    let elapsed = now_ms() - t0
    if elapsed / 1000UL > ticks.to_uint64() {
      ticks = (elapsed / 1000UL).to_int()
      ignore(tray.set_tooltip("netwhere 探针\n已运行 \{ticks} 秒"))
    }
    if auto_ms > 0 && elapsed >= auto_ms.to_uint64() {
      running = false
    }
  }
  tray.destroy()
  println("exit after \{now_ms() - t0} ms, \{ticks} ticks")
}
