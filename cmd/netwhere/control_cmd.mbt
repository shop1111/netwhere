// `netwhere start | stop | pause | resume | autostart`: control the
// installed collector without elevation (see the control package).

///|
async fn cmd_control(verb : String, args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("\{verb}: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  let wait_for = async fn(want : (@control.Phase) -> Bool, ms : Int32) -> Bool {
    let mut waited = 0
    while waited < ms {
      if want(@control.status(dir).phase) {
        return true
      }
      @async.sleep(250)
      waited += 250
    }
    want(@control.status(dir).phase)
  }
  match verb {
    "start" => {
      match @control.start() {
        Ok(_) => ()
        Err(e) => {
          println("start: \{e}")
          return 1
        }
      }
      if wait_for(p => p is (Running | Paused), 10000) {
        println("collector running")
        0
      } else {
        println(
          "start: the task ran but no heartbeat yet; see `netwhere status`",
        )
        1
      }
    }
    "stop" => {
      if @control.status(dir).phase is (NotInstalled | Stopped) {
        println("collector is not running")
        return 0
      }
      if @control.request(dir, Stop) is Err(e) {
        println("stop: \{e}")
        return 1
      }
      if wait_for(p => p is (NotInstalled | Stopped), 10000) {
        println("collector stopped")
        0
      } else {
        println("stop: no answer from the collector; see `netwhere status`")
        1
      }
    }
    "pause" | "resume" => {
      let st = @control.status(dir)
      if !(st.phase is (Running | Paused)) {
        println("\{verb}: collector is not running")
        return 1
      }
      let kind : @mailbox.Kind = if verb == "pause" { Pause } else { Resume }
      if @control.request(dir, kind) is Err(e) {
        println("\{verb}: \{e}")
        return 1
      }
      let want : @control.Phase = if verb == "pause" { Paused } else { Running }
      // The heartbeat is written every 5 s.
      if wait_for(p => p == want, 7000) {
        println(
          if verb == "pause" {
            "collector paused"
          } else {
            "collector resumed"
          },
        )
        0
      } else {
        println("\{verb}: requested; the heartbeat has not caught up yet")
        0
      }
    }
    _ => 2
  }
}

///|
async fn cmd_autostart(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("autostart: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  let tray = @control.installed_tray(dir)
  match a.positional {
    [] => {
      match @control.autostart_command() {
        Some(c) => println("start at login: on (\{c})")
        None => println("start at login: off")
      }
      0
    }
    ["on"] => {
      if !@fs.exists(tray) {
        println("autostart: \{tray} not found; run `netwhere install` first")
        return 1
      }
      match @control.set_autostart(Some(tray)) {
        0 => {
          println("start at login: on (the tray starts the collector)")
          0
        }
        e => {
          println("autostart: cannot write the Run key (Win32 error \{e})")
          1
        }
      }
    }
    ["off"] =>
      match @control.set_autostart(None) {
        0 => {
          println("start at login: off")
          0
        }
        e => {
          println("autostart: cannot delete the Run value (Win32 error \{e})")
          1
        }
      }
    _ => {
      println("usage: netwhere autostart [on|off]")
      2
    }
  }
}
