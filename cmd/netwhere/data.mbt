// Locating and opening the collector's files.

///|
fn data_dir_of(a : @cli.Args) -> String {
  a.get("--data-dir", @sys.data_dir())
}

///|
async fn open_ledger(dir : String) -> @store.Db? {
  let path = dir + "\\ledger.db"
  if !@fs.exists(path) {
    println(
      "no ledger at \{path}: the collector has not run yet (see `netwhere install`).",
    )
    return None
  }
  match (Ok(@store.Db::open_reader(path)) catch { e => Err(e) }) {
    Ok(db) => Some(db)
    Err(e) => {
      println("cannot open the ledger: \{e}")
      None
    }
  }
}

///|
async fn load_config(dir : String) -> @config.Config {
  let path = dir + "\\config.json"
  if !@fs.exists(path) {
    return @config.default()
  }
  @config.parse(@fs.read_file(path).text())
}

///|
/// Writes config.json atomically (temporary file, then rename).
async fn save_config(dir : String, c : @config.Config) -> Unit {
  let path = dir + "\\config.json"
  let tmp = path + ".tmp"
  @fs.write_file(tmp, c.to_text())
  @fs.rename(tmp, path, replace=true)
}

///|
/// False only when the process list is readable and has no netwhered
/// process with this pid; any doubt counts as alive.
fn collector_alive(pid : Int32) -> Bool {
  let procs = @sys.process_list()
  procs.length() == 0 ||
  procs.iter().any(p => p.pid == pid && p.exe.to_lower() == "netwhered.exe")
}

///|
/// Collector state from the heartbeat: (running, description).
fn collector_state(h : @store.Heartbeat?, now : Int64) -> (Bool, String) {
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
let offset : Int32 = @sys.utc_offset_minutes()
