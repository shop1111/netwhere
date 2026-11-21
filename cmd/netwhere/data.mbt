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
/// Writes config.json in place (see control.save_config: the user may not
/// create a temporary file next to it).
fn save_config(dir : String, c : @config.Config) -> Unit raise {
  match @control.save_config(dir, c) {
    Ok(_) => ()
    Err(e) => fail(e)
  }
}

///|
let offset : Int32 = @sys.utc_offset_minutes()
