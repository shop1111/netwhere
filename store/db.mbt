// ledger.db: written only by the collector, read by everyone else.

///|
pub let schema_version : Int32 = 1

///|
let schema : String =
  #|CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
  #|CREATE TABLE IF NOT EXISTS usage(
  #|  minute INTEGER NOT NULL, app TEXT NOT NULL, process TEXT NOT NULL,
  #|  domain TEXT NOT NULL, entry TEXT NOT NULL, exit_kind TEXT NOT NULL,
  #|  node TEXT NOT NULL, rule TEXT NOT NULL,
  #|  up INTEGER NOT NULL, down INTEGER NOT NULL,
  #|  PRIMARY KEY(minute, app, process, domain, entry, exit_kind, node, rule)
  #|) WITHOUT ROWID;
  #|CREATE INDEX IF NOT EXISTS usage_by_app ON usage(app, minute);
  #|CREATE TABLE IF NOT EXISTS heartbeat(
  #|  id INTEGER PRIMARY KEY CHECK (id = 1), pid INTEGER NOT NULL,
  #|  started INTEGER NOT NULL, updated INTEGER NOT NULL, state TEXT NOT NULL,
  #|  degraded INTEGER NOT NULL, core_link TEXT NOT NULL, last_error TEXT NOT NULL,
  #|  events INTEGER NOT NULL, dropped INTEGER NOT NULL, flows INTEGER NOT NULL,
  #|  private_bytes INTEGER NOT NULL, callback_ns INTEGER NOT NULL,
  #|  events_lost INTEGER NOT NULL, cpu_ms INTEGER NOT NULL
  #|);
  #|CREATE TABLE IF NOT EXISTS requests(
  #|  id TEXT PRIMARY KEY, kind TEXT NOT NULL, client_pid INTEGER NOT NULL,
  #|  root_pid INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL,
  #|  created INTEGER NOT NULL, updated INTEGER NOT NULL
  #|);
  #|CREATE TABLE IF NOT EXISTS trace_procs(
  #|  request_id TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER NOT NULL,
  #|  image TEXT NOT NULL
  #|);
  #|CREATE TABLE IF NOT EXISTS trace_flows(
  #|  request_id TEXT NOT NULL, pid INTEGER NOT NULL, process TEXT NOT NULL,
  #|  proto TEXT NOT NULL, peer TEXT NOT NULL, domain TEXT NOT NULL,
  #|  target_port INTEGER NOT NULL, entry TEXT NOT NULL, exit_kind TEXT NOT NULL,
  #|  node TEXT NOT NULL, rule TEXT NOT NULL, up INTEGER NOT NULL,
  #|  down INTEGER NOT NULL, inconsistent INTEGER NOT NULL
  #|);
  #|CREATE INDEX IF NOT EXISTS trace_flows_by_request ON trace_flows(request_id);

///|
#borrow(path)
extern "c" fn nw_keeper_open(path : Bytes) -> Int32 = "nw_keeper_open"

///|
extern "c" fn nw_keeper_close() -> Int32 = "nw_keeper_close"

///|
#derive(Debug)
pub(all) suberror StoreError {
  StoreError(String)
}

///|
pub impl Show for StoreError with fn output(self, logger) {
  let StoreError(m) = self
  logger.write_string("ledger.db: " + m)
}

///|
fn wrap(context : String, e : Error) -> StoreError {
  match e {
    @sqlite3.SqliteError(msg~, ..) => StoreError("\{context}: \{msg}")
    other => StoreError("\{context}: \{other}")
  }
}

///|
pub struct Db {
  priv conn : @sqlite3.Connection
  priv writer : Bool
}

///|
fn utf8z(s : String) -> Bytes {
  let b = Buffer()
  b.write_bytes(@utf8.encode(s))
  b.write_byte(b'\x00')
  b.to_bytes()
}

///|
fn Db::exec(self : Db, sql : String) -> Unit raise StoreError {
  let mut rest = sql[:]
  try {
    while self.conn.prepare_next(rest) is Some((stmt, tail)) {
      while stmt.step() {

      }
      stmt.finalize()
      rest = tail
    }
  } catch {
    e => raise wrap("exec", e)
  }
}

///|
/// Opens ledger.db for the collector: creates the schema, enables WAL and
/// starts the keeper connection first.
pub fn Db::open_writer(path : String) -> Db raise StoreError {
  let rc = nw_keeper_open(utf8z(path))
  if rc != 0 {
    raise StoreError("keeper connection failed with SQLite code \{rc}")
  }
  let conn = @sqlite3.Connection::open(path) catch {
    e => raise wrap("open", e)
  }
  let db = { conn, writer: true, }
  db.exec(
    "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA trusted_schema=OFF;",
  )
  db.exec("BEGIN; " + schema + " COMMIT;")
  let v = db.meta("schema_version")
  match v {
    None => db.set_meta("schema_version", schema_version.to_string())
    Some(s) if s == schema_version.to_string() => ()
    Some(s) => raise StoreError("schema version \{s} is not supported")
  }
  db
}

///|
/// Opens ledger.db for reading (CLI, UI). Works without write permission
/// while the -wal/-shm files exist, which the keeper connection guarantees.
pub fn Db::open_reader(path : String) -> Db raise StoreError {
  let conn = @sqlite3.Connection::open(path) catch {
    e => raise wrap("open \{path}", e)
  }
  let db = { conn, writer: false, }
  db.exec("PRAGMA busy_timeout=5000; PRAGMA query_only=1;")
  db
}

///|
pub fn Db::close(self : Db) -> Unit {
  if self.writer {
    // Fold the WAL into the main file; the persisted -wal stays, empty.
    self.exec("PRAGMA wal_checkpoint(TRUNCATE);") catch {
      _ => ()
    }
  }
  self.conn.close() catch {
    _ => ()
  }
  if self.writer {
    ignore(nw_keeper_close())
  }
}

///|
/// Runs `f` inside one transaction.
pub fn[X] Db::transaction(self : Db, f : () -> X raise) -> X raise StoreError {
  self.exec("BEGIN IMMEDIATE;")
  let r = f() catch {
    e => {
      self.exec("ROLLBACK;") catch {
        _ => ()
      }
      raise wrap("transaction", e)
    }
  }
  self.exec("COMMIT;")
  r
}

///|
pub fn Db::meta(self : Db, key : String) -> String? raise StoreError {
  let rows = self.query("SELECT value FROM meta WHERE key = ?1", [Text(key)])
  match rows {
    [[Text(v)], ..] => Some(v)
    _ => None
  }
}

///|
pub fn Db::set_meta(
  self : Db,
  key : String,
  value : String,
) -> Unit raise StoreError {
  self.run(
    "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [Text(key), Text(value)],
  )
}

///|
/// A bound parameter or a result cell.
#derive(Eq, Debug)
pub(all) enum Cell {
  Int(Int64)
  Text(String)
  Real(Double)
  Null
}

///|
fn bind_all(stmt : @sqlite3.Statement, params : Array[Cell]) -> Unit raise {
  for i, p in params {
    match p {
      Int(v) => stmt.bind(index=i + 1, v)
      Text(v) => stmt.bind(index=i + 1, v)
      Real(v) => stmt.bind(index=i + 1, v)
      Null => stmt.bind(index=i + 1, @sqlite3.Value::Null)
    }
  }
}

///|
/// Executes one statement that returns no rows.
pub fn Db::run(
  self : Db,
  sql : String,
  params : Array[Cell],
) -> Unit raise StoreError {
  try {
    let stmt = self.conn.prepare(sql)
    bind_all(stmt, params)
    while stmt.step() {

    }
    stmt.finalize()
  } catch {
    e => raise wrap(sql, e)
  }
}

///|
/// Executes a query; every row is an array of cells.
pub fn Db::query(
  self : Db,
  sql : String,
  params : Array[Cell],
) -> Array[Array[Cell]] raise StoreError {
  try {
    let stmt = self.conn.prepare(sql)
    bind_all(stmt, params)
    let rows = []
    let n = stmt.column_count()
    while stmt.step() {
      let row = []
      for i in 0..<n {
        let v : @sqlite3.Value = stmt.column(index=i)
        row.push(
          match v {
            Integer(x) => Int(x)
            Real(x) => Real(x)
            Text(x) => Text(x)
            Blob(_) => Null
            Null => Null
          },
        )
      }
      rows.push(row)
    }
    stmt.finalize()
    rows
  } catch {
    e => raise wrap(sql, e)
  }
}
