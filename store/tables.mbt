// Typed access to the ledger.db tables.

///|
pub let ticks_per_minute : Int64 = 600_000_000L

///|
/// How an exit is stored: (exit_kind, node).
pub fn exit_columns(x : @ledger.Exit) -> (String, String) {
  match x {
    Node(n) => ("node", n)
    CoreDirect => ("core-direct", "")
    CoreReject => ("core-reject", "")
    Unknown => ("unknown", "")
    NotProxied => ("-", "")
  }
}

///|
/// Adds usage rows (deltas) in one transaction.
pub fn Db::add_usage(
  self : Db,
  rows : Array[@ledger.UsageRow],
  core_present : Bool,
) -> Unit raise StoreError {
  if rows.length() == 0 {
    return
  }
  self.transaction(() => {
    for r in rows {
      let (kind, node) = exit_columns(r.exit)
      self.run(
        (
          #|INSERT INTO usage(minute, app, process, domain, entry, exit_kind, node, rule, up, down)
          #|VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
          #|ON CONFLICT(minute, app, process, domain, entry, exit_kind, node, rule)
          #|DO UPDATE SET up = up + excluded.up, down = down + excluded.down
        ),
        [
          Int(r.minute),
          Text(r.app),
          Text(r.process),
          Text(r.domain),
          Text(@report.entry_label(r.entry, core_present)),
          Text(kind),
          Text(node),
          Text(r.rule),
          Int(r.up),
          Int(r.down),
        ],
      )
    }
  })
}

///|
/// One stored usage row.
#derive(Eq, Debug)
pub(all) struct UsageRecord {
  minute : Int64
  app : String
  process : String
  domain : String
  entry : String
  exit_kind : String
  node : String
  rule : String
  up : Int64
  down : Int64
}

///|
fn int_of(c : Cell) -> Int64 {
  match c {
    Int(v) => v
    Real(v) => v.to_int64()
    _ => 0L
  }
}

///|
fn text_of(c : Cell) -> String {
  match c {
    Text(v) => v
    Int(v) => v.to_string()
    _ => ""
  }
}

///|
/// Usage rows with from <= minute < to.
pub fn Db::usage_between(
  self : Db,
  from : Int64,
  to : Int64,
) -> Array[UsageRecord] raise StoreError {
  self
  .query(
    "SELECT minute, app, process, domain, entry, exit_kind, node, rule, up, down FROM usage WHERE minute >= ?1 AND minute < ?2 ORDER BY minute",
    [Int(from), Int(to)],
  )
  .map(r => {
    minute: int_of(r[0]),
    app: text_of(r[1]),
    process: text_of(r[2]),
    domain: text_of(r[3]),
    entry: text_of(r[4]),
    exit_kind: text_of(r[5]),
    node: text_of(r[6]),
    rule: text_of(r[7]),
    up: int_of(r[8]),
    down: int_of(r[9]),
  })
}

///|
/// Deletes usage older than the given minute (retention).
pub fn Db::prune_usage(
  self : Db,
  before_minute : Int64,
) -> Unit raise StoreError {
  self.run("DELETE FROM usage WHERE minute < ?1", [Int(before_minute)])
}

// ---------------------------------------------------------------- heartbeat

///|
#derive(Eq, Debug)
pub(all) struct Heartbeat {
  pid : Int32
  started : Int64
  updated : Int64
  /// "running" | "paused" | "stopped"
  state : String
  degraded : Bool
  core_link : String
  last_error : String
  events : Int64
  dropped : Int64
  flows : Int32
  private_bytes : Int64
  /// Total time spent in the ETW callback (ns); divide by events.
  callback_ns : Int64
  /// Events the kernel reports as lost for the session.
  events_lost : Int64
  /// CPU time used by the collector so far (user + kernel, ms).
  cpu_ms : Int64
}

///|
pub fn Db::write_heartbeat(self : Db, h : Heartbeat) -> Unit raise StoreError {
  self.run(
    (
      #|INSERT INTO heartbeat(id, pid, started, updated, state, degraded, core_link, last_error, events, dropped, flows, private_bytes, callback_ns, events_lost, cpu_ms)
      #|VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
      #|ON CONFLICT(id) DO UPDATE SET pid = excluded.pid, started = excluded.started,
      #|  updated = excluded.updated, state = excluded.state, degraded = excluded.degraded,
      #|  core_link = excluded.core_link, last_error = excluded.last_error,
      #|  events = excluded.events, dropped = excluded.dropped, flows = excluded.flows,
      #|  private_bytes = excluded.private_bytes, callback_ns = excluded.callback_ns,
      #|  events_lost = excluded.events_lost, cpu_ms = excluded.cpu_ms
    ),
    [
      Int(h.pid.to_int64()),
      Int(h.started),
      Int(h.updated),
      Text(h.state),
      Int(if h.degraded { 1L } else { 0L }),
      Text(h.core_link),
      Text(h.last_error),
      Int(h.events),
      Int(h.dropped),
      Int(h.flows.to_int64()),
      Int(h.private_bytes),
      Int(h.callback_ns),
      Int(h.events_lost),
      Int(h.cpu_ms),
    ],
  )
}

///|
pub fn Db::heartbeat(self : Db) -> Heartbeat? raise StoreError {
  let rows = self.query(
    "SELECT pid, started, updated, state, degraded, core_link, last_error, events, dropped, flows, private_bytes, callback_ns, events_lost, cpu_ms FROM heartbeat WHERE id = 1",
    [],
  )
  match rows {
    [r, ..] =>
      Some({
        pid: int_of(r[0]).to_int(),
        started: int_of(r[1]),
        updated: int_of(r[2]),
        state: text_of(r[3]),
        degraded: int_of(r[4]) != 0L,
        core_link: text_of(r[5]),
        last_error: text_of(r[6]),
        events: int_of(r[7]),
        dropped: int_of(r[8]),
        flows: int_of(r[9]).to_int(),
        private_bytes: int_of(r[10]),
        callback_ns: int_of(r[11]),
        events_lost: int_of(r[12]),
        cpu_ms: int_of(r[13]),
      })
    [] => None
  }
}

// ---------------------------------------------------------------- requests and traces

///|
#derive(Eq, Debug)
pub(all) struct RequestRow {
  id : String
  kind : String
  client_pid : Int32
  root_pid : Int32
  state : String
  reason : String
  created : Int64
  updated : Int64
}

///|
pub fn Db::put_request(self : Db, r : RequestRow) -> Unit raise StoreError {
  self.run(
    (
      #|INSERT INTO requests(id, kind, client_pid, root_pid, state, reason, created, updated)
      #|VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      #|ON CONFLICT(id) DO UPDATE SET root_pid = excluded.root_pid, state = excluded.state,
      #|  reason = excluded.reason, updated = excluded.updated
    ),
    [
      Text(r.id),
      Text(r.kind),
      Int(r.client_pid.to_int64()),
      Int(r.root_pid.to_int64()),
      Text(r.state),
      Text(r.reason),
      Int(r.created),
      Int(r.updated),
    ],
  )
}

///|
pub fn Db::request(self : Db, id : String) -> RequestRow? raise StoreError {
  let rows = self.query(
    "SELECT id, kind, client_pid, root_pid, state, reason, created, updated FROM requests WHERE id = ?1",
    [Text(id)],
  )
  match rows {
    [r, ..] =>
      Some({
        id: text_of(r[0]),
        kind: text_of(r[1]),
        client_pid: int_of(r[2]).to_int(),
        root_pid: int_of(r[3]).to_int(),
        state: text_of(r[4]),
        reason: text_of(r[5]),
        created: int_of(r[6]),
        updated: int_of(r[7]),
      })
    [] => None
  }
}

///|
/// Stores the result of a trace (replacing any earlier result for it).
pub fn Db::put_trace(
  self : Db,
  id : String,
  procs : Array[(Int32, Int32, String)],
  flows : Array[@ledger.FlowSummary],
  core_present : Bool,
) -> Unit raise StoreError {
  self.transaction(() => {
    self.run("DELETE FROM trace_procs WHERE request_id = ?1", [Text(id)])
    self.run("DELETE FROM trace_flows WHERE request_id = ?1", [Text(id)])
    for p in procs {
      self.run(
        "INSERT INTO trace_procs(request_id, pid, ppid, image) VALUES (?1, ?2, ?3, ?4)",
        [Text(id), Int(p.0.to_int64()), Int(p.1.to_int64()), Text(p.2)],
      )
    }
    for f in flows {
      let (kind, node) = exit_columns(f.exit)
      self.run(
        (
          #|INSERT INTO trace_flows(request_id, pid, process, proto, peer, domain, target_port,
          #|  entry, exit_kind, node, rule, up, down, inconsistent)
          #|VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        ),
        [
          Text(id),
          Int(f.pid.to_int64()),
          Text(f.process),
          Text(if f.proto == Tcp { "tcp" } else { "udp" }),
          Text(f.peer.to_string()),
          Text(f.domain),
          Int(f.target_port.to_int64()),
          Text(@report.entry_label(f.entry, core_present)),
          Text(kind),
          Text(node),
          Text(f.rule),
          Int(f.up),
          Int(f.down),
          Int(if f.inconsistent { 1L } else { 0L }),
        ],
      )
    }
  })
}

///|
#derive(Eq, Debug)
pub(all) struct TraceFlow {
  pid : Int32
  process : String
  proto : String
  peer : String
  domain : String
  target_port : Int32
  entry : String
  exit_kind : String
  node : String
  rule : String
  up : Int64
  down : Int64
  inconsistent : Bool
}

///|
pub fn Db::trace_flows(
  self : Db,
  id : String,
) -> Array[TraceFlow] raise StoreError {
  self
  .query(
    "SELECT pid, process, proto, peer, domain, target_port, entry, exit_kind, node, rule, up, down, inconsistent FROM trace_flows WHERE request_id = ?1",
    [Text(id)],
  )
  .map(r => {
    pid: int_of(r[0]).to_int(),
    process: text_of(r[1]),
    proto: text_of(r[2]),
    peer: text_of(r[3]),
    domain: text_of(r[4]),
    target_port: int_of(r[5]).to_int(),
    entry: text_of(r[6]),
    exit_kind: text_of(r[7]),
    node: text_of(r[8]),
    rule: text_of(r[9]),
    up: int_of(r[10]),
    down: int_of(r[11]),
    inconsistent: int_of(r[12]) != 0L,
  })
}

///|
pub fn Db::trace_procs(
  self : Db,
  id : String,
) -> Array[(Int32, Int32, String)] raise StoreError {
  self
  .query("SELECT pid, ppid, image FROM trace_procs WHERE request_id = ?1", [
    Text(id),
  ])
  .map(r => (int_of(r[0]).to_int(), int_of(r[1]).to_int(), text_of(r[2])))
}

///|
/// Removes requests and trace results older than `before` (ticks).
pub fn Db::prune_requests(self : Db, before : Int64) -> Unit raise StoreError {
  self.transaction(() => {
    self.run(
      "DELETE FROM trace_flows WHERE request_id IN (SELECT id FROM requests WHERE updated < ?1)",
      [Int(before)],
    )
    self.run(
      "DELETE FROM trace_procs WHERE request_id IN (SELECT id FROM requests WHERE updated < ?1)",
      [Int(before)],
    )
    self.run("DELETE FROM requests WHERE updated < ?1", [Int(before)])
  })
}
