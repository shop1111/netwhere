///|
fn temp_db(tag : String) -> String {
  let dir = @sys.getenv("TEMP").unwrap()
  "\{dir}\\netwhere-test-\{tag}-\{@sys.current_pid()}-\{@sys.now()}.db"
}

///|
/// Removes the database files a test created.
async fn cleanup(path : String) -> Unit {
  for suffix in ["", "-wal", "-shm"] {
    @fs.remove(path + suffix, allow_missing=true)
  }
}

///|
fn row(minute : Int64, app : String, down : Int64) -> @ledger.UsageRow {
  {
    minute,
    app,
    process: "curl.exe",
    domain: "speed.cloudflare.com",
    entry: Direct,
    exit: NotProxied,
    ambiguous: false,
    rule: "",
    up: 1L,
    down,
  }
}

///|
async test "usage upserts accumulate; reader sees writer; files persist" {
  let path = temp_db("usage")
  let w = @store.Db::open_writer(path)
  w.add_usage([row(10L, "Cloudflare", 100L), row(11L, "Cloudflare", 5L)], true)
  w.add_usage([row(10L, "Cloudflare", 50L)], true)
  let r = @store.Db::open_reader(path)
  let rows = r.usage_between(0L, 100L)
  assert_eq(rows.length(), 2)
  assert_eq(rows[0].down, 150L)
  assert_eq(rows[0].up, 2L)
  // A direct flow while a core ran is stored as "bypass".
  inspect(rows[0].entry, content="bypass")
  inspect(rows[0].exit_kind, content="-")
  assert_eq(r.usage_between(11L, 12L).length(), 1)
  r.close()
  w.close()
  // The keeper connection keeps -wal and -shm after a clean shutdown.
  assert_true(@fs.exists(path + "-wal"))
  assert_true(@fs.exists(path + "-shm"))
  let again = @store.Db::open_writer(path)
  assert_eq(again.meta("schema_version"), Some("2"))
  again.prune_usage(11L)
  assert_eq(again.usage_between(0L, 100L).length(), 1)
  again.close()
  cleanup(path)
}

///|
async test "heartbeat round trip" {
  let path = temp_db("hb")
  let w = @store.Db::open_writer(path)
  assert_eq(w.heartbeat(), None)
  let h : @store.Heartbeat = {
    pid: 42,
    started: 1L,
    updated: 2L,
    state: "running",
    degraded: false,
    core_link: "connected",
    last_error: "",
    events: 100L,
    dropped: 0L,
    flows: 7,
    private_bytes: 9_000_000L,
    callback_ns: 1000L,
    events_lost: 0L,
    cpu_ms: 5L,
  }
  w.write_heartbeat(h)
  w.write_heartbeat({ ..h, updated: 3L, state: "paused", })
  let got = w.heartbeat().unwrap()
  assert_eq(got.updated, 3L)
  inspect(got.state, content="paused")
  assert_eq(got.flows, 7)
  w.close()
  cleanup(path)
}

///|
async test "requests and trace results" {
  let path = temp_db("req")
  let w = @store.Db::open_writer(path)
  let req : @store.RequestRow = {
    id: "abc",
    kind: "trace",
    client_pid: 10,
    root_pid: 0,
    state: "ready",
    reason: "",
    created: 100L,
    updated: 100L,
  }
  w.put_request(req)
  w.put_request({ ..req, root_pid: 11, state: "running", updated: 200L, })
  let got = w.request("abc").unwrap()
  assert_eq(got.root_pid, 11)
  inspect(got.state, content="running")
  assert_eq(got.created, 100L)
  let ip = fn(s : String) { @netaddr.IpAddr::parse(s).unwrap() }
  let flow : @ledger.FlowSummary = {
    pid: 11,
    process: "C:\\Windows\\System32\\curl.exe",
    proto: Tcp,
    sock: { addr: ip("127.0.0.1"), port: 50000, },
    peer: { addr: ip("127.0.0.1"), port: 7890, },
    entry: ProxyPort,
    exit: Node("HK 01"),
    group: "Proxy",
    rule: "Match",
    domain: "speed.cloudflare.com",
    domain_source: FromCore,
    target_port: 443,
    first: 0L,
    last: 1L,
    up: 950L,
    down: 20_000_000L,
    inconsistent: false,
    match_kind: Snapshot,
    match_dt: 0L,
    bound_off_tun: false,
  }
  w.put_trace("abc", [(11, 10, "curl.exe")], [flow], true)
  // Storing again replaces the earlier result.
  w.put_trace("abc", [(11, 10, "curl.exe")], [flow], true)
  let flows = w.trace_flows("abc")
  assert_eq(flows.length(), 1)
  inspect(
    flows[0].entry + " " + flows[0].exit_kind + " " + flows[0].node,
    content="proxy-port node HK 01",
  )
  assert_eq(flows[0].target_port, 443)
  assert_eq(w.trace_procs("abc"), [(11, 10, "curl.exe")])
  w.prune_requests(300L)
  assert_eq(w.request("abc"), None)
  assert_eq(w.trace_flows("abc").length(), 0)
  w.close()
  cleanup(path)
}

///|
/// Runs raw SQL on a database file (to build an old-version ledger).
fn raw_exec(path : String, sql : String) -> Unit raise {
  let conn = @sqlite3.Connection::open(path)
  let mut rest = sql[:]
  while conn.prepare_next(rest) is Some((stmt, tail)) {
    while stmt.step() {

    }
    stmt.finalize()
    rest = tail
  }
  conn.close()
}

///|
async test "a version 1 ledger is upgraded in place" {
  let path = temp_db("v1")
  raw_exec(
    path,
    (
      #|CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      #|INSERT INTO meta VALUES ('schema_version', '1');
      #|CREATE TABLE trace_flows(
      #|  request_id TEXT NOT NULL, pid INTEGER NOT NULL, process TEXT NOT NULL,
      #|  proto TEXT NOT NULL, peer TEXT NOT NULL, domain TEXT NOT NULL,
      #|  target_port INTEGER NOT NULL, entry TEXT NOT NULL, exit_kind TEXT NOT NULL,
      #|  node TEXT NOT NULL, rule TEXT NOT NULL, up INTEGER NOT NULL,
      #|  down INTEGER NOT NULL, inconsistent INTEGER NOT NULL
      #|);
      #|INSERT INTO trace_flows VALUES ('old', 1, 'a.exe', 'tcp', '1.2.3.4:443', '', 443, 'bypass', '-', '', '', 1, 2, 0);
    ),
  )
  let w = @store.Db::open_writer(path)
  assert_eq(w.meta("schema_version"), Some("2"))
  let old = w.trace_flows("old")
  assert_eq(old.length(), 1)
  inspect(old[0].match_kind, content="none")
  assert_false(old[0].bound_off_tun)
  // The new table exists.
  w.add_coverage([
    {
      minute: 5L,
      collector_ticks: 1L,
      core_ticks: 1L,
      link_ticks: 1L,
      etw_lost: 0L,
      dropped: 0L,
    },
  ])
  w.close()
  // Opening again does not migrate twice.
  let again = @store.Db::open_writer(path)
  assert_eq(again.coverage_between(0L, 10L).length(), 1)
  again.close()
  cleanup(path)
}

///|
async test "coverage deltas add up per minute; ambiguous exits stored apart" {
  let path = temp_db("cov")
  let w = @store.Db::open_writer(path)
  let c : @report.Coverage = {
    minute: 7L,
    collector_ticks: 100L,
    core_ticks: 100L,
    link_ticks: 40L,
    etw_lost: 0L,
    dropped: 1L,
  }
  w.add_coverage([c])
  w.add_coverage([{ ..c, etw_lost: 2L, dropped: 0L, }, { ..c, minute: 8L, }])
  let rows = w.coverage_between(0L, 100L)
  assert_eq(rows.length(), 2)
  assert_eq(rows[0], {
    minute: 7L,
    collector_ticks: 200L,
    core_ticks: 200L,
    link_ticks: 80L,
    etw_lost: 2L,
    dropped: 1L,
  })
  w.prune_usage(8L)
  assert_eq(w.coverage_between(0L, 100L).length(), 1)
  w.add_usage(
    [{ ..row(10L, "Cloudflare", 5L), exit: Node("HK 01"), ambiguous: true, }],
    true,
  )
  let u = w.usage_between(0L, 100L)
  inspect(u[0].exit_kind + " " + u[0].node, content="ambiguous HK 01")
  w.close()
  cleanup(path)
}
