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
  assert_eq(again.meta("schema_version"), Some("1"))
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
