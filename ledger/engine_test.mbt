// Synthetic scenarios modelled on the M0 probe experiments (PROBE.md).
// Addresses and ports follow the probe; node names are placeholders.

///|
let t0 : Int64 = 134389774848293434L

///|
let sec : Int64 = 10_000_000L

///|
let core_pid : Int32 = 14948

///|
let curl_pid : Int32 = 17716

///|
fn ipa(s : String) -> @netaddr.IpAddr {
  @netaddr.IpAddr::parse(s).unwrap()
}

///|
fn net(
  t : Int64,
  id : Int32,
  pid : Int32,
  sa : String,
  sp : Int32,
  da : String,
  dp : Int32,
  size : Int32,
) -> @ledger.Record {
  Net({ t: t0 + t, id, pid, size, saddr: sa, sport: sp, daddr: da, dport: dp, })
}

///|
fn header(tun~ : Bool = false) -> @ledger.Header {
  {
    version: 1,
    t0,
    note: "synthetic",
    devices: @ledger.DeviceMap::new([("\\Device\\HarddiskVolume3", "C:")]),
    cores: [{ pid: core_pid, name: "FlClashCore.exe", }],
    tun: if tun {
      [
        {
          if_index: 42,
          if_name: "FlClash",
          prefixes: [@netaddr.Cidr::parse("198.18.0.1/30").unwrap()],
        },
      ]
    } else {
      []
    },
    listeners: [
      { addr: ipa("127.0.0.1"), port: 7890, pid: core_pid, },
      { addr: ipa("127.0.0.1"), port: 5000, pid: 999, },
    ],
    procs: [],
    controller: "127.0.0.1:9090",
  }
}

///|
fn curl_start(t : Int64) -> @ledger.Record {
  ProcStart({
    t: t0 + t,
    pid: curl_pid,
    ppid: 20008,
    create_time: t0 + t,
    image: "\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe",
  })
}

///|
fn snapshot(t : Int64, body : String) -> @ledger.Record raise {
  MihomoSnapshot(t0 + t, @json.parse(body))
}

///|
fn describe(f : @ledger.FlowSummary) -> String {
  "\{@ledger.base_name(f.process)} \{f.proto} \{f.peer} entry=\{f.entry} exit=\{f.exit} domain=\{f.domain} up=\{f.up} down=\{f.down}" +
  (if f.inconsistent { " INCONSISTENT" } else { "" })
}

///|
fn run(h : @ledger.Header, records : Array[@ledger.Record]) -> @ledger.Engine {
  let (engine, _) = @ledger.replay({ header: h, records, })
  engine
}

///|
test "system proxy: app socket counted once, exit from the snapshot" {
  let e = run(header(), [
    curl_start(0L),
    // curl -> 127.0.0.1:7890 (app side, counted)
    net(1L, 12, curl_pid, "127.0.0.1", 64607, "127.0.0.1", 7890, 0),
    net(2L, 10, curl_pid, "127.0.0.1", 64607, "127.0.0.1", 7890, 950),
    net(3L, 11, curl_pid, "127.0.0.1", 64607, "127.0.0.1", 7890, 20_035_300),
    // the core's side of the same loopback connection (mirror, dropped)
    net(2L, 11, core_pid, "127.0.0.1", 7890, "127.0.0.1", 64607, 950),
    net(3L, 10, core_pid, "127.0.0.1", 7890, "127.0.0.1", 64607, 20_035_300),
    // the core's connection to the node (separate total)
    net(3L, 11, core_pid, "10.0.0.5", 55738, "203.0.113.7", 443, 20_109_000),
    snapshot(
      2L * sec,
      (
        #|{"downloadTotal":1,"uploadTotal":1,"connections":[{"id":"a","metadata":{
        #| "network":"tcp","type":"HTTP","sourceIP":"127.0.0.1","sourcePort":"64607",
        #| "host":"speed.cloudflare.com","process":"curl.exe"},
        #| "start":"2026-11-13T01:18:04.8293434+08:00",
        #| "chains":["HK 01","Proxy"],"rule":"Match","rulePayload":""}]}
      ),
    ),
  ])
  let flows = e.flows()
  inspect(
    flows.map(describe).join("\n"),
    content="curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=node:HK 01 domain=speed.cloudflare.com up=950 down=20035300",
  )
  inspect(flows[0].group + " " + flows[0].rule, content="Proxy Match")
  let t = e.totals()
  assert_eq(t.dropped_mirror, 20_036_250L)
  assert_eq(t.core_outbound_down, 20_109_000L)
  assert_eq(t.unknown_exit, 0L)
}

///|
test "direct and lan flows never enter the core; domain from dns" {
  let e = run(header(), [
    curl_start(0L),
    Dns({
      t: t0 + 1L,
      id: 3008,
      header_pid: curl_pid,
      client_pid: None,
      name: "speed.cloudflare.com",
      status: 0,
      results: "104.16.1.1;2606:4700::6810:101;",
    }),
    net(2L, 11, curl_pid, "10.0.0.5", 50001, "104.16.1.1", 443, 5000),
    net(
      3L, 27, curl_pid, "2001:db8::2", 50002, "2606:4700:0:0:0:0:6810:101", 443,
      7000,
    ),
    net(4L, 43, curl_pid, "192.168.1.1", 53, "192.168.1.20", 50003, 120),
  ])
  inspect(
    e.flows().map(describe).join("\n"),
    content=(
      #|curl.exe tcp 104.16.1.1:443 entry=direct exit=- domain=speed.cloudflare.com up=0 down=5000
      #|curl.exe tcp [2606:4700::6810:101]:443 entry=direct exit=- domain=speed.cloudflare.com up=0 down=7000
      #|curl.exe udp 192.168.1.1:53 entry=lan exit=- domain= up=0 down=120
    ),
  )
  assert_eq(e.flows()[0].domain_source, FromProcessDns)
}

///|
test "other processes' dns is a weaker domain source" {
  let e = run(header(), [
    Dns({
      t: t0,
      id: 3020,
      header_pid: 2504,
      client_pid: Some(31337),
      name: "cdn.example.net",
      status: 0,
      results: "93.184.216.34;",
    }),
    net(1L, 11, curl_pid, "10.0.0.5", 50010, "93.184.216.34", 443, 10),
  ])
  let f = e.flows()[0]
  inspect(f.domain, content="cdn.example.net")
  assert_eq(f.domain_source, FromAnyDns)
  // Unknown image: the flow is still reported, under its pid.
  inspect(f.process, content="pid:17716")
}

///|
test "tun: fake-ip flow joins by source port; core mirror on tun dropped; ipv6 bypasses" {
  let e = run(header(tun=true), [
    curl_start(0L),
    Dns({
      t: t0 + 1L,
      id: 3008,
      header_pid: curl_pid,
      client_pid: None,
      name: "speed.cloudflare.com",
      status: 0,
      results: "198.18.0.13;",
    }),
    Route({
      t: t0 + 2L,
      dst: ipa("198.18.0.13"),
      if_index: 42,
      if_name: "FlClash",
      via_tun: true,
    }),
    Route({
      t: t0 + 2L,
      dst: ipa("2606:4700::1"),
      if_index: 2,
      if_name: "WLAN",
      via_tun: false,
    }),
    net(2L, 10, curl_pid, "198.18.0.1", 50211, "198.18.0.13", 443, 818),
    net(3L, 11, curl_pid, "198.18.0.1", 50211, "198.18.0.13", 443, 20_035_800),
    // system stack: the core appears as 198.18.0.1:7890 <-> 198.18.0.2:10000
    net(3L, 10, core_pid, "198.18.0.1", 7890, "198.18.0.2", 10000, 20_035_800),
    // IPv6 default route is not TUN on the probe machine
    net(4L, 27, curl_pid, "2001:db8::2", 50300, "2606:4700::1", 443, 8_000_000),
    snapshot(
      sec,
      (
        #|{"connections":[{"id":"t","metadata":{"network":"tcp","type":"Tun",
        #| "sourceIP":"198.18.0.1","sourcePort":"50211","host":"speed.cloudflare.com",
        #| "process":"curl.exe"},"start":"2026-11-13T01:18:04.8293434+08:00",
        #| "chains":["TW 03","Proxy"],"rule":"Match","rulePayload":""}]}
      ),
    ),
  ])
  inspect(
    e.flows().map(describe).join("\n"),
    content=(
      #|curl.exe tcp 198.18.0.13:443 entry=tun exit=node:TW 03 domain=speed.cloudflare.com up=818 down=20035800
      #|curl.exe tcp [2606:4700::1]:443 entry=direct exit=- domain= up=0 down=8000000
    ),
  )
  assert_eq(e.totals().dropped_mirror, 20_035_800L)
  assert_true(e.core_present())
}

///|
test "short connection missing from snapshots is resolved from the log" {
  let e = run(header(), [
    curl_start(0L),
    net(1L, 10, curl_pid, "127.0.0.1", 63010, "127.0.0.1", 7890, 517),
    net(2L, 11, curl_pid, "127.0.0.1", 63010, "127.0.0.1", 7890, 2900),
    MihomoLog(
      t0 + 1L,
      "[TCP] 127.0.0.1:63010(curl.exe) --> www.baidu.com:443 match DomainSuffix(baidu.com) using Bypass[DIRECT]",
    ),
  ])
  let f = e.flows()[0]
  inspect(
    describe(f),
    content="curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=core-direct domain=www.baidu.com up=517 down=2900",
  )
  inspect(f.rule, content="DomainSuffix(baidu.com)")
}

///|
test "join respects process name and time window" {
  let e = run(header(), [
    curl_start(0L),
    net(0L, 10, curl_pid, "127.0.0.1", 63020, "127.0.0.1", 7890, 100),
    // Same port, wrong process.
    MihomoLog(
      t0, "[TCP] 127.0.0.1:63020(git.exe) --> a.test:443 match Match using Node A",
    ),
    // Same port and process, but a minute later: a reused port.
    MihomoLog(
      t0 + 60L * sec,
      "[TCP] 127.0.0.1:63020(curl.exe) --> b.test:443 match Match using Node B",
    ),
  ])
  inspect(
    describe(e.flows()[0]),
    content="curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=unknown domain= up=100 down=0",
  )
  assert_eq(e.totals().unknown_exit, 100L)
}

///|
test "long tun flow without any core record is inconsistent" {
  let e = run(header(tun=true), [
    Route({
      t: t0,
      dst: ipa("140.82.112.3"),
      if_index: 42,
      if_name: "FlClash",
      via_tun: true,
    }),
    net(0L, 10, curl_pid, "198.18.0.1", 51000, "140.82.112.3", 443, 100),
    net(5L * sec, 11, curl_pid, "198.18.0.1", 51000, "140.82.112.3", 443, 100),
  ])
  let f = e.flows()[0]
  assert_true(f.inconsistent)
  assert_eq(f.exit, Unknown)
}

///|
test "loopback between ordinary processes is not traffic" {
  let e = run(header(), [
    net(0L, 10, curl_pid, "127.0.0.1", 60000, "127.0.0.1", 5000, 300),
    net(0L, 11, 999, "127.0.0.1", 5000, "127.0.0.1", 60000, 300),
  ])
  assert_eq(e.flows().length(), 0)
  assert_eq(e.totals().dropped_loopback, 600L)
}

///|
test "minute rows and classification" {
  let rules = @rules.RuleSet::new()
  rules.add_domain(Builtin, Suffix("cloudflare.com"), "Cloudflare")
  let minute = 60L * sec
  let e = run(header(), [
    curl_start(0L),
    Dns({
      t: t0,
      id: 3008,
      header_pid: curl_pid,
      client_pid: None,
      name: "speed.cloudflare.com",
      status: 0,
      results: "104.16.1.1;",
    }),
    net(0L, 11, curl_pid, "10.0.0.5", 50001, "104.16.1.1", 443, 1000),
    net(minute, 11, curl_pid, "10.0.0.5", 50001, "104.16.1.1", 443, 2000),
    net(minute, 10, curl_pid, "10.0.0.5", 50001, "104.16.1.1", 443, 50),
    net(minute, 11, curl_pid, "10.0.0.5", 50002, "93.184.216.34", 443, 7),
  ])
  let rows = e.usage_rows(rules)
  inspect(
    rows
    .map(r => {
      "\{r.minute - t0 / minute} \{r.app} \{r.process} \{r.domain} \{r.entry} up=\{r.up} down=\{r.down}"
    })
    .join("\n"),
    content=(
      #|0 Cloudflare curl.exe speed.cloudflare.com direct up=0 down=1000
      #|1 Cloudflare curl.exe speed.cloudflare.com direct up=50 down=2000
      #|1 Unknown curl.exe  direct up=0 down=7
    ),
  )
}

///|
test "process tree for trace" {
  let start = fn(pid : Int32, ppid : Int32) -> @ledger.Record {
    ProcStart({ t: t0, pid, ppid, create_time: t0, image: "x.exe", })
  }
  let e = run(header(), [
    start(100, 1),
    start(101, 100),
    start(102, 101),
    start(103, 101),
    start(200, 1),
  ])
  let tree = e.process_tree(100)
  tree.sort()
  assert_eq(tree, [100, 101, 102, 103])
}

///|
test "take_usage hands out each byte once, after the settle time" {
  let rules = @rules.RuleSet::new()
  let e = run(header(), [
    curl_start(0L),
    net(0L, 11, curl_pid, "10.0.0.5", 50001, "104.16.1.1", 443, 1000),
  ])
  // Too early: the flow may still get a core record.
  assert_eq(e.take_usage(rules, t0 + sec).length(), 0)
  let rows = e.take_usage(rules, t0 + 10L * sec)
  assert_eq(rows.length(), 1)
  assert_eq(rows[0].down, 1000L)
  assert_eq(e.take_usage(rules, t0 + 11L * sec).length(), 0)
  e.on_net(
    @ledger.normalize_net({
      t: t0 + 12L * sec,
      id: 11,
      pid: curl_pid,
      size: 500,
      saddr: "10.0.0.5",
      sport: 50001,
      daddr: "104.16.1.1",
      dport: 443,
    }).unwrap(),
  )
  let more = e.take_usage(rules, t0 + 13L * sec)
  assert_eq(more.map(r => r.down), [500L])
  // Idle flows with nothing pending are forgotten.
  assert_eq(e.evict_idle(t0 + 600L * sec, 120L * sec), 1)
  assert_eq(e.flow_count(), 0)
}

///|
test "controller API traffic is not proxy traffic" {
  let h = {
    ..header(),
    listeners: [{ addr: ipa("127.0.0.1"), port: 9090, pid: core_pid, }],
  }
  let e = run(h, [
    net(0L, 11, curl_pid, "127.0.0.1", 60001, "127.0.0.1", 9090, 1000),
  ])
  assert_eq(e.flows().length(), 0)
  assert_eq(e.totals().dropped_loopback, 1000L)
}

///|
test "a connection opened before observation joins its snapshot" {
  // Mihomo says it started an hour before t0 and still lists it at t0+2s.
  let e = run(header(), [
    curl_start(0L),
    net(1L * sec, 11, curl_pid, "127.0.0.1", 61000, "127.0.0.1", 7890, 500),
    snapshot(
      2L * sec,
      (
        #|{"connections":[{"id":"old","metadata":{"network":"tcp","type":"HTTP",
        #| "sourceIP":"127.0.0.1","sourcePort":"61000","host":"api.example.com",
        #| "process":"curl.exe"},"start":"2026-11-13T00:18:04.8293434+08:00",
        #| "chains":["HK 01","Proxy"],"rule":"Match","rulePayload":""}]}
      ),
    ),
  ])
  inspect(
    describe(e.flows()[0]),
    content="curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=node:HK 01 domain=api.example.com up=0 down=500",
  )
}

///|
test "dns hijacked by tun is not flagged inconsistent" {
  let e = run(header(tun=true), [
    Route({
      t: t0,
      dst: ipa("198.18.0.2"),
      if_index: 42,
      if_name: "FlClash",
      via_tun: true,
    }),
    net(0L, 42, 2504, "198.18.0.1", 50000, "198.18.0.2", 53, 40),
    net(5L * sec, 43, 2504, "198.18.0.2", 53, "198.18.0.1", 50000, 120),
  ])
  let f = e.flows()[0]
  assert_eq(f.entry, Tun)
  assert_false(f.inconsistent)
}

///|
test "a long-lived connection keeps its exit after eviction runs" {
  let rules = @rules.RuleSet::new()
  let conn =
    #|{"connections":[{"id":"long","metadata":{"network":"tcp","type":"HTTPS",
    #| "sourceIP":"127.0.0.1","sourcePort":"61000","host":"api.example.com",
    #| "process":"curl.exe"},"start":"2026-11-13T00:18:04.8293434+08:00",
    #| "chains":["HK 01","Proxy"],"rule":"Match","rulePayload":""}]}
  let e = run(header(), [
    curl_start(0L),
    // curl resolved localhost, which is also the proxy's address.
    Dns({
      t: t0,
      id: 3008,
      header_pid: curl_pid,
      client_pid: None,
      name: "localhost",
      status: 0,
      results: "127.0.0.1;",
    }),
    net(1L * sec, 11, curl_pid, "127.0.0.1", 61000, "127.0.0.1", 7890, 500),
    snapshot(2L * sec, conn),
  ])
  ignore(e.take_usage(rules, t0 + 10L * sec))
  // Ten minutes on, Mihomo still lists it and it still carries bytes.
  for m in 1..<=10 {
    let t = t0 + (m * 60).to_int64() * sec
    e.on_core_snapshot(t, @mihomo.decode_snapshot(@json.parse(conn)))
    e.on_net(
      @ledger.normalize_net({
        t,
        id: 11,
        pid: curl_pid,
        size: 100,
        saddr: "127.0.0.1",
        sport: 61000,
        daddr: "127.0.0.1",
        dport: 7890,
      }).unwrap(),
    )
    ignore(e.evict_idle(t, 120L * sec))
  }
  let rows = e.take_usage(rules, t0 + 700L * sec)
  inspect(
    rows
    .map(r => "\{r.domain} \{r.entry} \{r.exit} \{r.down}")
    .iter()
    .fold(init=Map([]), (m : Map[String, Int64], k) => {
      m[k] = m.get(k).unwrap_or(0L) + 1L
      m
    })
    .keys()
    .collect()
    .join("\n"),
    content="api.example.com proxy-port node:HK 01 100",
  )
  // Without a core record, a proxy-port flow gets no name from DNS.
  let e2 = run(header(), [
    curl_start(0L),
    Dns({
      t: t0,
      id: 3009,
      header_pid: curl_pid,
      client_pid: None,
      name: "localhost",
      status: 0,
      results: "127.0.0.1;",
    }),
    net(1L * sec, 11, curl_pid, "127.0.0.1", 61001, "127.0.0.1", 7890, 500),
  ])
  inspect(
    describe(e2.flows()[0]),
    content="curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=unknown domain= up=0 down=500",
  )
}

///|
test "records that disagree on the outbound make the exit ambiguous" {
  let e = run(header(), [
    curl_start(0L),
    net(0L, 10, curl_pid, "127.0.0.1", 63030, "127.0.0.1", 7890, 100),
    MihomoLog(
      t0 + 1L * sec,
      "[TCP] 127.0.0.1:63030(curl.exe) --> a.test:443 match Match using Node A",
    ),
    MihomoLog(
      t0 + 3L * sec,
      "[TCP] 127.0.0.1:63030(curl.exe) --> b.test:443 match Match using Node B",
    ),
  ])
  let f = e.flows()[0]
  // The closer record is still shown, but flagged.
  assert_eq(f.exit, Node("Node A"))
  assert_eq(f.match_kind, Ambiguous)
  assert_eq(f.match_dt, 1L * sec)
  let t = e.totals()
  assert_eq(t.ambiguous_exit, 100L)
  assert_eq(t.unknown_exit, 0L)
  // Usage rows carry the flag, so the ledger never counts it as a node.
  let rows = e.usage_rows(@rules.RuleSet::new())
  assert_true(rows.iter().all(r => r.ambiguous))
}

///|
test "log line and snapshot of the same connection agree: not ambiguous" {
  let e = run(header(), [
    curl_start(0L),
    net(0L, 10, curl_pid, "127.0.0.1", 64607, "127.0.0.1", 7890, 100),
    MihomoLog(
      t0 + 1L,
      "[TCP] 127.0.0.1:64607(curl.exe) --> speed.cloudflare.com:443 match Match using Proxy[HK 01]",
    ),
    snapshot(
      2L * sec,
      (
        #|{"downloadTotal":1,"uploadTotal":1,"connections":[{"id":"a","metadata":{
        #| "network":"tcp","type":"HTTP","sourceIP":"127.0.0.1","sourcePort":"64607",
        #| "host":"speed.cloudflare.com","process":"curl.exe"},
        #| "start":"2026-11-13T01:18:04.8293434+08:00",
        #| "chains":["HK 01","Proxy"],"rule":"Match","rulePayload":""}]}
      ),
    ),
  ])
  let f = e.flows()[0]
  assert_eq(f.exit, Node("HK 01"))
  assert_eq(f.match_kind, Snapshot)
}

///|
test "match kinds: log only, none, not proxied" {
  let e = run(header(), [
    curl_start(0L),
    net(0L, 10, curl_pid, "127.0.0.1", 63040, "127.0.0.1", 7890, 100),
    MihomoLog(
      t0 + 1L * sec,
      "[TCP] 127.0.0.1:63040(curl.exe) --> a.test:443 match Match using Node A",
    ),
    net(0L, 10, curl_pid, "127.0.0.1", 63041, "127.0.0.1", 7890, 100),
    net(0L, 10, curl_pid, "192.0.2.10", 63042, "203.0.113.9", 443, 100),
  ])
  let kinds = e.flows().map(f => f.match_kind)
  assert_eq(kinds, [LogLine, NoMatch, NoMatch])
  assert_eq(e.flows()[2].exit, NotProxied)
}

///|
test "route says TUN but the socket is bound to another adapter: bypass" {
  let e = run(header(tun=true), [
    Route({
      t: t0,
      dst: ipa("140.82.112.3"),
      if_index: 42,
      if_name: "FlClash",
      via_tun: true,
    }),
    // curl --interface 192.168.1.10: the route points at TUN, the local
    // address is the physical adapter's.
    net(0L, 10, curl_pid, "192.168.1.10", 51001, "140.82.112.3", 443, 100),
    // An ordinary socket to the same address does enter TUN.
    net(0L, 10, curl_pid, "198.18.0.1", 51002, "140.82.112.3", 443, 100),
  ])
  let fs = e.flows()
  assert_eq(fs[0].entry, Direct)
  assert_true(fs[0].bound_off_tun)
  assert_eq(fs[1].entry, Tun)
  assert_false(fs[1].bound_off_tun)
}

///|
test "sing-box: snapshot and multi-line logs join; a direct tag is learned from logs" {
  let e = run(header(), [
    curl_start(0L),
    // Long connection: listed by a snapshot and logged.
    net(0L, 10, curl_pid, "127.0.0.1", 51234, "127.0.0.1", 7890, 900),
    MihomoLog(
      t0 + 1L,
      "[101 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:51234",
    ),
    MihomoLog(
      t0 + 2L,
      "[101 0ms] inbound/mixed[mixed-in]: inbound connection to www.baidu.com:443",
    ),
    MihomoLog(
      t0 + 3L,
      "[101 1ms] outbound/direct[我的直连]: outbound connection to www.baidu.com:443",
    ),
    snapshot(
      sec,
      (
        #|{"connections":[{"id":"5d3c1f1e","metadata":{"network":"tcp",
        #| "type":"mixed/mixed-in","sourceIP":"127.0.0.1","sourcePort":"51234",
        #| "destinationPort":"443","host":"www.baidu.com","dnsMode":"normal",
        #| "processPath":"C:\\Windows\\System32\\curl.exe"},
        #| "start":"2026-11-13T01:18:04.8293434+08:00",
        #| "chains":["我的直连","bypass"],"rule":"rule_set=geosite-cn => route(我的直连)","rulePayload":""}]}
      ),
    ),
    // Short connection: between snapshots, logs only.
    net(2L * sec, 10, curl_pid, "127.0.0.1", 51235, "127.0.0.1", 7890, 500),
    MihomoLog(
      t0 + 2L * sec,
      "[102 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:51235",
    ),
    MihomoLog(
      t0 + 2L * sec,
      "[102 0ms] inbound/mixed[mixed-in]: inbound connection to speed.cloudflare.com:443",
    ),
    MihomoLog(
      t0 + 2L * sec + 1L,
      "[102 2ms] outbound/vless[hk-01]: outbound connection to speed.cloudflare.com:443",
    ),
  ])
  let fs = e.flows()
  inspect(
    fs.map(f => describe(f) + " match=\{f.match_kind}").join("\n"),
    content=(
      #|curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=core-direct domain=www.baidu.com up=900 down=0 match=snapshot
      #|curl.exe tcp 127.0.0.1:7890 entry=proxy-port exit=node:hk-01 domain=speed.cloudflare.com up=500 down=0 match=log
    ),
  )
  inspect(fs[0].rule, content="rule_set=geosite-cn => route(我的直连)")
}
