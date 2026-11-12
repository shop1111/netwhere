// Field values below are taken from the M0 probe schema dump
// (etwprobe/evidence/raw/schema.txt), so these tests pin the probe findings.

///|
fn raw_net(
  id : Int32,
  pid : Int32,
  saddr : String,
  sport : Int32,
  daddr : String,
  dport : Int32,
  size~ : Int32 = 0,
) -> @ledger.RawNet {
  { t: 0L, id, pid, size, saddr, sport, daddr, dport, }
}

///|
test "tcp events are written from the sock side in both directions" {
  // Data received by FlClashCore (PID property 14948, header pid was System).
  let recv = @ledger.normalize_net(
    raw_net(11, 14948, "10.0.0.5", 55738, "172.215.188.225", 443, size=4380),
  ).unwrap()
  inspect(recv.sock, content="10.0.0.5:55738")
  inspect(recv.peer, content="172.215.188.225:443")
  assert_eq(recv.kind, Recv)
  assert_eq(recv.pid, 14948)
  // Data sent by the core back to an app on loopback: the local port is 7890.
  let send = @ledger.normalize_net(
    raw_net(10, 14948, "127.0.0.1", 7890, "127.0.0.1", 55737, size=4380),
  ).unwrap()
  inspect(send.sock, content="127.0.0.1:7890")
  inspect(send.peer, content="127.0.0.1:55737")
  assert_eq(send.kind, Send)
}

///|
test "udp receive swaps address direction" {
  let sent = @ledger.normalize_net(
    raw_net(42, 2504, "10.0.0.5", 49213, "10.0.0.53", 53, size=51),
  ).unwrap()
  inspect(sent.sock, content="10.0.0.5:49213")
  inspect(sent.peer, content="10.0.0.53:53")
  let got = @ledger.normalize_net(
    raw_net(43, 2504, "10.0.0.53", 53, "10.0.0.5", 49213, size=172),
  ).unwrap()
  inspect(got.sock, content="10.0.0.5:49213")
  inspect(got.peer, content="10.0.0.53:53")
  assert_eq(got.proto, Udp)
  assert_eq(got.kind, Recv)
}

///|
test "ipv6 events normalize the uncompressed etw text" {
  let ev = @ledger.normalize_net(
    raw_net(
      29, 24372, "2001:db8:3002:3250:0:0:2:daef", 53795, "2603:1030:807:14:0:0:0:43a",
      443,
    ),
  ).unwrap()
  inspect(ev.sock, content="[2001:db8:3002:3250::2:daef]:53795")
  inspect(ev.peer, content="[2603:1030:807:14::43a]:443")
  assert_eq(ev.kind, Disconnect)
}

///|
test "unknown ids and bad addresses are dropped" {
  assert_true(
    @ledger.normalize_net(raw_net(18, 1, "1.1.1.1", 1, "2.2.2.2", 2)) is None,
  )
  assert_true(
    @ledger.normalize_net(raw_net(10, 1, "nonsense", 1, "2.2.2.2", 2)) is None,
  )
}

///|
fn texts(xs : Array[@netaddr.IpAddr]) -> String {
  xs.map(a => a.to_text()).join(" ")
}

///|
test "dns query results" {
  let (cnames, addrs) = @ledger.parse_query_results(
    "type: 5 glb.tas01.cwsapp-prod.dcat.dsp.mp.microsoft.com;type: 5 glb.cwsapp.prod.dcat.dsp.trafficmanager.net;48.200.63.27;",
  )
  inspect(
    cnames.join(" "),
    content="glb.tas01.cwsapp-prod.dcat.dsp.mp.microsoft.com glb.cwsapp.prod.dcat.dsp.trafficmanager.net",
  )
  inspect(texts(addrs), content="48.200.63.27")
  let (_, v6) = @ledger.parse_query_results("2a06:98c1:58::da;2606:4700:7::da;")
  inspect(texts(v6), content="2a06:98c1:58::da 2606:4700:7::da")
  let (_, mapped) = @ledger.parse_query_results("::ffff:198.18.0.13;")
  inspect(texts(mapped), content="198.18.0.13")
}

///|
test "dns answers are attributed to the asking process" {
  let base : @ledger.RawDns = {
    t: 5L,
    id: 3020,
    header_pid: 2504,
    client_pid: Some(24372),
    name: "Speed.Cloudflare.com",
    status: 0,
    results: "198.18.0.13;",
  }
  let a = @ledger.normalize_dns(base).unwrap()
  assert_eq(a.pid, 24372)
  inspect(a.name, content="speed.cloudflare.com")
  // Event 3008 has no ClientPID: the header pid is the asker.
  let b = @ledger.normalize_dns({ ..base, id: 3008, client_pid: None, }).unwrap()
  assert_eq(b.pid, 2504)
  // Failures and empty answers carry nothing to join on.
  assert_true(@ledger.normalize_dns({ ..base, status: 9701, }) is None)
  assert_true(@ledger.normalize_dns({ ..base, results: "", }) is None)
}

///|
test "device paths become drive paths" {
  let devices = @ledger.DeviceMap::new([
    ("\\Device\\HarddiskVolume3", "C:"),
    ("\\Device\\HarddiskVolume30", "D:"),
  ])
  inspect(
    devices.to_dos_path(
      "\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe",
    ),
    content="C:\\Windows\\System32\\curl.exe",
  )
  // Prefix must end at a path component: Volume30 is not Volume3.
  inspect(
    devices.to_dos_path("\\Device\\HarddiskVolume30\\Tools\\git.exe"),
    content="D:\\Tools\\git.exe",
  )
  inspect(
    devices.to_dos_path("\\device\\harddiskvolume3\\x.exe"),
    content="C:\\x.exe",
  )
  inspect(devices.to_dos_path("\\??\\C:\\y.exe"), content="C:\\y.exe")
  inspect(
    devices.to_dos_path("\\Device\\Mup\\server\\share\\z.exe"),
    content="\\Device\\Mup\\server\\share\\z.exe",
  )
  inspect(
    @ledger.base_name("C:\\Windows\\System32\\curl.exe"),
    content="curl.exe",
  )
  inspect(@ledger.base_name("curl.exe"), content="curl.exe")
}
