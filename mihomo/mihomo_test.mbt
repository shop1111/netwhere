// Inputs follow the shape of real FlClash (Mihomo 1.10.0) output captured in
// the M0 probe and spikes/mihomo_ws, with host and node names replaced.

///|
let snapshot_text : String =
  #|{"downloadTotal":70898479,"uploadTotal":1234,"memory":95633408,"connections":[
  #| {"id":"22c729f9","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1",
  #|  "destinationIP":"","sourcePort":"50211","destinationPort":"443","inboundIP":"",
  #|  "inboundPort":"0","inboundName":"DEFAULT-TUN","host":"Speed.Cloudflare.com",
  #|  "dnsMode":"fake-ip","uid":0,"process":"curl.exe",
  #|  "processPath":"C:\\Windows\\System32\\curl.exe","sniffHost":""},
  #|  "upload":794,"download":20034499,"start":"2026-11-13T01:33:22.4691446+08:00",
  #|  "chains":["HK 01","Auto","Proxy"],"providerChains":["","",""],
  #|  "rule":"Match","rulePayload":""},
  #| {"id":"968e9b1b","metadata":{"network":"udp","type":"HTTP","sourceIP":"127.0.0.1",
  #|  "destinationIP":"10.0.0.97","sourcePort":"57130","destinationPort":"389",
  #|  "host":"","sniffHost":"ad.example.edu","process":"svchost.exe","processPath":""},
  #|  "upload":"150","download":0,"start":"garbage",
  #|  "chains":["DIRECT","Bypass"],"rule":"DomainSuffix","rulePayload":"edu"}
  #|]}

///|
test "snapshot decoding" {
  let snap = @mihomo.parse_snapshot(snapshot_text)
  assert_eq(snap.download_total, 70898479L)
  assert_eq(snap.conns.length(), 2)
  let a = snap.conns[0]
  inspect(a.outbound(), content="HK 01")
  inspect(a.host, content="speed.cloudflare.com")
  assert_eq(a.source_port, 50211)
  inspect(a.source.unwrap(), content="198.18.0.1")
  assert_true(a.dest_ip is None)
  assert_eq(a.download, 20034499L)
  assert_eq(a.start, Some(134389784024691446L))
  inspect(a.inbound_type, content="Tun")
  // Sniffed host fills in when "host" is empty; string numbers are accepted.
  let b = snap.conns[1]
  inspect(b.host, content="ad.example.edu")
  inspect(b.outbound(), content="DIRECT")
  assert_eq(b.upload, 150L)
  assert_true(b.start is None)
  inspect(b.rule + "(" + b.rule_payload + ")", content="DomainSuffix(edu)")
}

///|
test "empty and malformed snapshots" {
  let empty = @mihomo.parse_snapshot(
    "{\"downloadTotal\":0,\"uploadTotal\":0,\"connections\":null}",
  )
  assert_eq(empty.conns.length(), 0)
  let msg = try {
    let _ = @mihomo.parse_snapshot("[1,2]")
    "ok"
  } catch {
    e => e.to_string()
  }
  inspect(msg, content="mihomo: snapshot is not an object")
}

///|
test "rfc3339 to filetime" {
  assert_eq(@mihomo.parse_rfc3339("1601-01-01T00:00:00Z"), Some(0L))
  assert_eq(
    @mihomo.parse_rfc3339("1970-01-01T00:00:00Z"),
    Some(116444736000000000L),
  )
  assert_eq(
    @mihomo.parse_rfc3339("2024-02-29T23:59:59-05:30"),
    Some(133537445990000000L),
  )
  // Nanosecond fractions are truncated to 100 ns ticks.
  assert_eq(
    @mihomo.parse_rfc3339("2026-11-13T01:33:22.469144699+08:00"),
    Some(134389784024691446L),
  )
  for
    bad in [
      "", "2026-11-13", "2026-11-13T01:33:22", "2026-13-01T00:00:00Z", "2026-11-13T01:33:22+0800",
      "2026-11-13T01:33:22Zjunk",
    ] {
    assert_true(@mihomo.parse_rfc3339(bad) is None, msg=bad)
  }
}

///|
test "configs" {
  let j = @json.parse(
    (
      #|{"port":0,"socks-port":7891,"mixed-port":7890,"redir-port":0,"tproxy-port":0,
      #| "tun":{"enable":true,"device":"FlClash","stack":"Mixed",
      #|        "inet4-address":["198.18.0.1/30"],"inet6-address":["fdfe:dcba:9876::1/126"]}}
    ),
  )
  let c = @mihomo.decode_configs(j)
  assert_eq(c.ports, [7890, 7891])
  assert_true(c.tun_enabled)
  inspect(c.tun_device, content="FlClash")
  inspect(
    c.tun_prefixes.map(p => p.to_string()).join(" "),
    content="198.18.0.1/30 fdfe:dcba:9876::1/126",
  )
  let off = @mihomo.decode_configs(@json.parse("{\"mixed-port\":7890}"))
  assert_false(off.tun_enabled)
}

///|
test "log frame and routed-connection lines" {
  let m = @mihomo.parse_log_message(
    (
      #|{"type":"info","payload":"[TCP] 127.0.0.1:63010(curl.exe) --\u003e www.baidu.com:443 match DomainSuffix(baidu.com) using Bypass[DIRECT]"}
    ),
  )
  inspect(m.level, content="info")
  let l = @mihomo.parse_conn_log(m.payload).unwrap()
  assert_eq(l.source_port, 63010)
  inspect(l.source, content="127.0.0.1")
  inspect(l.process, content="curl.exe")
  inspect(
    l.dest_host + ":" + l.dest_port.to_string(),
    content="www.baidu.com:443",
  )
  inspect(l.rule + "|" + l.rule_payload, content="DomainSuffix|baidu.com")
  inspect(l.group + "|" + l.outbound, content="Bypass|DIRECT")
  inspect(l.network, content="tcp")
}

///|
test "routed-connection line variants" {
  let a = @mihomo.parse_conn_log(
    "[TCP] 127.0.0.1:63016(curl.exe) --> example.com:443 match Match using Fallback[TW 03 1x]",
  ).unwrap()
  inspect(
    a.rule + "|" + a.rule_payload + "|" + a.outbound,
    content="Match||TW 03 1x",
  )
  // Node names may contain brackets; the split happens at the first '['.
  let b = @mihomo.parse_conn_log(
    "[TCP] [::1]:5000(app.exe, uid=0) --> [2606:4700::1]:443 match IPCIDR(2606:4700::/32) using Proxy[[SS] HK 01]",
  ).unwrap()
  inspect(b.source, content="::1")
  inspect(b.process, content="app.exe")
  inspect(b.dest_host, content="2606:4700::1")
  inspect(b.rule_payload, content="2606:4700::/32")
  inspect(b.group + "|" + b.outbound, content="Proxy|[SS] HK 01")
  let c = @mihomo.parse_conn_log(
    "[UDP] 198.18.0.1:5353 --> x.test:53 using GLOBAL",
  ).unwrap()
  inspect(c.process + "|" + c.rule + "|" + c.outbound, content="||GLOBAL")
  let d = @mihomo.parse_conn_log(
    "[TCP] 127.0.0.1:1(uid=1000) --> x.test:443 doesn't match any rule using DIRECT",
  ).unwrap()
  inspect(d.process + "|" + d.outbound, content="|DIRECT")
  // Other log lines are not connection records.
  assert_true(@mihomo.parse_conn_log("[DNS] resolve x.test failed") is None)
  assert_true(
    @mihomo.parse_conn_log("Start initial configuration in progress") is None,
  )
  assert_true(
    @mihomo.parse_conn_log(
      "[TCP] dial Proxy (match Match/) 127.0.0.1:1 --> x:443 error: timeout",
    )
    is None,
  )
}
