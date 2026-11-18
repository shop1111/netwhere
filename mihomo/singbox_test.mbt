// sing-box Clash API shapes, built from sing-box's
// experimental/clashapi/connections.go (connectionObject.MarshalJSON) and
// log/format.go (FormatSimple); tags and hosts are placeholders.

///|
let singbox_snapshot : String =
  #|{"downloadTotal":5003000,"uploadTotal":1600,"memory":0,"connections":[
  #| {"id":"5d3c1f1e-0000-4000-8000-000000000001","metadata":{"network":"tcp",
  #|  "type":"mixed/mixed-in","sourceIP":"127.0.0.1","destinationIP":"",
  #|  "sourcePort":"51234","destinationPort":"443","host":"speed.cloudflare.com",
  #|  "dnsMode":"normal","processPath":"C:\\Windows\\System32\\curl.exe (user)"},
  #|  "upload":800,"download":5003000,"start":"2026-11-18T17:30:01.1234567+08:00",
  #|  "chains":["hk-01","proxy"],"rule":"final","rulePayload":""}
  #|]}

///|
test "sing-box snapshot: process from processPath, chain order like Mihomo" {
  let snap = @mihomo.parse_snapshot(singbox_snapshot)
  let c = snap.conns[0]
  inspect(c.process, content="curl.exe")
  assert_eq(c.source_port, 51234)
  inspect(c.outbound(), content="hk-01")
  inspect(c.host, content="speed.cloudflare.com")
  assert_true(c.start is Some(_))
  // /configs: sing-box reports zero ports and no TUN description.
  let cfg = @mihomo.decode_configs(
    @json.parse(
      "{\"port\":0,\"socks-port\":0,\"redir-port\":0,\"tproxy-port\":0,\"mixed-port\":0,\"allow-lan\":false,\"bind-address\":\"*\",\"mode\":\"Rule\",\"mode-list\":[\"Rule\"],\"log-level\":\"info\",\"ipv6\":false,\"tun\":null}",
    ),
  )
  assert_false(cfg.tun_known)
  assert_eq(cfg.ports, [])
}

///|
test "process_name_of_path" {
  inspect(
    @mihomo.process_name_of_path(
      "C:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    ),
    content="git.exe",
  )
  inspect(@mihomo.process_name_of_path("/usr/bin/curl (1000)"), content="curl")
  inspect(@mihomo.process_name_of_path("curl.exe"), content="curl.exe")
  inspect(@mihomo.process_name_of_path(""), content="")
}

///|
test "sing-box log lines join by connection id" {
  let p = @mihomo.ConnLogParser::new()
  // Two connections (ids 3392193542 and 77), interleaved.
  let lines = [
    "[3392193542 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:51234",
    "[77 0ms] inbound/tun[tun-in]: inbound packet connection from 172.19.0.1:60000",
    "[3392193542 0ms] inbound/mixed[mixed-in]: inbound connection to speed.cloudflare.com:443",
    "[77 0ms] inbound/tun[tun-in]: inbound packet connection to 1.1.1.1:53", "[3392193542 3ms] outbound/vless[hk-01]: outbound connection to speed.cloudflare.com:443",
    "[77 1ms] outbound/direct[直连]: outbound packet connection",
  ]
  let out = lines.filter_map(l => p.feed(l))
  assert_eq(out.length(), 2)
  let a = out[0]
  inspect(
    "\{a.network} \{a.source}:\{a.source_port} -> \{a.dest_host}:\{a.dest_port} via \{a.outbound} (\{a.outbound_type})",
    content="tcp 127.0.0.1:51234 -> speed.cloudflare.com:443 via hk-01 (vless)",
  )
  let b = out[1]
  inspect(
    "\{b.network} \{b.source}:\{b.source_port} -> \{b.dest_host}:\{b.dest_port} via \{b.outbound} (\{b.outbound_type})",
    content="udp 172.19.0.1:60000 -> 1.1.1.1:53 via 直连 (direct)",
  )
  // Every line above belongs to a routed connection.
  assert_true(lines.iter().all(l => @mihomo.is_conn_log_line(l)))
  // Mihomo lines still parse through the same parser.
  let m = p.feed(
    "[TCP] 127.0.0.1:63010(curl.exe) --> www.baidu.com:443 match Match using DIRECT",
  )
  inspect(m.unwrap().outbound_type, content="")
}

///|
test "sing-box: unrelated or incomplete lines yield nothing" {
  let p = @mihomo.ConnLogParser::new()
  // Not a connection line; a DNS line; an outbound whose inbound was never
  // seen; a malformed id.
  let lines = [
    "router: updated default interface WLAN, index 2", "[12 0ms] dns: exchanged example.com A 93.184.216.34",
    "[13 0ms] outbound/direct[direct]: outbound connection to a.test:443", "[x 0ms] inbound/mixed[m]: inbound connection from 127.0.0.1:1",
  ]
  for l in lines {
    assert_eq(p.feed(l), None)
  }
  assert_false(
    @mihomo.is_conn_log_line(
      "[12 0ms] dns: exchanged example.com A 93.184.216.34",
    ),
  )
}
