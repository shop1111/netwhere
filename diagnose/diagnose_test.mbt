///|
fn ip(s : String) -> @netaddr.IpAddr {
  @netaddr.IpAddr::parse(s).unwrap()
}

///|
fn flow(
  entry~ : String = "bypass",
  proto~ : String = "tcp",
  peer~ : String = "203.0.113.5",
  domain~ : String = "example.com",
  process~ : String = "curl.exe",
  bound_off_tun~ : Bool = false,
) -> @diagnose.FlowFacts {
  { process, proto, peer: ip(peer), port: 443, domain, entry, bound_off_tun, }
}

///|
fn codes(cs : Array[@diagnose.Cause]) -> String {
  cs.map(c => "\{c.code}/\{c.certainty}").join(" ")
}

///|
let sysproxy : @diagnose.Context = {
  ..@diagnose.Context::default(),
  system_proxy: true,
  system_proxy_server: "127.0.0.1:7890",
  system_proxy_override: "localhost;127.*;*.corp.example;<local>",
}

///|
let tun : @diagnose.Context = {
  ..@diagnose.Context::default(),
  tun_enabled: true,
  route_if: _ => Some("Ethernet"),
}

///|
test "flows that reached the core get no diagnosis" {
  assert_eq(@diagnose.diagnose(flow(entry="proxy-port"), [], sysproxy), [])
  assert_eq(@diagnose.diagnose(flow(entry="tun"), [], tun), [])
  assert_eq(@diagnose.diagnose(flow(entry="lan"), [], tun), [])
}

///|
test "no core at all" {
  inspect(
    codes(@diagnose.diagnose(flow(entry="direct"), [], sysproxy)),
    content="no-core/certain",
  )
}

///|
test "tun: ipv6 without an ipv6 tun address, and excluded routes" {
  let v6 = @diagnose.diagnose(flow(peer="2606:4700::1"), [], tun)
  inspect(codes(v6), content="tun-no-ipv6/certain")
  inspect(
    @diagnose.cause_text(v6[0]),
    content=(
      #|  tun-no-ipv6 (certain): TUN carries only IPv4; IPv6 traffic leaves through the physical adapter
      #|      - destination tcp example.com:443 ([2606:4700::1]) is IPv6
      #|      - the TUN adapter has no global IPv6 address
      #|      - route to 2606:4700::1 now goes through adapter "Ethernet"
      #|
    ),
  )
  // With IPv6 on the TUN adapter, an IPv6 bypass is a routing matter.
  inspect(
    codes(
      @diagnose.diagnose(flow(peer="2606:4700::1"), [], {
        ..tun,
        tun_has_v6: true,
      }),
    ),
    content="route-excluded/likely",
  )
  inspect(
    codes(@diagnose.diagnose(flow(), [], tun)),
    content="route-excluded/likely",
  )
}

///|
test "bound socket wins over everything else" {
  inspect(
    codes(@diagnose.diagnose(flow(bound_off_tun=true), [], tun)),
    content="bound-off-tun/certain",
  )
  // A fake-ip destination cannot be reached outside TUN at all.
  let fake = @diagnose.diagnose(
    flow(bound_off_tun=true, peer="198.18.0.15"),
    [],
    tun,
  )
  assert_eq(fake[0].evidence.length(), 3)
  assert_true(fake[0].evidence[2].contains("fake-ip"))
  let real = @diagnose.diagnose(flow(bound_off_tun=true), [], tun)
  assert_eq(real[0].evidence.length(), 2)
}

///|
test "nothing configured" {
  inspect(
    codes(@diagnose.diagnose(flow(), [], @diagnose.Context::default())),
    content="proxy-not-configured/certain",
  )
}

///|
test "system proxy: udp is never carried" {
  inspect(
    codes(@diagnose.diagnose(flow(proto="udp"), [], sysproxy)),
    content="udp-not-proxied/certain",
  )
}

///|
test "system proxy: program ignores it (git evidence included)" {
  let cs = @diagnose.diagnose(
    flow(process="git-remote-https.exe"),
    [],
    sysproxy,
  )
  inspect(codes(cs), content="no-proxy-config/likely")
  inspect(
    cs[0].evidence.join("\n"),
    content=(
      #|system proxy: on (127.0.0.1:7890)
      #|HTTP_PROXY, HTTPS_PROXY, ALL_PROXY: not set in the command's environment
      #|git http.proxy: not set
    ),
  )
}

///|
test "exception lists" {
  let corp = flow(domain="git.corp.example")
  inspect(
    codes(@diagnose.diagnose(corp, [], sysproxy)),
    content="no-proxy-match/likely",
  )
  let env : @diagnose.Context = {
    ..@diagnose.Context::default(),
    env: [
      ("https_proxy", "http://127.0.0.1:7890"),
      ("no_proxy", ".example.com, 10.0.0.0/8"),
    ],
  }
  let cs = @diagnose.diagnose(flow(domain="api.example.com"), [], env)
  inspect(codes(cs), content="no-proxy-match/likely")
  inspect(
    cs[0].evidence[1],
    content="entry \".example.com\" covers tcp api.example.com:443 (203.0.113.5)",
  )
  // A proxy variable is set and nothing explains the bypass.
  inspect(
    codes(@diagnose.diagnose(flow(domain="other.test"), [], env)),
    content="undetermined/undetermined",
  )
}

///|
test "same process used the proxy for other connections" {
  let f = flow()
  let others = [f, flow(entry="proxy-port", domain="cdn.test")]
  inspect(
    codes(@diagnose.diagnose(f, others, sysproxy)),
    content="mixed-in-process/likely",
  )
}

///|
test "matching helpers" {
  assert_true(@diagnose.glob_match("*.corp.example", "Git.Corp.Example"))
  assert_true(@diagnose.glob_match("192.168.*", "192.168.1.20"))
  assert_false(@diagnose.glob_match("*.corp.example", "corp.example.org"))
  assert_true(@diagnose.glob_match("a?c", "abc"))
  assert_eq(
    @diagnose.no_proxy_match(
      "localhost, .example.com",
      "example.com",
      ip("1.1.1.1"),
    ),
    Some(".example.com"),
  )
  assert_eq(
    @diagnose.no_proxy_match("example.com", "notexample.com", ip("1.1.1.1")),
    None,
  )
  assert_eq(
    @diagnose.no_proxy_match("10.0.0.0/8", "", ip("10.2.3.4")),
    Some("10.0.0.0/8"),
  )
  assert_eq(@diagnose.no_proxy_match("*", "", ip("10.2.3.4")), Some("*"))
  assert_eq(
    @diagnose.override_match("<local>;10.*", "intranet", ip("8.8.8.8")),
    Some("<local>"),
  )
  assert_eq(
    @diagnose.override_match("<local>;10.*", "", ip("10.1.1.1")),
    Some("10.*"),
  )
  assert_eq(@diagnose.override_match("<local>", "a.b", ip("8.8.8.8")), None)
}

///|
test "git config proxy" {
  let text =
    #|[user]
    #|  name = someone
    #|[https]
    #|  proxy = http://127.0.0.1:7891
    #|[http "https://example.com"]
    #|  proxy = http://ignored
    #|; [http]
    #|# proxy = commented
  inspect(@diagnose.git_config_proxy(text), content="http://127.0.0.1:7891")
  inspect(
    @diagnose.git_config_proxy(
      "[http]\r\n\tproxy = \"socks5://127.0.0.1:7890\"\r\n",
    ),
    content="socks5://127.0.0.1:7890",
  )
  inspect(@diagnose.git_config_proxy(""), content="")
}
