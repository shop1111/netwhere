///|
fn ip(s : String) -> @netaddr.IpAddr {
  @netaddr.IpAddr::parse(s).unwrap()
}

///|
test "ipv4 parse and print" {
  inspect(ip("10.0.0.5"), content="10.0.0.5")
  inspect(@netaddr.IpAddr::v4(198, 18, 0, 1), content="198.18.0.1")
  for bad in ["256.1.1.1", "1.2.3", "1.2.3.4.5", "", "1..2.3", "a.b.c.d"] {
    assert_true(@netaddr.IpAddr::parse(bad) is None, msg=bad)
  }
}

///|
test "ipv6 forms from etw, dns and mihomo agree" {
  // ETW prints uncompressed groups; DNS-Client and Mihomo compress them.
  assert_eq(ip("2603:1030:807:14:0:0:0:43a"), ip("2603:1030:807:14::43a"))
  inspect(ip("2603:1030:807:14:0:0:0:43a"), content="2603:1030:807:14::43a")
  inspect(
    ip("2001:db8:3002:3250:0:0:2:daef"),
    content="2001:db8:3002:3250::2:daef",
  )
  inspect(ip("::1"), content="::1")
  inspect(ip("::"), content="::")
  inspect(ip("FE80::45AF:8123%12"), content="fe80::45af:8123")
  inspect(ip("[2606:4700:7::da]"), content="2606:4700:7::da")
  // RFC 5952: a single zero group is not compressed; first longest run wins.
  inspect(ip("1:0:2:3:4:5:6:7"), content="1:0:2:3:4:5:6:7")
  inspect(ip("1:0:0:2:0:0:3:4"), content="1::2:0:0:3:4")
  inspect(ip("1:0:0:2:0:0:0:4"), content="1:0:0:2::4")
}

///|
test "ipv6 rejects malformed text" {
  for
    bad in [
      "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::", ":::", "g::1",
      "1:2:3:4:5:6:7::8",
    ] {
    assert_true(@netaddr.IpAddr::parse(bad) is None, msg=bad)
  }
}

///|
test "ipv4 mapped ipv6" {
  let m = ip("::ffff:127.0.0.1")
  inspect(m, content="::ffff:127.0.0.1")
  inspect(m.unmap(), content="127.0.0.1")
  assert_true(m.is_loopback())
}

///|
test "address classes" {
  assert_true(ip("127.0.0.1").is_loopback())
  assert_true(ip("::1").is_loopback())
  assert_false(ip("198.18.0.1").is_loopback())
  for
    s in ["10.0.0.53", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1"] {
    assert_true(ip(s).is_private(), msg=s)
  }
  for s in ["172.32.0.1", "198.18.0.1", "8.8.8.8", "2001:db8::1"] {
    assert_false(ip(s).is_private(), msg=s)
  }
  assert_true(ip("169.254.3.4").is_link_local())
  assert_true(ip("fe80::1").is_link_local())
  assert_false(ip("fec0::1").is_link_local())
  assert_true(ip("224.0.0.251").is_multicast())
  assert_true(ip("ff02::fb").is_multicast())
  assert_true(ip("0.0.0.0").is_unspecified())
}

///|
test "cidr contains" {
  let tun = @netaddr.Cidr::parse("198.18.0.1/30").unwrap()
  assert_true(tun.contains(ip("198.18.0.2")))
  assert_false(tun.contains(ip("198.18.0.5")))
  let fake = @netaddr.Cidr::parse("198.18.0.0/15").unwrap()
  assert_true(fake.contains(ip("198.19.255.1")))
  let ula = @netaddr.Cidr::parse("fc00::/7").unwrap()
  assert_true(ula.contains(ip("fd12::1")))
  assert_false(ula.contains(ip("fe80::1")))
  let v6_64 = @netaddr.Cidr::parse("2001:db8:3002:3250::/64").unwrap()
  assert_true(v6_64.contains(ip("2001:db8:3002:3250::2:daef")))
  let v6_96 = @netaddr.Cidr::parse("2001:db8::/96").unwrap()
  assert_true(v6_96.contains(ip("2001:db8::1.2.3.4")))
  assert_false(v6_96.contains(ip("2001:db8::1:0:0")))
  // Families never match each other; mapped IPv4 matches IPv4 prefixes.
  assert_false(tun.contains(ip("::1")))
  assert_true(tun.contains(ip("::ffff:198.18.0.2")))
  assert_true(
    @netaddr.Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")),
  )
  assert_true(@netaddr.Cidr::parse("10.0.0.0/33") is None)
  assert_true(@netaddr.Cidr::parse("10.0.0.0/") is None)
}
