// These tests query the live machine. They assert only what holds on any
// Windows host (loopback routing, a loopback adapter, a system drive).

///|
test "loopback destinations route through the loopback interface" {
  let r4 = @route.best_route(@netaddr.IpAddr::v4(127, 0, 0, 1))
  let ifs = @route.interfaces()
  let lo = ifs.filter(i => i.if_type == 24) // IF_TYPE_SOFTWARE_LOOPBACK
  assert_true(lo.length() >= 1, msg="no loopback adapter")
  assert_eq(r4.if_index, lo[0].if_index)
  assert_eq(r4.source, Some(@netaddr.IpAddr::v4(127, 0, 0, 1)))
  let r6 = @route.best_route(@netaddr.IpAddr::parse("::1").unwrap())
  assert_eq(r6.if_index, lo[0].if_index)
}

///|
test "interfaces carry prefixes" {
  let ifs = @route.interfaces()
  let lo = ifs.filter(i => i.if_type == 24)[0]
  assert_true(
    lo.prefixes.iter().any(p => p.contains(@netaddr.IpAddr::v4(127, 0, 0, 1))),
    msg="loopback adapter lacks 127.0.0.1",
  )
}

///|
test "tcp listeners are readable without elevation" {
  // Every Windows host listens on RPC endpoint mapper port 135.
  let ls = @route.tcp_listeners()
  assert_true(ls.iter().any(l => l.port == 135), msg="no listener on 135")
  assert_true(ls.iter().all(l => l.port > 0 && l.port < 65536))
}

///|
test "dos devices include the system drive" {
  let ds = @route.dos_devices()
  assert_true(
    ds.iter().any(d => d.1 == "C:" && d.0.has_prefix("\\Device\\")),
    msg="C: is not mapped to an NT device",
  )
}

///|
fn iface(
  idx : Int32,
  name : String,
  if_type : Int32,
  prefix : String,
) -> @route.Interface {
  {
    if_index: idx,
    if_type,
    up: true,
    name,
    description: "",
    prefixes: [@netaddr.Cidr::parse(prefix).unwrap()],
  }
}

///|
test "find_tun: by the core's description, else the virtual internet adapter" {
  let wlan = iface(2, "WLAN", 71, "192.168.1.10/24")
  let tun = iface(47, "singbox_tun", 53, "172.19.0.1/30")
  let ifs = [wlan, tun]
  let mihomo : @mihomo.CoreConfig = {
    ports: [7890],
    tun_known: true,
    tun_enabled: true,
    tun_device: "",
    tun_prefixes: [@netaddr.Cidr::parse("172.19.0.1/30").unwrap()],
  }
  assert_eq(@route.find_tun(Some(mihomo), ifs, Some(2)).map(i => i.if_index), [
    47,
  ])
  // Mihomo says TUN is off: no guessing.
  assert_eq(
    @route.find_tun(Some({ ..mihomo, tun_enabled: false, }), ifs, Some(47)),
    [],
  )
  // sing-box: no TUN description; the internet route decides.
  let singbox = {
    ..mihomo,
    tun_known: false,
    tun_enabled: false,
    tun_prefixes: [],
  }
  assert_eq(
    @route.find_tun(Some(singbox), ifs, Some(47)).map(i => i.if_index),
    [47],
  )
  // The internet goes through the physical adapter: no TUN.
  assert_eq(@route.find_tun(Some(singbox), ifs, Some(2)), [])
  // No controller answer at all: nothing.
  assert_eq(@route.find_tun(None, ifs, Some(47)), [])
}
