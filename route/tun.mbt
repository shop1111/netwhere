// Which adapters are the proxy core's TUN.

///|
/// IF_TYPE_PROP_VIRTUAL: what Wintun adapters (Mihomo, sing-box, WireGuard)
/// report as their interface type.
pub let if_type_prop_virtual : Int32 = 53

///|
/// The TUN adapters of the running core.
///
/// - When the core describes its TUN (Mihomo's /configs): the up adapters
///   matching its device name or holding an address in a configured prefix.
/// - When it does not (sing-box's Clash API reports "tun": null): the
///   adapter the route to the internet goes through (`internet_if`), if it
///   is an up virtual adapter (Wintun) rather than a physical one. Another
///   Wintun VPN carrying the default route would be mistaken for the core's
///   TUN; its flows then show as "tun" with no core record ("!").
pub fn find_tun(
  config : @mihomo.CoreConfig?,
  ifs : Array[Interface],
  internet_if : Int32?,
) -> Array[Interface] {
  guard config is Some(c) else { return [] }
  if c.tun_known {
    guard c.tun_enabled else { return [] }
    return ifs.filter(i => {
      let by_name = c.tun_device != "" && i.name == c.tun_device
      let by_prefix = i.prefixes
        .iter()
        .any(p => c.tun_prefixes.iter().any(t => t.contains(p.addr)))
      i.up && (by_name || by_prefix)
    })
  }
  guard internet_if is Some(idx) else { return [] }
  ifs.filter(i => {
    let is_virtual = i.if_type == if_type_prop_virtual ||
      i.description.to_lower().contains("wintun") ||
      i.name.to_lower().contains("tun")
    i.if_index == idx && i.up && is_virtual
  })
}

///|
/// The adapter the route to a public address goes through (1.1.1.1, then
/// 8.8.8.8), if a route can be looked up.
pub fn internet_route_if() -> Int32? {
  for a in ["1.1.1.1", "8.8.8.8"] {
    match @netaddr.IpAddr::parse(a) {
      Some(ip) => {
        let r = best_route(ip) catch { _ => continue }
        return Some(r.if_index)
      }
      None => ()
    }
  }
  None
}
