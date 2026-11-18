// Why did a connection bypass the proxy core? netwhere sees what happened
// (entry "bypass"), not what the program decided. This package turns the
// facts it can observe into candidate causes, each with the evidence used
// and how sure it is. When nothing fits, it says so. Pure; no I/O.

///|
#derive(Eq, Debug)
pub(all) enum Certainty {
  /// Follows from the observed facts alone.
  Certain
  /// Fits the facts, but depends on what the program does internally,
  /// which netwhere cannot see.
  Likely
  /// No rule fits: the facts are listed, no cause is claimed.
  Undetermined
}

///|
pub impl Show for Certainty with fn output(self, logger) {
  logger.write_string(
    match self {
      Certain => "certain"
      Likely => "likely"
      Undetermined => "undetermined"
    },
  )
}

///|
#derive(Eq, Debug)
pub(all) struct Cause {
  /// Stable identifier, e.g. "tun-no-ipv6".
  code : String
  certainty : Certainty
  /// One sentence for the user.
  summary : String
  /// The observed facts the cause rests on.
  evidence : Array[String]
}

///|
/// One connection as `trace` stores it.
#derive(Eq, Debug)
pub(all) struct FlowFacts {
  /// Executable name, e.g. "git-remote-https.exe".
  process : String
  /// "tcp" | "udp"
  proto : String
  peer : @netaddr.IpAddr
  port : Int32
  /// "" when no name is known.
  domain : String
  /// Stored entry label: "proxy-port" | "tun" | "bypass" | "direct" | "lan".
  entry : String
  bound_off_tun : Bool
}

///|
/// What the machine and the command's environment looked like.
pub(all) struct Context {
  /// WinINet system proxy (ProxyEnable) and its settings.
  system_proxy : Bool
  system_proxy_server : String
  /// ProxyOverride, ';'-separated.
  system_proxy_override : String
  /// Proxy variables set in the command's environment, as (name, value):
  /// any of HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY in either case.
  env : Array[(String, String)]
  /// git's http.proxy / https.proxy, "" when unset.
  git_proxy : String
  /// The core's TUN is enabled and its adapter is up.
  tun_enabled : Bool
  /// The TUN adapter has a global IPv6 address.
  tun_has_v6 : Bool
  /// Adapter the route to an address goes through, if it can be looked up.
  route_if : (@netaddr.IpAddr) -> String?
}

///|
pub fn Context::default() -> Context {
  {
    system_proxy: false,
    system_proxy_server: "",
    system_proxy_override: "",
    env: [],
    git_proxy: "",
    tun_enabled: false,
    tun_has_v6: false,
    route_if: _ => None,
  }
}

///|
let proxy_vars : Array[String] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]

///|
fn Context::env_get(self : Context, name : String) -> String? {
  for kv in self.env {
    if kv.0.to_upper() == name && kv.1 != "" {
      return Some(kv.1)
    }
  }
  None
}

///|
/// Proxy variables that are set, as "NAME=value".
fn Context::proxy_env(self : Context) -> Array[String] {
  let out = []
  for kv in self.env {
    if proxy_vars.contains(kv.0.to_upper()) && kv.1 != "" {
      out.push("\{kv.0}=\{kv.1}")
    }
  }
  out
}

///|
fn dest_text(f : FlowFacts) -> String {
  let addr = if f.peer.is_v4() { "\{f.peer}" } else { "[\{f.peer}]" }
  if f.domain == "" {
    "\{f.proto} \{addr}:\{f.port}"
  } else {
    "\{f.proto} \{f.domain}:\{f.port} (\{addr})"
  }
}

///|
fn is_git(process : String) -> Bool {
  let p = process.to_lower()
  p == "git.exe" || p.has_prefix("git-remote-")
}

///|
/// Case-insensitive glob with '*' (any run) and '?' (one character).
pub fn glob_match(pattern : String, text : String) -> Bool {
  let p = pattern.to_lower().to_array()
  let t = text.to_lower().to_array()
  let mut pi = 0
  let mut ti = 0
  let mut star = -1
  let mut mark = 0
  while ti < t.length() {
    if pi < p.length() && (p[pi] == '?' || p[pi] == t[ti]) {
      pi += 1
      ti += 1
    } else if pi < p.length() && p[pi] == '*' {
      star = pi
      mark = ti
      pi += 1
    } else if star >= 0 {
      pi = star + 1
      mark += 1
      ti = mark
    } else {
      return false
    }
  }
  while pi < p.length() && p[pi] == '*' {
    pi += 1
  }
  pi == p.length()
}

///|
fn trim_ws(s : StringView) -> String {
  s.trim(chars=" \t\r").to_owned()
}

///|
/// The NO_PROXY entry (curl semantics) that covers the destination, if any:
/// "*", a host or domain suffix (leading dot optional), an IP or a CIDR.
pub fn no_proxy_match(
  no_proxy : String,
  domain : String,
  ip : @netaddr.IpAddr,
) -> String? {
  let host = domain.to_lower()
  for raw in no_proxy.split(",") {
    let e = trim_ws(raw).to_lower()
    if e == "" {
      continue
    }
    if e == "*" {
      return Some(e)
    }
    if e.contains("/") {
      if @netaddr.Cidr::parse(e) is Some(c) && c.contains(ip) {
        return Some(e)
      }
      continue
    }
    if @netaddr.IpAddr::parse(e) is Some(a) {
      if a == ip {
        return Some(e)
      }
      continue
    }
    let d = if e.has_prefix(".") { e[1:].to_owned() } else { e }
    if host != "" && (host == d || host.has_suffix("." + d)) {
      return Some(e)
    }
  }
  None
}

///|
/// The system proxy exception (ProxyOverride) that covers the destination:
/// '*' wildcards against the name or the address; "<local>" for names
/// without a dot.
pub fn override_match(
  overrides : String,
  domain : String,
  ip : @netaddr.IpAddr,
) -> String? {
  let addr = ip.to_string()
  for raw in overrides.split(";") {
    let e = trim_ws(raw)
    if e == "" {
      continue
    }
    if e.to_lower() == "<local>" {
      if domain != "" && !domain.contains(".") {
        return Some(e)
      }
      continue
    }
    if (domain != "" && glob_match(e, domain)) || glob_match(e, addr) {
      return Some(e)
    }
  }
  None
}

///|
/// The proxy setting in a git config file's text: http.proxy, then
/// https.proxy ("" when neither is set).
pub fn git_config_proxy(text : String) -> String {
  let mut section = ""
  let mut http = ""
  let mut https = ""
  for raw in text.split("\n") {
    let line = trim_ws(raw)
    if line.has_prefix("[") {
      section = line.trim(chars="[] \t").to_owned().to_lower()
      continue
    }
    if line.has_prefix("#") || line.has_prefix(";") {
      continue
    }
    guard line.find("=") is Some(i) else { continue }
    let key = trim_ws(line[:i]).to_lower()
    let value = line[i + 1:].trim(chars=" \t\"").to_owned()
    if key == "proxy" && section == "http" {
      http = value
    } else if key == "proxy" && section == "https" {
      https = value
    }
  }
  if http != "" {
    http
  } else {
    https
  }
}

///|
fn route_fact(ctx : Context, f : FlowFacts) -> Array[String] {
  match (ctx.route_if)(f.peer) {
    Some(name) => ["route to \{f.peer} now goes through adapter \"\{name}\""]
    None => []
  }
}

///|
/// Candidate causes for one connection, most specific first. Only bypass
/// and direct connections get any; the others reached the core.
pub fn diagnose(
  f : FlowFacts,
  same_process : Array[FlowFacts],
  ctx : Context,
) -> Array[Cause] {
  if f.entry == "direct" {
    return [
      {
        code: "no-core",
        certainty: Certain,
        summary: "no proxy core was running, so nothing could carry the traffic",
        evidence: [
          "no process listening on a proxy port or owning a TUN adapter was found",
        ],
      },
    ]
  }
  if f.entry != "bypass" {
    return []
  }
  let causes : Array[Cause] = []
  let dest = dest_text(f)
  if f.bound_off_tun {
    causes.push({
      code: "bound-off-tun",
      certainty: Certain,
      summary: "the program bound its socket to another adapter, so the TUN route did not apply",
      evidence: [
        "route to \{f.peer} pointed at the TUN adapter",
        "but the connection's local address is outside the TUN network",
      ],
    })
  } else if ctx.tun_enabled {
    if !f.peer.is_v4() && !ctx.tun_has_v6 {
      let evidence = [
        "destination \{dest} is IPv6",
        "the TUN adapter has no global IPv6 address",
      ]
      evidence.append(route_fact(ctx, f))
      causes.push({
        code: "tun-no-ipv6",
        certainty: Certain,
        summary: "TUN carries only IPv4; IPv6 traffic leaves through the physical adapter",
        evidence,
      })
    } else {
      let evidence = ["TUN is on, but \{dest} was routed elsewhere"]
      evidence.append(route_fact(ctx, f))
      causes.push({
        code: "route-excluded",
        certainty: Likely,
        summary: "the route to this address does not go through TUN (route-exclude-address, a more specific route, or strict-route off)",
        evidence,
      })
    }
  } else {
    let env = ctx.proxy_env()
    if !ctx.system_proxy && env.length() == 0 && ctx.git_proxy == "" {
      causes.push({
        code: "proxy-not-configured",
        certainty: Certain,
        summary: "TUN and the system proxy are off and no proxy variable is set: nothing sends this traffic to the core",
        evidence: [
          "TUN: off", "system proxy: off", "HTTP_PROXY, HTTPS_PROXY, ALL_PROXY: not set",
        ],
      })
    } else if f.proto == "udp" {
      causes.push({
        code: "udp-not-proxied",
        certainty: Certain,
        summary: "the system proxy and proxy variables only carry TCP; UDP (QUIC, DNS) goes direct unless TUN is on",
        evidence: ["\{dest} is UDP", "TUN: off"],
      })
    } else {
      match ctx.env_get("NO_PROXY") {
        Some(np) =>
          if no_proxy_match(np, f.domain, f.peer) is Some(e) {
            causes.push({
              code: "no-proxy-match",
              certainty: Likely,
              summary: "the destination is on the NO_PROXY list",
              evidence: ["NO_PROXY=\{np}", "entry \"\{e}\" covers \{dest}"],
            })
          }
        None => ()
      }
      if ctx.system_proxy &&
        override_match(ctx.system_proxy_override, f.domain, f.peer) is Some(e) {
        causes.push({
          code: "no-proxy-match",
          certainty: Likely,
          summary: "the destination is on the system proxy's exception list",
          evidence: [
            "system proxy exceptions: \{ctx.system_proxy_override}",
            "entry \"\{e}\" covers \{dest}",
          ],
        })
      }
      if same_process.iter().any(o => o.entry == "proxy-port") {
        causes.push({
          code: "mixed-in-process",
          certainty: Likely,
          summary: "the same process sent other connections through the proxy, so it chose to connect directly here (its own exceptions or a second network library)",
          evidence: ["\{f.process} also connected through the proxy port"],
        })
      }
      if causes.length() == 0 && env.length() == 0 && ctx.system_proxy {
        let evidence = [
          if ctx.system_proxy_server == "" {
            "system proxy: on"
          } else {
            "system proxy: on (\{ctx.system_proxy_server})"
          },
          "HTTP_PROXY, HTTPS_PROXY, ALL_PROXY: not set in the command's environment",
        ]
        if is_git(f.process) {
          evidence.push(
            if ctx.git_proxy == "" {
              "git http.proxy: not set"
            } else {
              "git http.proxy: \{ctx.git_proxy}"
            },
          )
        }
        causes.push({
          code: "no-proxy-config",
          certainty: Likely,
          summary: "the program does not read the Windows system proxy, and no proxy variable told it otherwise",
          evidence,
        })
      }
      if causes.length() == 0 && env.length() > 0 {
        causes.push({
          code: "undetermined",
          certainty: Undetermined,
          summary: "a proxy variable is set, yet the program connected directly: it ignores the variable, or reads another one",
          evidence: env,
        })
      }
    }
  }
  if causes.length() == 0 {
    let evidence = [
      "\{dest} bypassed the core",
      "TUN: \{if ctx.tun_enabled { "on" } else { "off" }}",
      "system proxy: \{if ctx.system_proxy { "on" } else { "off" }}",
    ]
    evidence.append(route_fact(ctx, f))
    causes.push({
      code: "undetermined",
      certainty: Undetermined,
      summary: "no known cause fits the observed facts",
      evidence,
    })
  }
  causes
}

///|
/// "  code (certainty): summary" and one "      - fact" line per evidence.
pub fn cause_text(c : Cause) -> String {
  let buf = StringBuilder()
  buf.write_string("  \{c.code} (\{c.certainty}): \{c.summary}\n")
  for e in c.evidence {
    buf.write_string("      - \{e}\n")
  }
  buf.to_string()
}
