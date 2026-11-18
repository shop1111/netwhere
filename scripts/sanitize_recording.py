"""Sanitize a scenario recording before it is committed as test data.

usage: python -I scripts/sanitize_recording.py RAW_MANIFEST OUT_DIR [--redact-domain D ...]

Reads <mode>.manifest.json written by record-scenarios.ps1 and the recording
next to it, and writes OUT_DIR/<mode>.ndjson and OUT_DIR/<mode>.manifest.json.

What it does:
  * keeps only what the scenarios need: records of the scenario process trees
    and of the proxy core; Mihomo connections and log lines of those
    processes; route facts for kept peers; core listeners. Everything else
    the machine did during the recording (other apps, their DNS) is dropped;
  * maps this machine's own addresses and every private/link-local address
    to documentation addresses, consistently (fake-ip 198.18.0.0/15 and
    loopback stay as they are);
  * renames proxy nodes and policy groups ("Node A", "Group 1"); clears
    remoteDestination and inboundUser; replaces C:\\Users\\<name>;
  * replaces given domains (and subdomains) with example.* names.
"""

import ipaddress
import json
import re
import sys
from pathlib import Path

KEEP_OUTBOUNDS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "COMPATIBLE"}
TCP_IDS = set(range(10, 17)) | set(range(26, 33))
UDP_SEND = {42, 58}
UDP_RECV = {43, 59}
FAKE_IP = ipaddress.ip_network("198.18.0.0/15")

IPV4_RE = re.compile(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F.]{0,15})(?![\w:])")
# "[id duration] kind/type[tag]: message" (sing-box).
SINGBOX_RE = re.compile(
    r"^\[(?P<id>\d+) (?P<dur>[^\]]*)\] (?P<kind>inbound|outbound)/(?P<type>[^\[]+)"
    r"\[(?P<tag>.*?)\]: (?P<msg>.*)$")
USER_RE = re.compile(r"(?i)(C:\\\\?Users\\\\?)[^\\\"/]+")


def die(msg):
    print("sanitize: " + msg, file=sys.stderr)
    sys.exit(1)


class AddrMap:
    def __init__(self):
        self.map = {}
        self.n4 = 0
        self.n6 = 0
        self.nll = 0

    def needs(self, ip, local):
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        if ip.version == 4 and ip in FAKE_IP:
            return False
        if getattr(ip, "ipv4_mapped", None):
            return self.needs(ip.ipv4_mapped, local)
        return local or ip.is_private or ip.is_link_local

    def get(self, text, local=False):
        try:
            ip = ipaddress.ip_address(text.split("%")[0])
        except ValueError:
            return text
        if not self.needs(ip, local) and ip.compressed not in self.map:
            return text
        key = ip.compressed
        if key not in self.map:
            if ip.version == 4:
                self.n4 += 1
                self.map[key] = "10.0.%d.%d" % (self.n4 // 250, 5 + self.n4 % 250)
            elif ip.is_link_local:
                self.nll += 1
                self.map[key] = "fe80::%x" % self.nll
            else:
                self.n6 += 1
                self.map[key] = "2001:db8::%x" % (0x100 + self.n6)
        return self.map[key]

    def in_text(self, s):
        s = IPV4_RE.sub(lambda m: self.get(m.group(1)), s)
        return IPV6_RE.sub(lambda m: self.get(m.group(1)) if ":" in m.group(1) else m.group(1), s)


class NameMap:
    def __init__(self):
        self.nodes = {}
        self.groups = {}

    def node(self, n):
        if n in KEEP_OUTBOUNDS or n == "":
            return n
        if n not in self.nodes:
            self.nodes[n] = "Node " + chr(ord("A") + len(self.nodes) % 26) + (
                str(len(self.nodes) // 26) if len(self.nodes) >= 26 else "")
        return self.nodes[n]

    def group(self, n):
        if n in KEEP_OUTBOUNDS or n == "" or n in self.nodes:
            return self.nodes.get(n, n)
        if n not in self.groups:
            self.groups[n] = "Group %d" % (len(self.groups) + 1)
        return self.groups[n]

    def chain_text(self, chain):
        # "Last[First]" or a single name
        if chain.endswith("]") and "[" in chain[1:]:
            i = chain.index("[")
            return "%s[%s]" % (self.group(chain[:i]), self.node(chain[i + 1:-1]))
        return self.node(chain)


def base_name(path):
    return re.split(r"[\\/]", path)[-1].lower()


def main(argv):
    if len(argv) < 3:
        die(__doc__)
    manifest_path = Path(argv[1])
    out_dir = Path(argv[2])
    domains = []
    rest = argv[3:]
    while rest:
        if rest[0] == "--redact-domain" and len(rest) > 1:
            domains.append(rest[1].lower().strip("."))
            rest = rest[2:]
        else:
            die("unknown argument " + rest[0])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rec_path = manifest_path.parent / manifest["recording"]
    lines = [l for l in rec_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    header = json.loads(lines[0])
    records = [json.loads(l) for l in lines[1:]]

    # ---- which processes to keep
    parents = {p[0]: p[1] for p in header.get("procs", [])}
    images = {p[0]: p[2] for p in header.get("procs", [])}
    for r in records:
        if r["k"] == "pstart":
            parents[r["pid"]] = r["ppid"]
            images[r["pid"]] = r["image"]
    keep = {c["pid"] for c in header["cores"]}
    roots = [s["pid"] for s in manifest["scenarios"]]
    frontier = list(roots)
    keep.update(roots)
    while frontier:
        p = frontier.pop()
        for child, parent in parents.items():
            if parent == p and child not in keep:
                keep.add(child)
                frontier.append(child)
    names = {base_name(images[p]) for p in keep if p in images}

    # ---- the machine's own addresses (local side of kept sockets)
    addrs = AddrMap()
    for r in records:
        if r["k"] == "net" and r["pid"] in keep:
            if r["id"] in TCP_IDS or r["id"] in UDP_SEND:
                addrs.get(r["sa"], local=True)
            elif r["id"] in UDP_RECV:
                addrs.get(r["da"], local=True)

    # Remote addresses of the core's own outbound connections are proxy
    # servers (subscription nodes) or its upstream DNS: replace them too.
    core_pids = {c["pid"] for c in header["cores"]}
    upstream = {}

    def upstream_addr(a):
        if a not in upstream:
            n = len(upstream) + 1
            try:
                v6 = ipaddress.ip_address(a).version == 6
            except ValueError:
                return a
            upstream[a] = ("2001:db8:ffff::%x" % n) if v6 else ("203.0.113.%d" % n)
        return upstream[a]

    for r in records:
        if r["k"] == "net" and r["pid"] in core_pids:
            remote = r["sa"] if r["id"] in UDP_RECV else r["da"]
            try:
                ip = ipaddress.ip_address(remote)
            except ValueError:
                continue
            if not (ip.is_loopback or ip.is_private or (ip.version == 4 and ip in FAKE_IP)):
                upstream_addr(remote)

    names_map = NameMap()

    # Local ports of the kept application sockets. sing-box reports no
    # process unless find_process is on, so its connections and log lines
    # are claimed by source port instead.
    app_ports = {r["sp"] for r in records
                 if r["k"] == "net" and r["pid"] in keep and r["pid"] not in core_pids}

    # sing-box logs one connection over several "[id dur] kind/type[tag]: msg"
    # lines. Keep the ids whose inbound source port is an application port;
    # direct/block outbound tags are kept as they are (they name no node).
    singbox_ids = set()
    for r in records:
        if r["k"] != "mlog":
            continue
        m = SINGBOX_RE.match(r["line"])
        if not m:
            continue
        src = re.search(r"connection from \S*:(\d+)$", m["msg"])
        if m["kind"] == "inbound" and src and int(src.group(1)) in app_ports:
            singbox_ids.add(m["id"])
        if m["kind"] == "outbound" and m["type"] in ("direct", "block"):
            KEEP_OUTBOUNDS.add(m["tag"])

    def redact_domain(s):
        for d in domains:
            s = re.sub(r"(?i)\b([\w-]+\.)*" + re.escape(d) + r"\b",
                       "example-%d.test" % (domains.index(d) + 1), s)
        return s

    def scrub(s):
        return redact_domain(USER_RE.sub(r"\1user", addrs.in_text(s)))

    out = []
    kept_peers = set()
    dropped = {}

    def drop(kind):
        dropped[kind] = dropped.get(kind, 0) + 1

    for r in records:
        k = r["k"]
        if k == "net":
            if r["pid"] not in keep:
                drop(k)
                continue
            r["sa"] = upstream.get(r["sa"]) or addrs.get(r["sa"])
            r["da"] = upstream.get(r["da"]) or addrs.get(r["da"])
            kept_peers.add(r["da"])
            kept_peers.add(r["sa"])
        elif k == "dns":
            if r.get("cpid", r["hpid"]) not in keep:
                drop(k)
                continue
            r["name"] = redact_domain(r["name"])
            r["res"] = scrub(r["res"])
        elif k in ("pstart", "pstop"):
            if r["pid"] not in keep:
                drop(k)
                continue
            if k == "pstart":
                r["image"] = scrub(r["image"])
        elif k == "msnap":
            conns = (r["body"].get("connections") or [])
            kept = []
            for c in conns:
                md = c.get("metadata", {})
                proc = (md.get("process") or "").lower() or base_name(
                    re.sub(r" \(.*\)$", "", md.get("processPath") or ""))
                if proc:
                    if proc not in names:
                        continue
                elif int(md.get("sourcePort") or 0) not in app_ports:
                    continue
                for f in ("sourceIP", "destinationIP", "inboundIP"):
                    if md.get(f):
                        md[f] = addrs.get(md[f])
                md["remoteDestination"] = ""
                md["inboundUser"] = ""
                md["processPath"] = scrub(md.get("processPath", ""))
                for f in ("host", "sniffHost"):
                    md[f] = redact_domain(md.get(f, ""))
                chains = c.get("chains") or []
                c["chains"] = [names_map.node(x) if i == 0 else names_map.group(x)
                               for i, x in enumerate(chains)]
                c["providerChains"] = ["" for _ in c.get("providerChains") or []]
                kept.append(c)
            if not kept:
                drop(k)
                continue
            r["body"] = {"downloadTotal": 0, "uploadTotal": 0, "connections": kept}
        elif k == "mlog" and SINGBOX_RE.match(r["line"]):
            m = SINGBOX_RE.match(r["line"])
            if m["id"] not in singbox_ids:
                drop(k)
                continue
            tag = names_map.node(m["tag"]) if m["kind"] == "outbound" else m["tag"]
            r["line"] = "[%s %s] %s/%s[%s]: %s" % (
                m["id"], m["dur"], m["kind"], m["type"], tag, scrub(m["msg"]))
        elif k == "mlog":
            m = re.search(r"\(([^),]+)", r["line"])
            if not m or m.group(1).lower() not in names:
                drop(k)
                continue
            line = r["line"]
            u = line.rfind(" using ")
            if u >= 0:
                line = line[:u + 7] + names_map.chain_text(line[u + 7:])
            r["line"] = scrub(line)
        elif k == "route":
            r["dst"] = upstream.get(r["dst"]) or addrs.get(r["dst"])
            r["ifname"] = "TUN" if r["tun"] else "LAN"
        elif k == "listen":
            r["items"] = [l for l in r["items"] if l["pid"] in keep]
            for l in r["items"]:
                l["addr"] = addrs.get(l["addr"])
        out.append(r)

    # Routes only for peers that kept flows use.
    out = [r for r in out if r["k"] != "route" or r["dst"] in kept_peers]

    header["procs"] = [[p[0], p[1], scrub(p[2])] for p in header.get("procs", []) if p[0] in keep]
    header["listeners"] = [l for l in header["listeners"] if l["pid"] in keep]
    for l in header["listeners"]:
        l["addr"] = addrs.get(l["addr"])
    for t in header["tun"]:
        t["ifname"] = "TUN"
        nets = [(p, ipaddress.ip_network(p, strict=False)) for p in t["prefixes"]]
        t["prefixes"] = [p for p, n in nets if n.version == 4 and n.subnet_of(FAKE_IP)]
    header["note"] = scrub(header.get("note", ""))
    # Older recordings lack the controller; the manifest has it.
    if not header.get("controller"):
        header["controller"] = manifest.get("controller", "127.0.0.1:9090")

    out_dir.mkdir(parents=True, exist_ok=True)
    mode = manifest["mode"]
    text = "\n".join(json.dumps(x, ensure_ascii=False, separators=(",", ":")) for x in [header] + out) + "\n"
    (out_dir / (mode + ".ndjson")).write_text(text, encoding="utf-8", newline="\n")
    for s in manifest["scenarios"]:
        s["command"] = scrub(s["command"])
    manifest["recording"] = mode + ".ndjson"
    (out_dir / (mode + ".manifest.json")).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    print("kept %d of %d records; dropped %s" % (len(out), len(records),
          ", ".join("%s=%d" % kv for kv in sorted(dropped.items())) or "nothing"))
    print("kept processes: %s" % ", ".join(sorted(names)))
    print("mapped %d addresses, %d core upstreams, %d nodes, %d groups" % (
        len(addrs.map), len(upstream), len(names_map.nodes), len(names_map.groups)))
    print("review before committing: %s" % (out_dir / (mode + ".ndjson")))


if __name__ == "__main__":
    main(sys.argv)
