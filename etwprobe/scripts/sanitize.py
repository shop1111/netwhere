"""Copy selected raw probe outputs into evidence/, masking machine-specific addresses.

Usage: python -I scripts/sanitize.py evidence/raw evidence
Raw files stay in evidence/raw (git-ignored): they contain this machine's addresses,
DNS servers, proxy node names and other processes' traffic.
"""
import json
import re
import sys
from pathlib import Path

RAW, OUT = Path(sys.argv[1]), Path(sys.argv[2])
FILES = [
    "env.txt", "env-admin.txt", "leak.txt", "check.txt",
    "trace-curl-noproxy.txt", "trace-git-ls-remote.txt", "trace-powershell-iwr.txt",
    "trace-curl-direct-5mb.txt", "trace-curl-proxy-20mb.txt", "trace-curl-proxy-github.txt",
    "tun-env.txt", "tun-trace-curl-baidu.txt", "tun-trace-curl-github.txt",
    "tun-trace-git-ls-remote.txt", "tun-trace-curl-proxyport.txt", "tun-trace-curl-20mb.txt",
]
RULES = [
    (re.compile(r"\b172\.27\.\d+\.\d+\b"), "<LAN-IPv4>"),
    (re.compile(r"\b2001:250:[0-9a-f:]+\b"), "<IPv6>"),
    (re.compile(r"\b10\.8\.\d+\.\d+\b"), "<DNS-server>"),
    (re.compile(r"\b58\.247\.\d+\.\d+:\d+\b"), "<proxy-node>"),
]


def mask(text: str) -> str:
    for pattern, repl in RULES:
        text = pattern.sub(repl, text)
    return text


for name in FILES:
    src = RAW / name
    if src.exists():
        (OUT / name).write_text(mask(src.read_text(encoding="utf-8")), encoding="utf-8")

# Mihomo side of the 20 MB comparison: the connection that matches the ETW source port.
m = re.search(r"PROXY-PORT .*?sport ([0-9,]+)", (RAW / "trace-curl-proxy-20mb.txt").read_text(encoding="utf-8"))
ports = {int(p) for p in m.group(1).split(",")} if m else set()
lines = [f"ETW source port(s) of curl's loopback socket: {sorted(ports)}"]
for i in range(1, 17):
    snap = RAW / f"proxy-20mb-snap-{i}.json"
    if not snap.exists():
        continue
    data = json.loads(snap.read_text(encoding="utf-8"))
    if i == 1:
        lines.append(f"snapshot top-level keys: {sorted(data.keys())}")
    for c in data.get("connections", []):
        md = c["metadata"]
        if int(md.get("sourcePort") or 0) in ports:
            lines.append(
                f"t+{i}s sourcePort={md['sourcePort']} process={md['process']} host={md['host']} "
                f"rule={c['rule']} chains={len(c['chains'])} (node name masked) "
                f"download={c['download']} upload={c['upload']}"
            )
(OUT / "proxy-20mb-mihomo.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("wrote", len(FILES) + 1, "files to", OUT)

# TUN mode: same comparison, plus the TUN-specific metadata fields.
tun_trace = RAW / "tun-trace-curl-20mb.txt"
if tun_trace.exists():
    m = re.search(r"TUN-fake-ip .*?sport ([0-9,]+)", tun_trace.read_text(encoding="utf-8"))
    ports = {int(p) for p in m.group(1).split(",")} if m else set()
    lines = [f"ETW source port(s) of curl's socket to the fake IP: {sorted(ports)}"]
    for i in range(1, 17):
        snap = RAW / f"tun-20mb-snap-{i}.json"
        if not snap.exists():
            continue
        for c in json.loads(snap.read_text(encoding="utf-8")).get("connections", []):
            md = c["metadata"]
            if int(md.get("sourcePort") or 0) in ports:
                lines.append(
                    f"t+{i}s type={md['type']} sourceIP={md['sourceIP']} sourcePort={md['sourcePort']} "
                    f"inboundPort={md['inboundPort']} process={md['process']} host={md['host']} "
                    f"rule={c['rule']} download={c['download']} upload={c['upload']}"
                )
    (OUT / "tun-20mb-mihomo.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
