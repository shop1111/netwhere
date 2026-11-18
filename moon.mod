name = "shop1111/netwhere"

version = "0.3.0"

readme = "README.md"

repository = "https://github.com/shop1111/netwhere"

license = "Apache-2.0"

keywords = [ "windows", "etw", "network", "traffic", "mihomo" ]

description = "Windows per-app traffic route ledger: where each program's traffic goes (direct, proxy node, TUN, LAN), from ETW plus optional Mihomo enrichment."

preferred_target = "native"

supported_targets = [ "native" ]

import {
  "moonbitlang/async@0.22.9",
  "moonbit-community/sqlite3@0.2.5",
}
