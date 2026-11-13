"""Sample the installed collector's overhead once a minute.

usage: python -I scripts/sample_overhead.py [MINUTES] [OUT_CSV] [DATA_DIR]

Reads the heartbeat row of ledger.db (read-only; the collector writes it
every 5 s) and the collector's working set from tasklist, and appends one
CSV row per sample. Defaults: 120 minutes, testdata\\raw\\overhead.csv,
%ProgramData%\\netwhere.
"""

import csv
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

FIELDS = ["time", "uptime_s", "state", "cpu_ms", "private_mb", "working_set_mb",
          "events", "dropped", "events_lost", "callback_ns_per_event", "flows", "usage_rows"]


def working_set_mb(pid):
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, timeout=10).stdout
        cell = next(csv.reader([out.strip()]))[4]          # "12,345 K"
        return round(int("".join(ch for ch in cell if ch.isdigit())) / 1024, 1)
    except Exception:
        return ""


def sample(db_path):
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
    try:
        hb = con.execute("SELECT pid, started, updated, state, cpu_ms, private_bytes, events,"
                         " dropped, events_lost, callback_ns, flows FROM heartbeat").fetchone()
        rows = con.execute("SELECT count(*) FROM usage").fetchone()[0]
    finally:
        con.close()
    pid, started, updated, state, cpu, priv, events, dropped, lost, cb, flows = hb
    return {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "uptime_s": (updated - started) // 10_000_000,
        "state": state,
        "cpu_ms": cpu,
        "private_mb": round(priv / 1048576, 1),
        "working_set_mb": working_set_mb(pid),
        "events": events,
        "dropped": dropped,
        "events_lost": lost,
        "callback_ns_per_event": cb // events if events else 0,
        "flows": flows,
        "usage_rows": rows,
    }


def main(argv):
    minutes = int(argv[1]) if len(argv) > 1 else 120
    out = Path(argv[2] if len(argv) > 2 else r"testdata\raw\overhead.csv")
    data = Path(argv[3] if len(argv) > 3 else os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "netwhere"))
    db = data / "ledger.db"
    out.parent.mkdir(parents=True, exist_ok=True)
    new = not out.exists()
    with out.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for i in range(minutes + 1):
            try:
                row = sample(db)
                w.writerow(row)
                f.flush()
                print("%s  cpu %s ms  private %s MB  ws %s MB  events %s  lost %s  dropped %s  %s ns/event" % (
                    row["time"], row["cpu_ms"], row["private_mb"], row["working_set_mb"],
                    row["events"], row["events_lost"], row["dropped"], row["callback_ns_per_event"]), flush=True)
            except Exception as e:
                print("%s  sample failed: %s" % (time.strftime("%H:%M:%S"), e), flush=True)
            if i < minutes:
                time.sleep(60)


if __name__ == "__main__":
    main(sys.argv)
