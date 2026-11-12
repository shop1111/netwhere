// Known-outcome scenarios (PLAN.md section 6): a manifest written by
// scripts/record-scenarios.ps1 names each scenario's root pid and what its
// traffic must look like; `check` replays the recording and compares.
//
// Expectation fields:
//   process   executable whose flows are checked (within the scenario's tree)
//   entry     "proxy-port" | "tun" | "bypass" | "direct" | "lan", or
//             "route" = anything but proxy-port (decided by the route table)
//   exit      "core" = any core outbound (node, DIRECT, REJECT);
//             "node" = a proxy node; "-" = never entered a core; "any";
//             or an exact label
//   down_min  minimum bytes received by the matching flows
//   only      every flow of the process must match entry and exit

///|
#derive(Eq, Debug)
pub(all) struct Expect {
  process : String
  entry : String
  exit : String
  down_min : Int64
  only : Bool
}

///|
#derive(Eq, Debug)
pub(all) struct Scenario {
  name : String
  pid : Int32
  exit_code : Int32
  expect : Array[Expect]
}

///|
#derive(Eq, Debug)
pub(all) struct Manifest {
  mode : String
  recording : String
  scenarios : Array[Scenario]
}

///|
#derive(Debug)
pub(all) suberror ManifestError {
  ManifestError(String)
}

///|
pub impl Show for ManifestError with fn output(self, logger) {
  let ManifestError(m) = self
  logger.write_string("manifest: " + m)
}

///|
fn str_field(m : Map[String, Json], k : String) -> String raise ManifestError {
  match m.get(k) {
    Some(String(s)) => s
    _ => raise ManifestError("missing string \"\{k}\"")
  }
}

///|
fn num_field(
  m : Map[String, Json],
  k : String,
  default : Double,
) -> Double raise ManifestError {
  match m.get(k) {
    Some(Number(d, ..)) => d
    None | Some(Null) => default
    _ => raise ManifestError("\"\{k}\" is not a number")
  }
}

///|
pub fn parse_manifest(text : StringView) -> Manifest raise ManifestError {
  // PowerShell 5 writes UTF-8 with a byte-order mark.
  let text = match text.strip_prefix("\u{feff}") {
    Some(t) => t
    None => text
  }
  let j = @json.parse(text) catch {
    e => raise ManifestError("invalid JSON: \{e}")
  }
  guard j is Object(top) else { raise ManifestError("not an object") }
  let scenarios = []
  // ConvertTo-Json turns a one-element array into a bare object.
  let items = match top.get("scenarios") {
    Some(Array(xs)) => xs
    Some(Object(_) as one) => [one]
    _ => []
  }
  for s in items {
    guard s is Object(sm) else {
      raise ManifestError("scenario is not an object")
    }
    let expects = []
    let raw = match sm.get("expect") {
      Some(Array(xs)) => xs
      Some(Object(_) as one) => [one]
      _ => []
    }
    for e in raw {
      guard e is Object(em) else {
        raise ManifestError("expect is not an object")
      }
      expects.push({
        process: str_field(em, "process").to_lower(),
        entry: str_field(em, "entry"),
        exit: str_field(em, "exit"),
        down_min: num_field(em, "down_min", 0.0).to_int64(),
        only: em.get("only") is Some(True),
      })
    }
    scenarios.push({
      name: str_field(sm, "name"),
      pid: num_field(sm, "pid", 0.0).to_int(),
      exit_code: num_field(sm, "exit_code", 0.0).to_int(),
      expect: expects,
    })
  }
  {
    mode: str_field(top, "mode"),
    recording: str_field(top, "recording"),
    scenarios,
  }
}

///|
#derive(Eq, Debug)
pub(all) enum Outcome {
  Pass(String)
  Fail(String)
  Skip(String)
}

///|
fn entry_ok(want : String, got : @ledger.Entry, core_present : Bool) -> Bool {
  match want {
    "route" => got != ProxyPort
    w => @report.entry_label(got, core_present) == w
  }
}

///|
fn exit_ok(want : String, got : @ledger.Exit) -> Bool {
  match (want, got) {
    ("any", _) => true
    ("core", Node(_) | CoreDirect | CoreReject) => true
    ("node", Node(_)) => true
    ("-", NotProxied) => true
    (w, g) => @report.exit_label(g) == w
  }
}

///|
fn describe(f : @ledger.FlowSummary, core_present : Bool) -> String {
  "\{f.proto} \{f.peer} \{@report.entry_label(f.entry, core_present)}/\{@report.exit_label(f.exit)} down=\{f.down}"
}

///|
/// Checks every scenario of the manifest against the replayed recording.
pub fn check(m : Manifest, rec : @ledger.Recording) -> Array[(String, Outcome)] {
  let (engine, _) = @ledger.replay(rec)
  let core = engine.core_present()
  let all = engine.flows()
  let out = []
  for s in m.scenarios {
    if s.exit_code != 0 {
      out.push((s.name, Skip("command exited with \{s.exit_code}")))
      continue
    }
    let tree = engine.process_tree(s.pid)
    let flows = all.filter(f => tree.contains(f.pid))
    let problems = []
    let notes = []
    for e in s.expect {
      let mine = flows.filter(f => {
        @ledger.base_name(f.process).to_lower() == e.process
      })
      if mine.length() == 0 {
        problems.push("no flows for \{e.process}")
        continue
      }
      let matching = mine.filter(f => {
        entry_ok(e.entry, f.entry, core) && exit_ok(e.exit, f.exit)
      })
      let down = matching.fold(init=0L, (acc, f) => acc + f.down)
      if down < e.down_min {
        problems.push(
          "\{e.process}: \{e.entry}/\{e.exit} received \{down} B, expected at least \{e.down_min} B; flows: " +
          mine.map(f => describe(f, core)).join("; "),
        )
        continue
      }
      if e.only && matching.length() < mine.length() {
        let others = mine.filter(f => {
          !(entry_ok(e.entry, f.entry, core) && exit_ok(e.exit, f.exit))
        })
        problems.push(
          "\{e.process}: unexpected flows: " +
          others.map(f => describe(f, core)).join("; "),
        )
        continue
      }
      notes.push(
        "\{e.process} \{e.entry}/\{e.exit} \{@report.human_bytes(down)}",
      )
    }
    out.push(
      (
        s.name,
        if problems.length() > 0 {
          Fail(problems.join("\n  "))
        } else {
          Pass(notes.join(", "))
        },
      ),
    )
  }
  out
}

///|
pub fn outcome_text(results : Array[(String, Outcome)]) -> String {
  results
  .map(r => {
    match r.1 {
      Pass(m) => "PASS \{r.0}: \{m}"
      Fail(m) => "FAIL \{r.0}:\n  \{m}"
      Skip(m) => "SKIP \{r.0}: \{m}"
    }
  })
  .join("\n")
}
