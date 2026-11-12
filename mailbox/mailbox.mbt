// Mailbox protocol between unprivileged clients and the collector
// (PLAN.md section 3). Clients drop small JSON files into requests\; the
// collector, which runs elevated, parses them here with MoonBit code only,
// validates everything, and keeps the request state machine. This file is
// pure: the collector supplies the facts it needs through Checks and turns
// the returned effects into database writes and tracking changes.
//
// Message file: {"v":1,"id":"…","kind":"trace|pause|resume",
//                "op":"start|root|done","client_pid":N,"root_pid":N}
// File name: <id>.<seq>.json, written as .tmp then renamed.

///|
pub let max_message_bytes : Int32 = 4096

///|
pub let max_active_traces : Int32 = 4

///|
/// A Ready trace whose root is not reported within this time expires.
pub let ready_timeout : Int64 = 300_000_000L // 30 s

///|
/// A root whose parent is not confirmed within this time is rejected.
pub let root_confirm_timeout : Int64 = 50_000_000L // 5 s

///|
/// Longest trace by default.
pub let max_trace : Int64 = 6_000_000_000L // 10 min

///|
/// Wait after "done" for ETW to deliver the tail (it flushes every second).
pub let finish_delay : Int64 = 20_000_000L // 2 s

///|
#derive(Eq, Debug)
pub(all) enum Kind {
  Trace
  Pause
  Resume
}

///|
#derive(Eq, Debug)
pub(all) enum Op {
  Start
  Root
  Done
}

///|
#derive(Eq, Debug)
pub(all) struct Message {
  id : String
  kind : Kind
  op : Op
  client_pid : Int32
  root_pid : Int32
}

///|
fn valid_id(id : String) -> Bool {
  if id.length() < 8 || id.length() > 64 {
    return false
  }
  for c in id {
    match c {
      'a'..<='z' | 'A'..<='Z' | '0'..<='9' | '-' => ()
      _ => return false
    }
  }
  true
}

///|
#derive(Debug)
pub(all) suberror MessageError {
  MessageError(String)
}

///|
/// Parses and validates one message file. Errors are reasons suitable for
/// the collector log; they never echo more than a short prefix of the input.
pub fn parse_message(text : String) -> Message raise MessageError {
  if text.length() > max_message_bytes {
    raise MessageError("message too large (\{text.length()} bytes)")
  }
  let j = @json.parse(text) catch { _ => raise MessageError("not JSON") }
  guard j is Object(m) else { raise MessageError("not an object") }
  guard m.get("v") is Some(Number(1.0, ..)) else {
    raise MessageError("unsupported version")
  }
  guard m.get("id") is Some(String(id)) && valid_id(id) else {
    raise MessageError("bad id")
  }
  let kind = match m.get("kind") {
    Some(String("trace")) => Trace
    Some(String("pause")) => Pause
    Some(String("resume")) => Resume
    _ => raise MessageError("bad kind")
  }
  let op = match m.get("op") {
    Some(String("start")) => Start
    Some(String("root")) => Root
    Some(String("done")) => Done
    _ => raise MessageError("bad op")
  }
  let int_field = fn(k : String) -> Int32 raise MessageError {
    match m.get(k) {
      Some(Number(d, ..)) if d >= 0.0 && d < 4294967296.0 && d == d.floor() =>
        d.to_int64().to_int()
      None => 0
      _ => raise MessageError("bad \{k}")
    }
  }
  let client_pid = int_field("client_pid")
  let root_pid = int_field("root_pid")
  if client_pid <= 0 {
    raise MessageError("missing client_pid")
  }
  if op == Root && root_pid <= 0 {
    raise MessageError("missing root_pid")
  }
  { id, kind, op, client_pid, root_pid, }
}

///|
/// Message text written by clients.
pub fn Message::to_json_text(self : Message) -> String {
  let m = Map([])
  m["v"] = Json::number(1.0)
  m["id"] = Json::string(self.id)
  m["kind"] = Json::string(
    match self.kind {
      Trace => "trace"
      Pause => "pause"
      Resume => "resume"
    },
  )
  m["op"] = Json::string(
    match self.op {
      Start => "start"
      Root => "root"
      Done => "done"
    },
  )
  m["client_pid"] = Json::number(self.client_pid.to_double())
  if self.root_pid > 0 {
    m["root_pid"] = Json::number(self.root_pid.to_double())
  }
  Json::object(m).stringify()
}

///|
#derive(Eq, Debug)
pub(all) enum State {
  Ready
  Running
  Finishing
  Complete
  Rejected
  Expired
}

///|
pub fn state_name(s : State) -> String {
  match s {
    Ready => "ready"
    Running => "running"
    Finishing => "finishing"
    Complete => "complete"
    Rejected => "rejected"
    Expired => "expired"
  }
}

///|
#derive(Eq, Debug)
pub(all) struct Request {
  id : String
  kind : Kind
  client_pid : Int32
  mut root_pid : Int32
  mut state : State
  mut reason : String
  created : Int64
  mut updated : Int64
  /// A root reported but its parent not yet confirmed: (pid, since).
  mut unconfirmed_root : (Int32, Int64)?
  mut done_at : Int64
}

///|
/// Facts only the collector can establish.
pub(all) struct Checks {
  /// None when the pid is a live process of the installing user, not
  /// elevated; otherwise the reason it is not acceptable.
  client_problem : (Int32) -> String?
  /// Parent pid from process-start events, if seen.
  parent_of : (Int32) -> Int32?
}

///|
#derive(Eq, Debug)
pub(all) enum Effect {
  /// The request's row changed (write it to ledger.db).
  Changed(String)
  /// Start recording the subtree of this pid for the request.
  Track(String, Int32)
  /// Narrow the request to the subtree of the root pid.
  Narrow(String, Int32)
  /// Stop tracking; store the trace result when the state is Complete.
  Finish(String)
  Pause
  Resume
}

///|
pub struct Inbox {
  requests : Map[String, Request]
}

///|
pub fn Inbox::new() -> Inbox {
  { requests: Map([]), }
}

///|
fn Inbox::active_traces(self : Inbox) -> Int32 {
  let mut n = 0
  for _, r in self.requests {
    if r.kind == Trace &&
      (r.state == Ready || r.state == Running || r.state == Finishing) {
      n += 1
    }
  }
  n
}

///|
fn Request::set(
  self : Request,
  s : State,
  reason : String,
  now : Int64,
) -> Unit {
  self.state = s
  self.reason = reason
  self.updated = now
}

///|
/// Applies one validated message.
pub fn Inbox::apply(
  self : Inbox,
  m : Message,
  now : Int64,
  checks : Checks,
) -> Array[Effect] {
  let out = []
  match m.op {
    Start => {
      if self.requests.contains(m.id) {
        return out
      }
      let r : Request = {
        id: m.id,
        kind: m.kind,
        client_pid: m.client_pid,
        root_pid: 0,
        state: Ready,
        reason: "",
        created: now,
        updated: now,
        unconfirmed_root: None,
        done_at: 0L,
      }
      self.requests[m.id] = r
      out.push(Changed(m.id))
      match (checks.client_problem)(m.client_pid) {
        Some(why) => {
          r.set(Rejected, why, now)
          return out
        }
        None => ()
      }
      match m.kind {
        Pause => {
          r.set(Complete, "", now)
          out.push(Pause)
        }
        Resume => {
          r.set(Complete, "", now)
          out.push(Resume)
        }
        Trace =>
          if self.active_traces() > max_active_traces {
            r.set(Rejected, "too many traces running", now)
          } else {
            out.push(Track(m.id, m.client_pid))
          }
      }
    }
    Root => {
      guard self.requests.get(m.id) is Some(r) &&
        r.client_pid == m.client_pid &&
        r.state == Ready else {
        return out
      }
      r.unconfirmed_root = Some((m.root_pid, now))
      r.root_pid = m.root_pid
      r.updated = now
      out.push(Changed(m.id))
      self.confirm(r, now, checks, out)
    }
    Done => {
      guard self.requests.get(m.id) is Some(r) && r.client_pid == m.client_pid else {
        return out
      }
      match r.state {
        Running => {
          r.set(Finishing, "", now)
          r.done_at = now
          out.push(Changed(m.id))
        }
        // The command never started (or its root was never confirmed).
        Ready => {
          r.set(Complete, "command did not start", now)
          out.push(Changed(m.id))
          out.push(Finish(m.id))
        }
        _ => ()
      }
    }
  }
  out
}

///|
fn Inbox::confirm(
  self : Inbox,
  r : Request,
  now : Int64,
  checks : Checks,
  out : Array[Effect],
) -> Unit {
  ignore(self)
  guard r.unconfirmed_root is Some((root, since)) else { return }
  match (checks.parent_of)(root) {
    Some(p) if p == r.client_pid => {
      r.unconfirmed_root = None
      r.set(Running, "", now)
      out.push(Changed(r.id))
      out.push(Narrow(r.id, root))
    }
    Some(_) => {
      r.unconfirmed_root = None
      r.set(Rejected, "root process was not started by the client", now)
      out.push(Changed(r.id))
      out.push(Finish(r.id))
    }
    None =>
      if now - since > root_confirm_timeout {
        r.unconfirmed_root = None
        r.set(Rejected, "root process start was not observed", now)
        out.push(Changed(r.id))
        out.push(Finish(r.id))
      }
  }
}

///|
/// Advances time: confirms pending roots, completes finished traces,
/// expires stale ones.
pub fn Inbox::tick(self : Inbox, now : Int64, checks : Checks) -> Array[Effect] {
  let out = []
  for _, r in self.requests {
    match r.state {
      Ready => {
        self.confirm(r, now, checks, out)
        if r.state == Ready &&
          r.unconfirmed_root is None &&
          now - r.created > ready_timeout {
          r.set(Expired, "no command was started", now)
          out.push(Changed(r.id))
          out.push(Finish(r.id))
        }
      }
      Running =>
        if now - r.created > max_trace {
          r.set(Expired, "trace exceeded the time limit", now)
          out.push(Changed(r.id))
          out.push(Finish(r.id))
        }
      Finishing =>
        if now - r.done_at >= finish_delay {
          r.set(Complete, "", now)
          out.push(Changed(r.id))
          out.push(Finish(r.id))
        }
      _ => ()
    }
  }
  out
}

///|
/// Drops finished requests from memory once they are older than `keep`.
pub fn Inbox::forget(self : Inbox, now : Int64, keep : Int64) -> Unit {
  let old = []
  for id, r in self.requests {
    let finished = r.state == Complete ||
      r.state == Rejected ||
      r.state == Expired
    if finished && now - r.updated > keep {
      old.push(id)
    }
  }
  for id in old {
    self.requests.remove(id)
  }
}
