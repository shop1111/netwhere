///|
let client : Int32 = 100

///|
let root : Int32 = 200

///|
fn checks(
  parents : Map[Int32, Int32],
  bad~ : Map[Int32, String] = Map([]),
) -> @mailbox.Checks {
  { client_problem: pid => bad.get(pid), parent_of: pid => parents.get(pid), }
}

///|
fn msg(
  op : @mailbox.Op,
  kind~ : @mailbox.Kind = Trace,
  client_pid~ : Int32 = client,
  root_pid~ : Int32 = 0,
) -> @mailbox.Message {
  { id: "trace-0001", kind, op, client_pid, root_pid, }
}

///|
fn state(ib : @mailbox.Inbox) -> String {
  let r = ib.requests["trace-0001"]
  @mailbox.state_name(r.state) +
  (if r.reason == "" { "" } else { " (" + r.reason + ")" })
}

///|
test "full trace: ready, running, finishing, complete" {
  let ib = @mailbox.Inbox::new()
  let parents : Map[Int32, Int32] = Map([])
  let c = checks(parents)
  assert_eq(ib.apply(msg(Start), 0L, c), [
    Changed("trace-0001"),
    Track("trace-0001", client),
  ])
  inspect(state(ib), content="ready")
  // Root reported before its process-start event arrived: waits.
  assert_eq(ib.apply(msg(Root, root_pid=root), 10L, c), [Changed("trace-0001")])
  inspect(state(ib), content="ready")
  parents[root] = client
  assert_eq(ib.tick(20L, c), [Changed("trace-0001"), Narrow("trace-0001", root)])
  inspect(state(ib), content="running")
  ignore(ib.apply(msg(Done), 1000L, c))
  inspect(state(ib), content="finishing")
  // Not before ETW had time to deliver the tail.
  assert_eq(ib.tick(1000L + @mailbox.finish_delay - 1L, c), [])
  assert_eq(ib.tick(1000L + @mailbox.finish_delay, c), [
    Changed("trace-0001"),
    Finish("trace-0001"),
  ])
  inspect(state(ib), content="complete")
}

///|
test "a root that is not the client's child is rejected" {
  let ib = @mailbox.Inbox::new()
  let c = checks(Map([(root, 4)]))
  ignore(ib.apply(msg(Start), 0L, c))
  let fx = ib.apply(msg(Root, root_pid=root), 1L, c)
  assert_true(fx.contains(Finish("trace-0001")))
  inspect(
    state(ib),
    content="rejected (root process was not started by the client)",
  )
}

///|
test "unobserved root and silent clients expire" {
  let ib = @mailbox.Inbox::new()
  let c = checks(Map([]))
  ignore(ib.apply(msg(Start), 0L, c))
  ignore(ib.apply(msg(Root, root_pid=root), 1L, c))
  ignore(ib.tick(1L + @mailbox.root_confirm_timeout + 1L, c))
  inspect(state(ib), content="rejected (root process start was not observed)")
  let ib2 = @mailbox.Inbox::new()
  ignore(ib2.apply(msg(Start), 0L, c))
  ignore(ib2.tick(@mailbox.ready_timeout + 1L, c))
  inspect(state(ib2), content="expired (no command was started)")
}

///|
test "client checks, other clients and duplicate starts" {
  let ib = @mailbox.Inbox::new()
  let c = checks(Map([(root, client)]), bad=Map([(7, "process is elevated")]))
  ignore(ib.apply(msg(Start, client_pid=7), 0L, c))
  inspect(state(ib), content="rejected (process is elevated)")
  let ib2 = @mailbox.Inbox::new()
  ignore(ib2.apply(msg(Start), 0L, c))
  // Another process cannot drive someone else's request.
  assert_eq(ib2.apply(msg(Root, client_pid=999, root_pid=root), 1L, c), [])
  // Starting again with the same id changes nothing.
  assert_eq(ib2.apply(msg(Start), 2L, c), [])
  inspect(state(ib2), content="ready")
}

///|
test "pause and resume" {
  let ib = @mailbox.Inbox::new()
  let c = checks(Map([]))
  assert_eq(ib.apply(msg(Start, kind=Pause), 0L, c), [
    Changed("trace-0001"),
    Pause,
  ])
  inspect(state(ib), content="complete")
}

///|
test "message parsing validates everything" {
  let ok = @mailbox.parse_message(
    "{\"v\":1,\"id\":\"trace-0001\",\"kind\":\"trace\",\"op\":\"root\",\"client_pid\":100,\"root_pid\":200}",
  )
  assert_eq(ok, msg(Root, root_pid=200))
  assert_eq(@mailbox.parse_message(ok.to_json_text()), ok)
  let err = fn(text : String) {
    try {
      let _ = @mailbox.parse_message(text)
      "ok"
    } catch {
      MessageError(m) => m
    }
  }
  inspect(err("[]"), content="not an object")
  inspect(err("{\"v\":2}"), content="unsupported version")
  inspect(err("{\"v\":1,\"id\":\"../../x\"}"), content="bad id")
  inspect(
    err("{\"v\":1,\"id\":\"trace-0001\",\"kind\":\"rm\"}"),
    content="bad kind",
  )
  inspect(
    err(
      "{\"v\":1,\"id\":\"trace-0001\",\"kind\":\"trace\",\"op\":\"start\",\"client_pid\":-1}",
    ),
    content="bad client_pid",
  )
  inspect(
    err(
      "{\"v\":1,\"id\":\"trace-0001\",\"kind\":\"trace\",\"op\":\"root\",\"client_pid\":1}",
    ),
    content="missing root_pid",
  )
  inspect(err("x".repeat(5000)), content="message too large (5000 bytes)")
}
