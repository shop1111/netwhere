///|
test "own process facts" {
  let pid = @sys.current_pid()
  assert_true(pid > 0)
  let img = @sys.image_path(pid).unwrap()
  assert_true(img.has_suffix(".exe"), msg=img)
  assert_true(@sys.current_user_sid().has_prefix("S-1-"))
  assert_eq(@sys.process_user_sid(pid), Some(@sys.current_user_sid()))
  assert_true(@sys.process_create_time(pid).unwrap() < @sys.now())
  assert_true(@sys.process_elevated(pid) is Some(_))
  assert_true(@sys.image_path(-5) is None)
}

///|
test "clock is filetime" {
  // 2026-01-01T00:00:00Z = 134117856000000000 ticks; the clock must be later.
  assert_true(@sys.now() > 134117856000000000L)
}

///|
test "argument quoting follows CommandLineToArgvW rules" {
  inspect(@sys.quote_arg("git"), content="git")
  inspect(@sys.quote_arg("a b"), content="\"a b\"")
  inspect(@sys.quote_arg(""), content="\"\"")
  inspect(@sys.quote_arg("say \"hi\""), content="\"say \\\"hi\\\"\"")
  inspect(
    @sys.quote_arg("C:\\dir with space\\"),
    content="\"C:\\dir with space\\\\\"",
  )
  inspect(@sys.quote_arg("C:\\plain\\path"), content="C:\\plain\\path")
  inspect(
    @sys.join_command_line(["curl", "-H", "X: y", "https://e.test/?a=1"][:]),
    content="curl -H \"X: y\" https://e.test/?a=1",
  )
}

///|
test "suspended child runs only after resume" {
  let pid = @sys.spawn_suspended("cmd.exe /c exit 7")
  assert_true(pid > 0)
  // Suspended: still running after a short wait.
  assert_false(@sys.child_wait(200))
  assert_true(@sys.resume_child())
  assert_true(@sys.child_wait(10000))
  assert_eq(@sys.child_exit_code(), 7)
}

///|
test "process snapshot sees this process and its parent" {
  let list = @sys.process_list()
  let me = @sys.current_pid()
  let mine = list.filter(e => e.pid == me)
  assert_eq(mine.length(), 1)
  assert_true(mine[0].exe.has_suffix(".exe"))
  assert_true(list.iter().any(e => e.pid == mine[0].ppid) || mine[0].ppid > 0)
  // System (pid 4) cannot be opened, but the snapshot still names it.
  inspect(@sys.process_name(4, snapshot=list).unwrap(), content="System")
}

///|
test "run_wait returns the exit code" {
  assert_eq(@sys.run_wait("cmd.exe", ["/c", "exit 5"]), Ok(5))
  assert_true(@sys.run_wait("no-such-program-netwhere.exe", []) is Err(2))
}
