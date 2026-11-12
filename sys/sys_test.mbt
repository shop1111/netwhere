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
  inspect(@sys.quote_arg("C:\\dir with space\\"), content="\"C:\\dir with space\\\\\"")
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
