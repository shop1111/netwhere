///|
test "options, switches, positionals and the rest after --" {
  let a = @cli.parse(
    ["f.ndjson", "--pid", "42", "--expect", "--", "git", "--version"][:],
    with_value=["--pid"],
    switches=["--expect"],
  )
  assert_eq(a.positional, ["f.ndjson"])
  assert_eq(a.int("--pid", 0), 42)
  assert_true(a.has("--expect"))
  assert_eq(a.rest, ["git", "--version"])
  assert_eq(a.int("--secs", 60), 60)
}

///|
test "errors" {
  let msg = fn(args : Array[String]) {
    try {
      let a = @cli.parse(args[:], with_value=["--n"], switches=[])
      let _ = a.int("--n", 0)
      "ok"
    } catch {
      e => e.to_string()
    }
  }
  inspect(msg(["--x"]), content="unknown option --x")
  inspect(msg(["--n"]), content="--n needs a value")
  inspect(msg(["--n", "-1"]), content="--n: not a number: -1")
}
