///|
let sample : String =
  #|{
  #|  "controller": "127.0.0.1:9097",
  #|  "rules": [
  #|    {"app": "Work", "domain": "GitHub.com"},
  #|    {"app": "Editor", "process": "Code.exe"},
  #|    {"app": "Sync", "process": "code.exe", "domain": "full:api.github.com"}
  #|  ],
  #|  "multipliers": {"HK 01": 2},
  #|  "unknown_field": true
  #|}

///|
test "parse, apply and write back" {
  let c = @config.parse(sample)
  inspect(c.controller, content="127.0.0.1:9097")
  assert_eq(c.retention_days, 400)
  assert_eq(c.rules.length(), 3)
  let set = @rules.RuleSet::new()
  c.apply_rules(set)
  assert_eq(set.classify("x.exe", Some("gist.github.com")).unwrap().app, "Work")
  assert_eq(
    set.classify("C:\\x\\code.exe", Some("example.org")).unwrap().app,
    "Editor",
  )
  assert_eq(
    set.classify("code.exe", Some("api.github.com")).unwrap().app,
    "Sync",
  )
  let again = @config.parse(c.to_text())
  assert_eq(again, c)
}

///|
test "empty file means defaults" {
  assert_eq(@config.parse(""), @config.default())
  assert_eq(@config.parse("\u{feff}  "), @config.default())
}

///|
test "invalid input is rejected with a reason" {
  let err = fn(text : String) {
    try {
      let _ = @config.parse(text)
      "ok"
    } catch {
      e => e.to_string()
    }
  }
  inspect(err("[]"), content="config.json: top level must be an object")
  inspect(
    err("{\"rules\":[{\"app\":\"A\"}]}"),
    content="config.json: rules[0] needs a process, a domain or both",
  )
  inspect(
    err("{\"rules\":[{\"process\":\"a.exe\"}]}"),
    content="config.json: rules[0].app is required",
  )
  inspect(
    err("{\"rules\":[{\"app\":\"A\",\"domain\":\"regexp:.*\"}]}"),
    content="config.json: rules[0].domain is not a valid pattern",
  )
  inspect(
    err("{\"multipliers\":{\"n\":-1}}"),
    content="config.json: multiplier for \"n\" must be a number in 0..100",
  )
  inspect(
    err("{\"retention_days\":0}"),
    content="config.json: retention_days must be 1..36500",
  )
  inspect(
    err("{\"secret\":5}"),
    content="config.json: secret must be a string of at most 1024 characters",
  )
}

///|
test "multipliers from node names" {
  let c = @config.parse(sample)
  assert_eq(c.multiplier("HK 01"), 2.0)
  assert_eq(c.multiplier("TW 03丨1x TW"), 1.0)
  assert_eq(c.multiplier("US 05 | 0.5x"), 0.5)
  assert_eq(c.multiplier("JP x3 premium"), 3.0)
  assert_eq(c.multiplier("SG 2倍"), 2.0)
  assert_eq(c.multiplier("HK 01 IPLC"), 1.0)
  assert_eq(c.multiplier("Node X"), 1.0)
}
