// `netwhere classify` and `netwhere rules`: edit the user rules in
// config.json. The collector reloads the file within a few seconds; rules
// only affect traffic counted afterwards.

///|
fn is_process_target(t : String) -> Bool {
  t.to_lower().has_suffix(".exe") || t.contains("\\")
}

///|
fn rule_text(r : @config.UserRule) -> String {
  let parts = []
  if r.process != "" {
    parts.push("process " + r.process)
  }
  if r.domain is Some(p) {
    parts.push("domain " + @config.pattern_text(p))
  }
  parts.join(" + ") + " -> " + r.app
}

///|
fn small_number(s : String) -> Int32? {
  if s.length() == 0 || s.length() > 6 {
    return None
  }
  let mut v = 0
  for c in s {
    guard c is ('0'..<='9') else { return None }
    v = v * 10 + (c.to_int() - '0'.to_int())
  }
  Some(v)
}

///|
async fn cmd_classify(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(args, with_value=["--data-dir"], switches=[]) catch {
    e => {
      println("classify: \{e}")
      return 2
    }
  }
  guard a.positional is [target, app] && app.trim().length() > 0 else {
    println("usage: netwhere classify <domain|process.exe> <app name>")
    return 2
  }
  let dir = data_dir_of(a)
  let rule : @config.UserRule = if is_process_target(target) {
    {
      app: app.trim().to_owned(),
      process: @rules.normalize_process(target),
      domain: None,
    }
  } else {
    match @config.parse_pattern(target) {
      Some(p) => { app: app.trim().to_owned(), process: "", domain: Some(p), }
      None => {
        println("classify: not a domain or process: \{target}")
        return 2
      }
    }
  }
  try {
    let c = load_config(dir)
    // Same target again: the newest rule replaces the old one.
    let rules = c.rules.filter(r => {
      r.process != rule.process || r.domain != rule.domain
    })
    rules.push(rule)
    save_config(dir, { ..c, rules, })
    println("added: \{rule_text(rule)}")
    0
  } catch {
    e => {
      println("classify: \{e}")
      1
    }
  }
}

///|
async fn cmd_rules(args : ArrayView[String]) -> Int32 {
  let a = @cli.parse(
    args,
    with_value=["--data-dir", "--app", "--process", "--domain"],
    switches=[],
  ) catch {
    e => {
      println("rules: \{e}")
      return 2
    }
  }
  let dir = data_dir_of(a)
  let usage = "usage: netwhere rules list | add --app A [--process P] [--domain D] | remove N"
  try {
    let c = load_config(dir)
    match a.positional {
      [] | ["list"] => {
        if c.rules.length() == 0 {
          println("no user rules")
        }
        for i, r in c.rules {
          println("\{i + 1}. \{rule_text(r)}")
        }
        let builtin = dir + "\\builtin-rules.txt"
        if @fs.exists(builtin) {
          let set = @rules.RuleSet::new()
          let n = @rules.load_builtin(set, @fs.read_file(builtin).text())
          println(
            "built-in: \{n} domain patterns (v2fly/domain-list-community)",
          )
        } else {
          println("built-in: none installed")
        }
        0
      }
      ["add"] => {
        guard a.options.get("--app") is Some(app) && app.trim().length() > 0 else {
          println(usage)
          return 2
        }
        let process = match a.options.get("--process") {
          Some(p) => @rules.normalize_process(p)
          None => ""
        }
        let domain = match a.options.get("--domain") {
          Some(d) =>
            match @config.parse_pattern(d) {
              Some(p) => Some(p)
              None => {
                println("rules: not a domain pattern: \{d}")
                return 2
              }
            }
          None => None
        }
        if process == "" && domain is None {
          println("rules: give --process, --domain or both")
          return 2
        }
        let rule : @config.UserRule = {
          app: app.trim().to_owned(),
          process,
          domain,
        }
        let rules = c.rules.copy()
        rules.push(rule)
        save_config(dir, { ..c, rules, })
        println("added \{rules.length()}. \{rule_text(rule)}")
        0
      }
      ["remove", n] => {
        let index = match small_number(n) {
          Some(x) if x >= 1 && x <= c.rules.length() => x - 1
          _ => {
            println("rules: no rule number \{n}")
            return 2
          }
        }
        let rules = c.rules.copy()
        let gone = rules.remove(index)
        save_config(dir, { ..c, rules, })
        println("removed: \{rule_text(gone)}")
        0
      }
      _ => {
        println(usage)
        2
      }
    }
  } catch {
    e => {
      println("rules: \{e}")
      1
    }
  }
}
