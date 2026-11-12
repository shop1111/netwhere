// rules-import: build rules/builtin.txt from a local checkout of
// v2fly/domain-list-community (MIT).
//
//   rules-import DATA_DIR --apps rules/apps.txt --out rules/builtin.txt
//                [--source "v2fly/domain-list-community@<commit>"]
//
// DATA_DIR is the checkout's data/ directory. Lists are read on demand
// (with their includes); the output is sorted, so the same input always
// gives the same file.

///|
fn parse_apps(text : String) -> Array[(String, String)] {
  let out = []
  for line in text.split("\n") {
    let line = line.trim(chars=" \t\r")
    if line.length() == 0 || line.has_prefix("#") {
      continue
    }
    // list name, then whitespace, then the display name
    let mut i = 0
    while i < line.length() &&
          line.code_unit_at(i) != ' ' &&
          line.code_unit_at(i) != '\t' {
      i += 1
    }
    let name = line[:i].to_owned()
    let app = line[i:].trim(chars=" \t").to_owned()
    if app.length() > 0 {
      out.push((name, app))
    }
  }
  out
}

///|
/// Loads a list and, recursively, the lists it includes.
async fn load(
  dir : String,
  name : String,
  lists : Map[String, @rules.V2flyList],
) -> Unit {
  if lists.contains(name) {
    return
  }
  let path = dir + "\\" + name
  if !@fs.exists(path) {
    return
  }
  let list = @rules.parse_v2fly_list(name, @fs.read_file(path).text())
  lists[name] = list
  for inc in list.includes {
    load(dir, inc.name, lists)
  }
}

///|
async fn main {
  let args = @env.args()
  let a = @cli.parse(args[1:], with_value=["--apps", "--out", "--source"], switches=[]) catch {
    e => {
      println("rules-import: \{e}")
      @sys.exit(2)
      return
    }
  }
  guard a.positional is [data_dir] else {
    println(
      "usage: rules-import DATA_DIR --apps rules/apps.txt --out rules/builtin.txt [--source TEXT]",
    )
    @sys.exit(2)
    return
  }
  let code = try {
    let apps = parse_apps(
      @fs.read_file(a.get("--apps", "rules/apps.txt")).text(),
    )
    let lists = Map([])
    let sections = []
    let mut skipped_regexp = 0
    for entry in apps {
      let (name, app) = entry
      load(data_dir, name, lists)
      if !lists.contains(name) {
        println("skip: no list \"\{name}\" in \{data_dir}")
        continue
      }
      let entries = @rules.resolve_v2fly(lists, name) catch {
        e => {
          println("skip \{name}: \{e}")
          continue
        }
      }
      sections.push((app, entries.map(e => e.pattern)))
      println("\{name} -> \{app}: \{entries.length()} patterns")
    }
    for _, l in lists {
      skipped_regexp += l.regexp_skipped
    }
    let text = @rules.write_builtin(
      sections,
      a.get("--source", "v2fly/domain-list-community"),
    )
    let out = a.get("--out", "rules/builtin.txt")
    @fs.write_file(out, text)
    println(
      "wrote \{out}: \{sections.length()} apps; \{skipped_regexp} regexp patterns skipped",
    )
    0
  } catch {
    e => {
      println("rules-import: \{e}")
      1
    }
  }
  @sys.exit(code)
}
