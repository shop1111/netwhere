// Minimal argument parsing shared by netwhere and netwhered.

///|
/// Parsed command line: "--name value" options, "--flag" switches and
/// positional arguments, plus everything after "--" kept verbatim.
pub(all) struct Args {
  options : Map[String, String]
  switches : Array[String]
  positional : Array[String]
  rest : Array[String]
}

///|
#derive(Debug)
pub(all) suberror ArgError {
  ArgError(String)
}

///|
pub impl Show for ArgError with fn output(self, logger) {
  let ArgError(msg) = self
  logger.write_string(msg)
}

///|
/// `with_value` lists options that take a value; `switches` lists flags.
/// Unknown "--x" arguments are errors.
pub fn parse(
  args : ArrayView[String],
  with_value~ : Array[String],
  switches~ : Array[String],
) -> Args raise ArgError {
  let options = Map([])
  let on = []
  let positional = []
  let mut rest = []
  let mut i = 0
  while i < args.length() {
    let a = args[i]
    if a == "--" {
      rest = args[i + 1:].to_owned()
      break
    }
    if a.has_prefix("--") {
      if with_value.contains(a) {
        guard i + 1 < args.length() else {
          raise ArgError("\{a} needs a value")
        }
        options[a] = args[i + 1]
        i += 2
        continue
      }
      if switches.contains(a) {
        on.push(a)
        i += 1
        continue
      }
      raise ArgError("unknown option \{a}")
    }
    positional.push(a)
    i += 1
  }
  { options, switches: on, positional, rest, }
}

///|
pub fn Args::has(self : Args, switch_ : String) -> Bool {
  self.switches.contains(switch_)
}

///|
pub fn Args::get(self : Args, name : String, default : String) -> String {
  self.options.get_or_default(name, default)
}

///|
/// Non-negative integer option.
pub fn Args::int(
  self : Args,
  name : String,
  default : Int32,
) -> Int32 raise ArgError {
  match self.options.get(name) {
    None => default
    Some(s) => {
      if s.length() == 0 || s.length() > 9 {
        raise ArgError("\{name}: not a number: \{s}")
      }
      let mut v = 0
      for c in s {
        guard c is ('0'..<='9') else {
          raise ArgError("\{name}: not a number: \{s}")
        }
        v = v * 10 + (c.to_int() - '0'.to_int())
      }
      v
    }
  }
}
