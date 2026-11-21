// What the page may ask for. Every call is {q, arg}; the answer is JSON.
// Numbers are bytes (as JSON numbers; exact below 2^53) or minutes; the
// page formats them. Writes go only where the CLI writes: config.json, the
// mailbox and the user's own HKCU Run value.

///|
priv suberror ApiError {
  ApiError(String)
}

///|
priv struct Api {
  dir : String
  offset : Int32
  /// Built-in rule count, read once.
  mut builtin : Int32?
  /// Opens a native "save as" dialog; None when cancelled.
  save_dialog : (String) -> String?
}

///|
fn num(n : Int64) -> Json {
  Json::number(n.to_double())
}

///|
fn str(s : String) -> Json {
  Json::string(s)
}

///|
fn obj(fields : Array[(String, Json)]) -> Json {
  Json::object(Map::from_array(fields))
}

///|
fn split_json(s : @query.Split) -> Json {
  Json::array([
    num(s.via_node),
    num(s.core_direct),
    num(s.core_unknown),
    num(s.bypass),
    num(s.lan),
  ])
}

///|
fn field(arg : Json, name : String) -> Json? {
  match arg {
    Object(m) => m.get(name)
    _ => None
  }
}

///|
fn field_str(arg : Json, name : String) -> String raise ApiError {
  match field(arg, name) {
    Some(String(s)) => s
    _ => raise ApiError("missing \{name}")
  }
}

///|
fn field_str_or(arg : Json, name : String, default : String) -> String {
  match field(arg, name) {
    Some(String(s)) => s
    _ => default
  }
}

///|
fn field_int(arg : Json, name : String) -> Int32 raise ApiError {
  match field(arg, name) {
    Some(Number(d, ..)) if d == d.floor() && d.abs() < 1.0e9 => d.to_int()
    _ => raise ApiError("missing \{name}")
  }
}

///|
fn Api::period(self : Api, arg : Json) -> @query.Period {
  let now = @sys.now()
  match field_str_or(arg, "period", "today") {
    "24h" => @query.last_hours(24, now)
    "7d" => @query.last_days(7, now)
    "30d" => @query.last_days(30, now)
    _ => @query.today(now, self.offset)
  }
}

///|
fn Api::rows(
  self : Api,
  p : @query.Period,
) -> Array[@store.UsageRecord] raise ApiError {
  let db = @store.Db::open_reader(self.dir + "\\ledger.db") catch {
    e => raise ApiError("无法打开账本：\{e}")
  }
  let rows = db.usage_between(p.from, p.to) catch {
    e => {
      db.close()
      raise ApiError("读取账本失败：\{e}")
    }
  }
  db.close()
  rows
}

///|
fn Api::coverage(self : Api, p : @query.Period) -> Json {
  let now_minute = @sys.now() / @store.ticks_per_minute + 1L
  let to = if p.to < now_minute { p.to } else { now_minute }
  let rows = try {
    let db = @store.Db::open_reader(self.dir + "\\ledger.db")
    let r = db.coverage_between(p.from, to) catch { _ => [] }
    db.close()
    r
  } catch {
    _ => []
  }
  if rows.length() == 0 {
    return obj([("none", Json::boolean(true))])
  }
  let c = @report.summarize_coverage(rows, p.from, to)
  obj([
    ("none", Json::boolean(false)),
    ("span", num(c.span_ticks / 10_000_000L)),
    ("collector", num(c.collector_ticks / 10_000_000L)),
    ("core", num(c.core_ticks / 10_000_000L)),
    ("link", num(c.link_ticks / 10_000_000L)),
    ("etw_lost", num(c.etw_lost)),
    ("dropped", num(c.dropped)),
  ])
}

///|
fn Api::config(self : Api) -> @config.Config raise ApiError {
  @control.load_config(self.dir) catch {
    e => raise ApiError("config.json 无法解析：\{e}")
  }
}

///|
fn Api::save(self : Api, c : @config.Config) -> Unit raise ApiError {
  // Round trip through the parser: what the collector will accept.
  let c = @config.parse(c.to_text()) catch {
    e => raise ApiError("设置无效：\{e}")
  }
  match @control.save_config(self.dir, c) {
    Ok(_) => ()
    Err(e) => raise ApiError(e)
  }
}

///|
fn phase_name(p : @control.Phase) -> String {
  match p {
    NotInstalled => "not-installed"
    Stopped => "stopped"
    Running => "running"
    Paused => "paused"
  }
}

///|
fn Api::status(self : Api) -> Json {
  let st = @control.status(self.dir)
  let fields = [
    ("phase", str(phase_name(st.phase))),
    ("detail", str(st.detail)),
    ("autostart", Json::boolean(@control.autostart_command() is Some(_))),
    ("data_dir", str(self.dir)),
  ]
  if st.heartbeat is Some(h) {
    let up_s = (h.updated - h.started) / 10_000_000L
    fields.push(("degraded", Json::boolean(h.degraded)))
    fields.push(("core_link", str(h.core_link)))
    fields.push(("since", str(@report.format_local(h.started, self.offset))))
    fields.push(("pid", Json::number(h.pid.to_double())))
    fields.push(("events", num(h.events)))
    fields.push(("dropped", num(h.dropped)))
    fields.push(("events_lost", num(h.events_lost)))
    fields.push(("flows", Json::number(h.flows.to_double())))
    fields.push(("private_bytes", num(h.private_bytes)))
    fields.push(
      (
        "cpu_permille",
        num(if up_s > 0L { h.cpu_ms * 1000L / (up_s * 1000L) } else { 0L }),
      ),
    )
    fields.push(("last_error", str(h.last_error)))
  }
  obj(fields)
}

///|
fn Api::overview(self : Api, arg : Json) -> Json raise ApiError {
  let p = self.period(arg)
  let rows = self.rows(p)
  let c = self.config()
  let t = @query.totals(rows, n => c.multiplier(n))
  let step = @query.timeline_step(p)
  let tl = @query.timeline(rows, p, step, offset=self.offset.to_int64())
  let apps = @query.group(rows, "app")
  obj([
    ("label", str(p.label)),
    ("up", num(t.up)),
    ("down", num(t.down)),
    ("split", split_json(t.split)),
    ("total", num(t.split.total)),
    ("plan_low", num(t.plan.low)),
    ("plan_high", num(t.plan.high)),
    ("plan_uncertain", num(t.plan.uncertain)),
    ("step", num(step)),
    (
      "timeline",
      Json::array(
        tl.map(b => {
          Json::array([
            str(
              @report.format_local(
                b.start * @store.ticks_per_minute,
                self.offset,
              ),
            ),
            split_json(b.split),
          ])
        }),
      ),
    ),
    (
      "apps",
      Json::array(
        apps
        .iter()
        .take(10)
        .map(g => obj([("key", str(g.key)), ("split", split_json(g.split))]))
        .collect(),
      ),
    ),
    ("apps_count", Json::number(apps.length().to_double())),
    ("coverage", self.coverage(p)),
  ])
}

///|
fn Api::groups(self : Api, arg : Json) -> Json raise ApiError {
  let p = self.period(arg)
  let by = field_str_or(arg, "by", "app")
  if !@query.groupings.contains(by) {
    raise ApiError("bad grouping \{by}")
  }
  let mut rows = self.rows(p)
  if arg is { "filters": Array(fs), .. } {
    for f in fs {
      guard f is Array([String(fby), String(fkey)]) &&
        @query.groupings.contains(fby) else {
        raise ApiError("bad filter")
      }
      rows = @query.filter(rows, key=(fby, fkey))
    }
  }
  let gs = @query.group(rows, by)
  obj([
    ("label", str(p.label)),
    ("count", Json::number(gs.length().to_double())),
    (
      "rows",
      Json::array(
        gs
        .iter()
        .take(500)
        .map(g => obj([("key", str(g.key)), ("split", split_json(g.split))]))
        .collect(),
      ),
    ),
  ])
}

///|
fn Api::nodes(self : Api, arg : Json) -> Json raise ApiError {
  let p = self.period(arg)
  let c = self.config()
  let rows = self.rows(p)
  let t = @query.totals(rows, n => c.multiplier(n))
  obj([
    ("label", str(p.label)),
    (
      "nodes",
      Json::array(
        @query.nodes(rows, n => c.multiplier(n)).map(n => {
          obj([
            ("node", str(n.node)),
            ("bytes", num(n.bytes)),
            ("multiplier", Json::number(n.multiplier)),
            ("configured", Json::boolean(c.multipliers.contains(n.node))),
            ("plan", num(n.plan)),
          ])
        }),
      ),
    ),
    ("plan_low", num(t.plan.low)),
    ("plan_high", num(t.plan.high)),
    ("plan_uncertain", num(t.plan.uncertain)),
  ])
}

///|
fn Api::unknown(self : Api, arg : Json) -> Json raise ApiError {
  let p = self.period(arg)
  let us = @query.unclassified(self.rows(p))
  obj([
    ("label", str(p.label)),
    ("count", Json::number(us.length().to_double())),
    (
      "rows",
      Json::array(
        us
        .iter()
        .take(300)
        .map(u => {
          obj([
            ("process", str(u.process)),
            ("domain", str(u.domain)),
            ("bytes", num(u.bytes)),
          ])
        })
        .collect(),
      ),
    ),
  ])
}

///|
fn Api::rules(self : Api) -> Json raise ApiError {
  let c = self.config()
  if self.builtin is None {
    let n = match @control.read_text(self.dir + "\\builtin-rules.txt") {
      Some(text) =>
        @rules.load_builtin(@rules.RuleSet::new(), text[:]) catch {
          _ => 0
        }
      None => 0
    }
    self.builtin = Some(n)
  }
  obj([
    (
      "rules",
      Json::array(
        c.rules.mapi((i, r) => {
          obj([
            ("index", Json::number(i.to_double())),
            ("app", str(r.app)),
            ("process", str(r.process)),
            (
              "domain",
              str(
                match r.domain {
                  Some(p) => @config.pattern_text(p)
                  None => ""
                },
              ),
            ),
          ])
        }),
      ),
    ),
    ("builtin", Json::number(self.builtin.unwrap_or(0).to_double())),
  ])
}

///|
fn Api::rule_add(self : Api, arg : Json) -> Json raise ApiError {
  let rule = match
    @query.make_rule(
      field_str(arg, "app"),
      process=field_str_or(arg, "process", ""),
      domain=field_str_or(arg, "domain", ""),
    ) {
    Ok(r) => r
    Err(e) => raise ApiError(e)
  }
  self.save(@query.with_rule(self.config(), rule))
  self.rules()
}

///|
fn Api::rule_remove(self : Api, arg : Json) -> Json raise ApiError {
  match @query.without_rule(self.config(), field_int(arg, "index")) {
    Some(c) => self.save(c)
    None => raise ApiError("规则已变化，请刷新")
  }
  self.rules()
}

///|
fn Api::classify(self : Api, arg : Json) -> Json raise ApiError {
  let rule = match
    @query.classify_rule(field_str(arg, "target"), field_str(arg, "app")) {
    Ok(r) => r
    Err(e) => raise ApiError(e)
  }
  self.save(@query.with_rule(self.config(), rule))
  obj([("text", str(@query.rule_text(rule)))])
}

///|
fn Api::settings(self : Api) -> Json raise ApiError {
  let c = self.config()
  let mult = c.multipliers.iter().collect()
  mult.sort_by((a, b) => a.0.compare(b.0))
  obj([
    ("controller", str(c.controller)),
    ("has_secret", Json::boolean(c.secret != "")),
    ("retention_days", Json::number(c.retention_days.to_double())),
    (
      "multipliers",
      Json::array(mult.map(kv => Json::array([str(kv.0), Json::number(kv.1)]))),
    ),
  ])
}

///|
fn Api::settings_save(self : Api, arg : Json) -> Json raise ApiError {
  let c = self.config()
  let controller = field_str_or(arg, "controller", c.controller)
    .trim()
    .to_owned()
  // The secret is never sent to the page: absent means keep it.
  let secret = match arg {
    { "secret": String(s), .. } => s
    _ => c.secret
  }
  let retention_days = match arg {
    { "retention_days": Number(d, ..), .. } if d >= 1.0 && d <= 3650.0 =>
      d.to_int()
    { "retention_days": _, .. } =>
      raise ApiError("保留天数应在 1 到 3650 之间")
    _ => c.retention_days
  }
  let multipliers = match arg {
    { "multipliers": Array(items), .. } => {
      let m = Map([])
      for it in items {
        guard it is Array([String(name), Number(x, ..)]) &&
          name.trim() != "" &&
          x >= 0.0 &&
          x <= 100.0 else {
          raise ApiError("倍率应为 0 到 100 之间的数")
        }
        m[name.trim().to_owned()] = x
      }
      m
    }
    _ => c.multipliers
  }
  self.save({ ..c, controller, secret, retention_days, multipliers, })
  self.settings()
}

///|
fn Api::control(self : Api, arg : Json) -> Json raise ApiError {
  let result = match field_str(arg, "action") {
    "start" => @control.start()
    "pause" => @control.request(self.dir, Pause).map(_ => ())
    "resume" => @control.request(self.dir, Resume).map(_ => ())
    "stop" =>
      if @control.stop_and_wait(self.dir, timeout_ms=10000) {
        Ok(())
      } else {
        Err("采集进程没有在 10 秒内退出")
      }
    other => raise ApiError("unknown action \{other}")
  }
  match result {
    Ok(_) => self.status()
    Err(e) => raise ApiError(e)
  }
}

///|
/// The tray program start-at-login should run: the installed one, else
/// the one next to this window.
fn Api::tray_program(self : Api) -> String? {
  let installed = @control.installed_tray(self.dir)
  if @sys.file_exists(installed) {
    return Some(installed)
  }
  let here = dir_of(own_path())
  for
    c in [
      here + "\\netwhere-tray.exe",
      here + "\\..\\netwhere-tray\\netwhere-tray.exe",
    ] {
    if @sys.file_exists(c) {
      return Some(c)
    }
  }
  None
}

///|
fn Api::autostart(self : Api, arg : Json) -> Json raise ApiError {
  let on = match arg {
    { "on": True, .. } => true
    { "on": False, .. } => false
    _ => raise ApiError("missing on")
  }
  let err = if on {
    match self.tray_program() {
      Some(t) => @control.set_autostart(Some(t))
      None => raise ApiError("没有找到 netwhere-tray.exe")
    }
  } else {
    @control.set_autostart(None)
  }
  if err != 0 {
    raise ApiError("无法修改登录时启动（Win32 错误 \{err}）")
  }
  self.status()
}

///|
fn Api::export_csv(self : Api, arg : Json) -> Json raise ApiError {
  let p = self.period(arg)
  let rows = self.rows(p)
  guard (self.save_dialog)(
      "netwhere-\{field_str_or(arg, "period", "today")}.csv",
    )
    is Some(path) else {
    return obj([("cancelled", Json::boolean(true))])
  }
  // A byte-order mark so Excel reads the UTF-8 names correctly.
  let text = "\u{feff}" + @query.csv(rows, self.offset)
  match @sys.write_file_atomic(path, @utf8.encode(text[:])) {
    0 =>
      obj([
        ("path", str(path)),
        ("rows", Json::number(rows.length().to_double())),
      ])
    e => raise ApiError("无法写入 \{path}（Win32 错误 \{e}）")
  }
}

///|
/// Answers one call: {"ok": value} or {"err": message}.
fn Api::call(self : Api, q : String, arg : Json) -> Json {
  let r : Result[Json, String] = Ok(
    match q {
      "status" => self.status()
      "overview" => self.overview(arg)
      "groups" => self.groups(arg)
      "nodes" => self.nodes(arg)
      "unknown" => self.unknown(arg)
      "rules" => self.rules()
      "rule_add" => self.rule_add(arg)
      "rule_remove" => self.rule_remove(arg)
      "classify" => self.classify(arg)
      "settings" => self.settings()
      "settings_save" => self.settings_save(arg)
      "control" => self.control(arg)
      "autostart" => self.autostart(arg)
      "export" => self.export_csv(arg)
      _ => raise ApiError("unknown call \{q}")
    },
  ) catch {
    ApiError(m) => Err(m)
  }
  match r {
    Ok(v) => obj([("ok", v)])
    Err(m) => obj([("err", str(m))])
  }
}
