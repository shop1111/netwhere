// Probe for Nanaloveyuki/moonview: does a WebView2 window built from MoonBit
// give us what the netwhere UI needs?
//   - page served from a custom scheme (no HTTP port)
//   - JS <-> MoonBit messages: round-trip latency
//   - 2000-row table pushed as JSON and rendered
//   - Chinese text, an input box (IME checked by hand), resizing
//   - after the window closes, every msedgewebview2 process of ours exits
//
// usage: main.exe [--auto MS]   (--auto closes the window after MS ms)

///|
extern "C" fn host_create(w : Int, h : Int, auto_ms : Int) -> UInt64 = "nwp_host_create"

///|
extern "C" fn host_client_size() -> Int = "nwp_host_client_size"

///|
extern "C" fn host_pump() -> Int = "nwp_host_pump"

///|
extern "C" fn host_take_resize() -> Int = "nwp_host_take_resize"

///|
extern "C" fn host_take_close() -> Int = "nwp_host_take_close"

///|
extern "C" fn host_destroy() -> Unit = "nwp_host_destroy"

///|
extern "C" fn now_us() -> UInt64 = "nwp_now_us"

///|
fn et(e : @moonview.WebViewError) -> String {
  match e {
    Unavailable => "unavailable"
    Unsupported(s) => "unsupported: \{s}"
    ConfigurationLocked => "configuration locked"
    CreateRejected => "create rejected"
    WrongThread => "wrong thread"
    Destroyed => "destroyed"
    NativeFailure(code, s) => "native failure \{code}: \{s}"
  }
}

///|
fn rect_of(packed : Int) -> @moonview.Rect {
  @moonview.Rect::new(x=0, y=0, width=packed >> 16, height=packed & 0xffff)
}

///|
let page : String =
  #|<!doctype html>
  #|<html lang="zh-CN"><head><meta charset="utf-8"><title>netwhere 探针</title>
  #|<style>
  #|  :root { color-scheme: light dark; font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif; }
  #|  body { margin: 0; padding: 16px; }
  #|  #out { font: 12px Consolas, monospace; white-space: pre-wrap; }
  #|  .wrap { height: 60vh; overflow: auto; border: 1px solid #8884; }
  #|  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  #|  td, th { padding: 2px 8px; border-bottom: 1px solid #8882; text-align: left; }
  #|  td.n { text-align: right; font-variant-numeric: tabular-nums; }
  #|</style></head><body>
  #|<h3>流量走向探针：中文显示、输入法、表格</h3>
  #|<input id="q" placeholder="在这里用中文输入法打字" style="width:300px">
  #|<span id="echo"></span>
  #|<div id="out"></div>
  #|<div class="wrap"><table><thead><tr><th>#</th><th>进程</th><th>目的地</th><th>入口</th><th>出口</th><th>下行</th></tr></thead><tbody id="rows"></tbody></table></div>
  #|<script>
  #|const out = document.getElementById("out");
  #|const log = s => { out.textContent += s + "\n"; window.moonview.postMessage(JSON.stringify({t: "log", s})); };
  #|const pending = new Map(); let next = 1;
  #|const call = (q, arg) => new Promise(res => { const id = next++; pending.set(id, res);
  #|  window.moonview.postMessage(JSON.stringify({t: "call", id, q, arg})); });
  #|window.moonview.onmessage = ev => { const m = JSON.parse(ev.data);
  #|  const r = pending.get(m.id); if (r) { pending.delete(m.id); r(m.v); } };
  #|document.getElementById("q").addEventListener("input", e =>
  #|  call("echo", e.target.value).then(v => document.getElementById("echo").textContent = "MoonBit 收到：" + v));
  #|(async () => {
  #|  let t0 = performance.now();
  #|  for (let i = 0; i < 100; i++) await call("ping", i);
  #|  log("round trip: " + ((performance.now() - t0) / 100).toFixed(3) + " ms avg over 100");
  #|  t0 = performance.now();
  #|  const rows = await call("rows", 2000);
  #|  const t1 = performance.now();
  #|  const tb = document.getElementById("rows");
  #|  const frag = document.createDocumentFragment();
  #|  for (const r of rows) { const tr = document.createElement("tr");
  #|    tr.innerHTML = `<td class=n>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${r[3]}</td><td>${r[4]}</td><td class=n>${r[5]}</td>`;
  #|    frag.appendChild(tr); }
  #|  tb.appendChild(frag);
  #|  await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
  #|  log("rows: " + rows.length + ", transfer " + (t1 - t0).toFixed(1) + " ms, render " + (performance.now() - t1).toFixed(1) + " ms");
  #|  log("devicePixelRatio " + devicePixelRatio + ", viewport " + innerWidth + "x" + innerHeight);
  #|})();
  #|</script></body></html>

///|
fn rows_json(n : Int) -> Json {
  let procs = ["git-remote-https.exe", "curl.exe", "claude.exe", "微信.exe"]
  let hosts = ["github.com:443", "speed.cloudflare.com:443", "api.anthropic.com:443", "例子.中国:443"]
  let entries = ["proxy-port", "tun", "bypass", "direct"]
  let exits = ["香港 01", "日本 02 [2x]", "DIRECT", "?"]
  let a : Array[Json] = []
  for i in 0..<n {
    a.push(
      Json::array([
        Json::number(i.to_double()),
        Json::string(procs[i % 4]),
        Json::string("tcp " + hosts[i / 4 % 4]),
        Json::string(entries[i / 16 % 4]),
        Json::string(exits[i / 64 % 4]),
        Json::string("\{i * 37 % 1000}.\{i % 10} KB"),
      ]),
    )
  }
  Json::array(a)
}

///|
fn main {
  let args = @env.args()
  let auto_ms = if args.length() >= 3 && args[1] == "--auto" {
    @string.parse_int(args[2]) catch { _ => 0 }
  } else {
    0
  }
  let t_start = now_us()
  let hwnd = host_create(1100, 760, auto_ms)
  if hwnd == 0UL {
    println("cannot create window")
    return
  }
  let data_dir = match @env.get_env_var("LOCALAPPDATA") {
    Some(d) => d + "\\netwhere-probe\\webview2"
    None => ""
  }
  println("data dir: \{data_dir}")
  match @moonview.register_custom_scheme("netwhere") {
    Ok(_) => ()
    Err(e) => println("register scheme: \{et(e)}")
  }
  let view : Ref[@moonview.WebView?] = Ref(None)
  let reply = fn(id : Json, v : Json) {
    let m = Map([])
    m["id"] = id
    m["v"] = v
    if view.val is Some(w) {
      ignore(w.post_message(Json::object(m).stringify()))
    }
  }
  let on_event = fn(ev : @moonview.WebViewEvent) {
    match ev {
      Ready =>
        println("ready after \{(now_us() - t_start) / 1000UL} ms")
      NavigationCompleted(url) =>
        println("loaded \{url} after \{(now_us() - t_start) / 1000UL} ms")
      ProtocolRequest(req) =>
        if view.val is Some(w) {
          let body = @utf8.encode(page[:], bom=false)
          ignore(
            w.respond_protocol(
              req.id,
              @moonview.ProtocolResponse::new(
                status=200,
                headers=[
                  @moonview.HttpHeader::new(
                    name="Content-Type",
                    value="text/html; charset=utf-8",
                  ),
                ],
                body~,
              ),
            ),
          )
        }
      PageMessage(text) => {
        let j = @json.parse(text) catch { _ => Json::null() }
        match j {
          { "t": "log", "s": String(s), .. } => println("page: \{s}")
          { "t": "call", "id": id, "q": String("ping"), "arg": arg, .. } =>
            reply(id, arg)
          { "t": "call", "id": id, "q": String("echo"), "arg": String(s), .. } =>
            reply(id, Json::string(s))
          { "t": "call", "id": id, "q": String("rows"), "arg": Number(n, ..), .. } =>
            reply(id, rows_json(n.to_int()))
          _ => println("unexpected message: \{text}")
        }
      }
      CreationFailed(e) => println("creation failed: \{et(e)}")
      ProcessFailed(e) => println("process failed: \{et(e)}")
      NavigationFailed(url, e) => println("navigation failed: \{url} \{et(e)}")
      _ => ()
    }
  }
  let options = @moonview.WebViewOptions::new(
    bounds=rect_of(host_client_size()),
    context=@moonview.WebContext::persistent(data_directory=data_dir),
    initial_url="netwhere://app/index.html",
    on_event~,
    on_navigation=url => if url.has_prefix("netwhere://") { Allow } else { Deny },
    on_new_window=_ => Deny,
  )
  match @moonview.WebView::create_in_context(options.context, hwnd, options) {
    Ok(w) => view.val = Some(w)
    Err(e) => {
      println("create failed: \{et(e)}")
      host_destroy()
    }
  }
  while host_pump() != 0 {
    let r = host_take_resize()
    if r >= 0 && view.val is Some(w) {
      ignore(w.set_bounds(rect_of(r)))
    }
    if host_take_close() != 0 {
      if view.val is Some(w) {
        let t = now_us()
        let res = match w.destroy() { Ok(_) => "ok"; Err(e) => et(e) }
        println("destroy: \{res} in \{(now_us() - t) / 1000UL} ms")
        view.val = None
      }
      host_destroy()
    }
  }
  println("exit after \{(now_us() - t_start) / 1000UL} ms")
}
