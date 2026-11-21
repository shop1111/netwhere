// netwhere-ui: the window. Runs unprivileged, only while open; closing it
// ends the process and its WebView2 processes.
//
// The page (web\, embedded at build time into web_assets.mbt) is served
// from the custom scheme netwhere://app/ — no HTTP port — and talks to
// MoonBit through WebView messages: {"id", "q", "arg"} in, {"id", "ok"} or
// {"id", "err"} out (api.mbt).
//
// usage: netwhere-ui.exe [--data-dir DIR] [--web DIR]
//   --web DIR  serve the page from DIR instead (for working on it)

///|
extern "C" fn activate_existing() -> Int32 = "nwu_activate_existing"

///|
#borrow(icon)
extern "C" fn create_window(w : Int32, h : Int32, icon : String) -> UInt64 = "nwu_create"

///|
extern "C" fn client_size() -> Int32 = "nwu_client_size"

///|
extern "C" fn pump() -> Int32 = "nwu_pump"

///|
extern "C" fn take_resize() -> Int32 = "nwu_take_resize"

///|
extern "C" fn take_close() -> Int32 = "nwu_take_close"

///|
extern "C" fn destroy_window() -> Unit = "nwu_destroy"

///|
#borrow(text)
extern "C" fn message_box(text : String) -> Unit = "nwu_message_box"

///|
fn own_path() -> String {
  @sys.image_path(@sys.current_pid()).unwrap_or("netwhere-ui.exe")
}

///|
fn dir_of(path : String) -> String {
  match path.rev_find("\\") {
    Some(i) => path[:i].to_owned()
    None => "."
  }
}

///|
fn rect_of(packed : Int32) -> @moonview.Rect {
  @moonview.Rect::new(x=0, y=0, width=packed >> 16, height=packed & 0xffff)
}

///|
fn arg_value(args : Array[String], name : String) -> String? {
  for i in 0..<(args.length() - 1) {
    if args[i] == name {
      return Some(args[i + 1])
    }
  }
  None
}

///|
fn mime_of(path : String) -> String {
  if path.has_suffix(".html") {
    "text/html; charset=utf-8"
  } else if path.has_suffix(".css") {
    "text/css; charset=utf-8"
  } else if path.has_suffix(".js") {
    "text/javascript; charset=utf-8"
  } else if path.has_suffix(".svg") {
    "image/svg+xml"
  } else {
    "application/octet-stream"
  }
}

///|
/// The file behind netwhere://app/<name>: embedded, or from --web DIR.
fn asset(web_dir : String?, name : String) -> String? {
  // Only plain names: no directories, no "..".
  for c in name {
    match c {
      'a'..<='z' | 'A'..<='Z' | '0'..<='9' | '-' | '_' | '.' => ()
      _ => return None
    }
  }
  if name.contains("..") {
    return None
  }
  match web_dir {
    Some(d) => @control.read_text(d + "\\" + name)
    None => web_assets.get(name)
  }
}

///|
let scheme_prefix : String = "netwhere://app/"

///|
fn view_error(e : @moonview.WebViewError) -> String {
  match e {
    Unavailable => "WebView2 运行时不可用"
    Unsupported(s) => "不支持：\{s}"
    ConfigurationLocked => "配置已锁定"
    CreateRejected => "创建被拒绝"
    WrongThread => "线程错误"
    Destroyed => "已销毁"
    NativeFailure(code, s) => "错误 \{code}：\{s}"
  }
}

///|
fn main {
  let args = @env.args()
  if activate_existing() != 0 {
    return
  }
  let dir = arg_value(args, "--data-dir").unwrap_or(@sys.data_dir())
  let web_dir = arg_value(args, "--web")
  let icons = @icon.write_icons()
  let hwnd = create_window(1200, 800, icons.get("running").unwrap_or(""))
  if hwnd == 0UL {
    message_box("无法创建窗口")
    return
  }
  ignore(@moonview.register_custom_scheme("netwhere"))
  let view : Ref[@moonview.WebView?] = Ref(None)
  let api : Api = {
    dir,
    offset: @sys.utc_offset_minutes(),
    builtin: None,
    save_dialog: name => {
      guard view.val is Some(w) else { return None }
      match
        w.show_file_dialog(
          @moonview.FileDialogOptions::new(
            kind=SaveFile,
            title=Some("导出 CSV"),
            filters=[
              @moonview.FileDialogFilter::new(name="CSV", extensions=["csv"]),
            ],
            default_name=Some(name),
          ),
        ) {
        Ok(Selected([path, ..])) => Some(path)
        _ => None
      }
    },
  }
  let on_event = fn(ev : @moonview.WebViewEvent) {
    match ev {
      ProtocolRequest(req) =>
        if view.val is Some(w) {
          let name0 = if req.uri.has_prefix(scheme_prefix) {
            req.uri[scheme_prefix.length():].to_owned()
          } else {
            ""
          }
          // Drop a query or fragment (WebView2 passes the fragment along).
          let mut name1 = name0
          for sep in ["#", "?"] {
            if name1.find(sep) is Some(i) {
              name1 = name1[:i].to_owned()
            }
          }
          let name = if name1 == "" { "index.html" } else { name1 }
          let resp = match asset(web_dir, name) {
            Some(text) =>
              @moonview.ProtocolResponse::new(
                status=200,
                headers=[
                  @moonview.HttpHeader::new(
                    name="Content-Type",
                    value=mime_of(name),
                  ),
                  @moonview.HttpHeader::new(
                    name="Cache-Control",
                    value="no-store",
                  ),
                ],
                body=@utf8.encode(text[:]),
              )
            None => @moonview.ProtocolResponse::new(status=404)
          }
          ignore(w.respond_protocol(req.id, resp))
        }
      PageMessage(text) => {
        // Messages only from our own page.
        guard view.val is Some(w) &&
          w.page_message_source().unwrap_or("").has_prefix(scheme_prefix) else {
          return
        }
        let m = @json.parse(text) catch { _ => return }
        guard m is { "id": Number(_, ..) as id, "q": String(q), .. } else {
          return
        }
        let arg = match m {
          { "arg": a, .. } => a
          _ => Json::null()
        }
        let reply = match api.call(q, arg) {
          Object(fields) => {
            fields["id"] = id
            Json::object(fields)
          }
          other => other
        }
        ignore(w.post_message(reply.stringify()))
      }
      CreationFailed(e) =>
        message_box(
          "无法创建 WebView2（\{view_error(e)}）。请确认已安装 Microsoft Edge WebView2 运行时。",
        )
      ProcessFailed(e) =>
        message_box("WebView2 进程出错：\{view_error(e)}")
      _ => ()
    }
  }
  let options = @moonview.WebViewOptions::new(
    bounds=rect_of(client_size()),
    context=@moonview.WebContext::persistent(
      data_directory=@icon.user_dir() + "\\webview2",
    ),
    initial_url=scheme_prefix + "index.html",
    on_event~,
    on_navigation=url => {
      if url.has_prefix(scheme_prefix) {
        Allow
      } else {
        Deny
      }
    },
    on_new_window=_ => Deny,
  )
  match @moonview.WebView::create_in_context(options.context, hwnd, options) {
    Ok(w) => view.val = Some(w)
    Err(e) => {
      message_box("无法创建 WebView2：\{view_error(e)}")
      destroy_window()
    }
  }
  while pump() != 0 {
    let r = take_resize()
    if r >= 0 && view.val is Some(w) {
      ignore(w.set_bounds(rect_of(r)))
    }
    if take_close() != 0 {
      if view.val is Some(w) {
        ignore(w.destroy())
        view.val = None
      }
      destroy_window()
    }
  }
}
