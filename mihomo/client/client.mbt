// Mihomo external-controller client (native, moonbitlang/async).
//
// Subscriptions reconnect on their own with exponential backoff, so a core
// restart (or the core starting after netwhere) is not an error.

///|
pub(all) struct Controller {
  /// "host:port" of external-controller, e.g. "127.0.0.1:9090".
  addr : String
  /// Bearer secret; empty when the controller has none.
  secret : String
}

///|
pub fn Controller::new(
  addr~ : String = "127.0.0.1:9090",
  secret~ : String = "",
) -> Controller {
  { addr, secret, }
}

///|
fn Controller::headers(
  self : Controller,
) -> Map[@http.CaseInsensitiveString, String] {
  let h = Map([])
  if self.secret != "" {
    h[@http.CaseInsensitiveString("Authorization")] = "Bearer " + self.secret
  }
  h
}

///|
/// GET a JSON endpoint ("/configs", "/version", ...).
pub async fn Controller::get_json(self : Controller, path : String) -> Json {
  let (resp, body) = @http.get(
    "http://\{self.addr}\{path}",
    headers=self.headers(),
  )
  if resp.code != 200 {
    raise @mihomo.DecodeError("GET \{path}: HTTP \{resp.code} \{resp.reason}")
  }
  body.json()
}

///|
pub async fn Controller::configs(self : Controller) -> @mihomo.CoreConfig {
  @mihomo.decode_configs(self.get_json("/configs"))
}

///|
/// Connection state of a subscription, reported through `on_state`.
pub(all) enum LinkState {
  Connected
  Disconnected(String)
}

///|
/// Keeps a WebSocket subscription alive forever (until cancelled), calling
/// `on_text` for every text frame. Backoff: 0.5 s doubling to 30 s, reset
/// after a successful connection.
pub async fn Controller::subscribe(
  self : Controller,
  path : String,
  on_text : async (String) -> Unit,
  on_state~ : (LinkState) -> Unit = _ => (),
) -> Unit {
  let mut backoff = 500
  for ;; {
    try {
      let ws = @websocket.connect(
        "ws://\{self.addr}\{path}",
        headers=self.headers(),
      )
      defer ws.close()
      on_state(Connected)
      backoff = 500
      for ;; {
        let msg = ws.recv()
        let text = msg.read_all().text()
        on_text(text)
      }
    } catch {
      // Cancellation is not an error and never reaches this handler.
      e => on_state(Disconnected(e.to_string()))
    }
    @async.sleep(backoff)
    backoff = if backoff * 2 > 30000 { 30000 } else { backoff * 2 }
  }
}

///|
/// /connections stream with the given push interval (milliseconds).
pub async fn Controller::watch_connections(
  self : Controller,
  interval_ms : Int32,
  on_text : async (String) -> Unit,
  on_state~ : (LinkState) -> Unit = _ => (),
) -> Unit {
  self.subscribe("/connections?interval=\{interval_ms}", on_text, on_state~)
}

///|
/// /logs stream at "info" level: one routed-connection line per connection.
pub async fn Controller::watch_logs(
  self : Controller,
  on_text : async (String) -> Unit,
  on_state~ : (LinkState) -> Unit = _ => (),
) -> Unit {
  self.subscribe("/logs?level=info", on_text, on_state~)
}
