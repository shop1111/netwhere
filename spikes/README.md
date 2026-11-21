# spikes

One-off feasibility programs. Each directory is its own MoonBit module, so its
dependencies never leak into `shop1111/netwhere`.

| dir | question |
|---|---|
| `sqlite` | Can a read-only principal read a WAL database written by the collector, before and after the collector exits? (`write`, `write-persist`, `read`, `schema`, `trigger`) |
| `mihomo_ws` | Can `moonbitlang/async` subscribe to Mihomo `/connections` and `/logs`, and does `/logs` catch connections that snapshots miss? |
| `webview_mv` | Does `Nanaloveyuki/moonview` give the UI what it needs: page from a custom scheme, JS <-> MoonBit messages, a 2000-row table, Chinese input, resizing, and no WebView2 process left after the window closes? (`--auto MS` closes it) |
| `tray_jj` | Does `justjavac/tray` handle a Chinese menu with a checkbox, a tooltip refreshed by a thread timer, and a clean exit? (`--auto MS` exits) |

```powershell
cd spikes\sqlite;    moon build --target native
cd spikes\mihomo_ws; moon build --target native
_build\native\debug\build\cmd\main\main.exe 127.0.0.1:9090 9 200 info
cd spikes\webview_mv; moon build --target native   # Windows tar.exe must come before Git's tar on PATH
cd spikes\tray_jj;    moon build --target native
```

Rejected without a spike directory: `justjavac/webview` 0.1.10 (still `moon.mod.json`,
which current `moon` refuses; ships a prebuilt `webview.dll`) and `NoahLiu/gui-webview`
0.2.0 (tied to the whole `native-gui` framework; fetches the WebView2 loader from the
author's release page rather than NuGet).
