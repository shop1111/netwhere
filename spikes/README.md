# spikes

One-off feasibility programs. Each directory is its own MoonBit module, so its
dependencies never leak into `shop1111/netwhere`.

| dir | question |
|---|---|
| `sqlite` | Can a read-only principal read a WAL database written by the collector, before and after the collector exits? (`write`, `write-persist`, `read`, `schema`, `trigger`) |
| `mihomo_ws` | Can `moonbitlang/async` subscribe to Mihomo `/connections` and `/logs`, and does `/logs` catch connections that snapshots miss? |

```powershell
cd spikes\sqlite;    moon build --target native
cd spikes\mihomo_ws; moon build --target native
_build\native\debug\build\cmd\main\main.exe 127.0.0.1:9090 9 200 info
```
