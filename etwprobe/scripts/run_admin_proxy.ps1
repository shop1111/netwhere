# Second elevated run: one large download forced through the proxy port, with Mihomo
# /connections snapshots taken while the (kept-alive) connection is idle, so the ETW
# byte count of the app's loopback socket can be compared with Mihomo's counter.
param(
  [string]$Exe = "$PSScriptRoot\..\_build\native\release\build\cmd\probe\probe.exe",
  [string]$Out = "$PSScriptRoot\..\evidence\raw",
  [string]$Controller = "http://127.0.0.1:9090",
  [string]$Proxy = "http://127.0.0.1:7890"
)
New-Item -ItemType Directory -Force $Out | Out-Null
$Exe = (Resolve-Path $Exe).Path
$Out = (Resolve-Path $Out).Path
$url = "https://speed.cloudflare.com/__down?bytes"
# Two transfers on one connection, 12 s apart (--rate): the first moves 20 MB, the
# pause leaves the finished counters visible in /connections.
$probeArgs = "trace -- curl.exe -s -o NUL -o NUL -x $Proxy --rate 1/12s --limit-rate 4M $url=20000000 $url=0"
$p = Start-Process -FilePath cmd.exe -ArgumentList "/c `"`"$Exe`" $probeArgs > `"$Out\trace-curl-proxy-20mb.txt`" 2>&1`"" -WindowStyle Hidden -PassThru
for ($i = 1; $i -le 16; $i++) {
  Start-Sleep 1
  curl.exe -s --noproxy "*" "$Controller/connections" -o "$Out\proxy-20mb-snap-$i.json"
}
$p.WaitForExit()
# Re-run a quick trace to check that the root process name is now resolved.
cmd /c "`"$Exe`" trace -- curl.exe -s -o NUL -x $Proxy https://www.github.com > `"$Out\trace-curl-proxy-github.txt`" 2>&1"
