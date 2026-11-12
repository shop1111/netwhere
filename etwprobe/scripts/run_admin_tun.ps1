# Elevated TUN-mode experiments. Switch FlClash to TUN mode first; the script stops
# if no TUN adapter is up. Raw output goes to evidence\raw\tun-*.
param(
  [string]$Exe = "$PSScriptRoot\..\_build\native\release\build\cmd\probe\probe.exe",
  [string]$Out = "$PSScriptRoot\..\evidence\raw",
  [string]$Controller = "http://127.0.0.1:9090"
)
New-Item -ItemType Directory -Force $Out | Out-Null
$Exe = (Resolve-Path $Exe).Path
$Out = (Resolve-Path $Out).Path

# 0. environment: TUN adapter, routes, DNS, system proxy, Mihomo config
$tun = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Wintun|TUN|Meta|FlClash' -or $_.Name -match 'Wintun|TUN|Meta|FlClash') }
& {
  "== TUN adapters"; $tun | Format-Table Name, InterfaceDescription, ifIndex, Status | Out-String
  "== IP of TUN"; $tun | ForEach-Object { Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue } | Format-Table IPAddress, PrefixLength | Out-String
  "== default routes"; Get-NetRoute -DestinationPrefix '0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0' -ErrorAction SilentlyContinue | Format-Table DestinationPrefix, InterfaceAlias, RouteMetric | Out-String
  "== DNS servers"; Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | Format-Table InterfaceAlias, ServerAddresses | Out-String
  $is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  "== system proxy: ProxyEnable=$($is.ProxyEnable) ProxyServer=$($is.ProxyServer)"
} | Out-File -Encoding utf8 "$Out\tun-env.txt"
curl.exe -s --noproxy "*" "$Controller/configs" -o "$Out\tun-configs.json"
if (-not $tun) { "no TUN adapter is up; switch FlClash to TUN mode and rerun" | Out-File -Encoding utf8 -Append "$Out\tun-env.txt"; exit 2 }

function Run([string]$name, [string]$probeArgs) {
  cmd /c "`"$Exe`" $probeArgs > `"$Out\$name.txt`" 2>&1"
}

# 1. scenario traces. --noproxy forces curl past the env/system proxy so it uses TUN.
Run "tun-trace-curl-baidu" "trace -- curl.exe -s -o NUL --noproxy * https://www.baidu.com"
Run "tun-trace-curl-github" "trace -- curl.exe -s -o NUL --noproxy * https://www.github.com"
Run "tun-trace-git-ls-remote" "trace -- git ls-remote https://github.com/moonbitlang/core.git HEAD"
Run "tun-trace-curl-proxyport" "trace -- curl.exe -s -o NUL -x http://127.0.0.1:7890 https://www.github.com"

# 2. 20 MB through TUN with a kept-alive pause, snapshots every second for the join
$url = "https://speed.cloudflare.com/__down?bytes"
$probeArgs = "trace -- curl.exe -s -o NUL -o NUL --noproxy * --rate 1/12s --limit-rate 4M $url=20000000 $url=0"
$p = Start-Process -FilePath cmd.exe -ArgumentList "/c `"`"$Exe`" $probeArgs > `"$Out\tun-trace-curl-20mb.txt`" 2>&1`"" -WindowStyle Hidden -PassThru
for ($i = 1; $i -le 16; $i++) {
  Start-Sleep 1
  curl.exe -s --noproxy "*" "$Controller/connections" -o "$Out\tun-20mb-snap-$i.json"
}
$p.WaitForExit()

# 3. machine-wide view for 15 s while a TUN download runs (what does the core's side look like?)
$p = Start-Process -FilePath cmd.exe -ArgumentList "/c `"`"$Exe`" net 15 7890 > `"$Out\tun-net.txt`" 2>&1`"" -WindowStyle Hidden -PassThru
Start-Sleep 3
curl.exe -s -o NUL --noproxy "*" --limit-rate 2M "$url=8000000"
$p.WaitForExit()
