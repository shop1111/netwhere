# Runs every probe experiment that needs an elevated token, writing raw output to
# evidence\raw\. Start it once from an elevated prompt (or via Start-Process -Verb RunAs).
param(
  [string]$Exe = "$PSScriptRoot\..\_build\native\release\build\cmd\probe\probe.exe",
  [string]$Out = "$PSScriptRoot\..\evidence\raw",
  [string]$Controller = "http://127.0.0.1:9090",
  [int]$ProxyPort = 7890
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Out | Out-Null
$Exe = (Resolve-Path $Exe).Path
$Out = (Resolve-Path $Out).Path

function Run([string]$name, [string]$probeArgs) {
  Write-Host "== $name : probe $probeArgs"
  cmd /c "`"$Exe`" $probeArgs > `"$Out\$name.txt`" 2>&1"
}

function Background([string]$name, [string]$probeArgs) {
  Start-Process -FilePath cmd.exe -ArgumentList "/c `"`"$Exe`" $probeArgs > `"$Out\$name.txt`" 2>&1`"" -WindowStyle Hidden -PassThru
}

function Snapshot([string]$name) {
  try {
    (Invoke-WebRequest -Uri "$Controller/connections" -UseBasicParsing -TimeoutSec 5 -Proxy $null).Content |
      Out-File -Encoding utf8 "$Out\$name.json"
  } catch { "snapshot failed: $($_.Exception.Message)" | Out-File -Encoding utf8 "$Out\$name.json" }
}

# 1. privileges and providers
Run "env-admin" "env"

# 2. sessions outlive their process
Run "leak" "leak"
logman query MoonEtwProbe -ets > "$Out\leak-logman.txt" 2>&1
Run "check" "check"

# 3. schemas: generate a little traffic of every kind while it records
$p = Background "schema" "schema 10"
Start-Sleep 3
curl.exe -s -o NUL https://www.github.com
curl.exe -s -o NUL --noproxy "*" https://www.baidu.com
Resolve-DnsName www.bing.com -ErrorAction SilentlyContinue | Out-Null
cmd /c exit
$p.WaitForExit()

# 4. machine-wide flows for 20 s with a proxied and a direct download
$p = Background "net" "net 20 $ProxyPort"
Start-Sleep 3
curl.exe -s -o NUL --limit-rate 2M "https://speed.cloudflare.com/__down?bytes=8000000"
Snapshot "net-connections"
curl.exe -s -o NUL --noproxy "*" --limit-rate 2M "https://speed.cloudflare.com/__down?bytes=8000000"
$p.WaitForExit()

# 5. scenario traces
Run "trace-curl-env-proxy" "trace -- curl.exe -s -o NUL https://www.github.com"
Run "trace-curl-noproxy" "trace -- curl.exe -s -o NUL --noproxy * https://www.baidu.com"
Run "trace-git-ls-remote" "trace -- git ls-remote https://github.com/moonbitlang/core.git HEAD"
Run "trace-powershell-iwr" "trace -- powershell.exe -NoProfile -Command `"Invoke-WebRequest https://www.bing.com -UseBasicParsing | Out-Null`""
Run "trace-curl-direct-5mb" "trace -- curl.exe -s -o NUL --noproxy * https://speed.cloudflare.com/__down?bytes=5000000"

# 6. proxied 50 MB at 5 MB/s, with a /connections snapshot in the middle for port matching
$p = Background "trace-curl-proxy-50mb" "trace -- curl.exe -s -o NUL --limit-rate 5M https://speed.cloudflare.com/__down?bytes=50000000"
Start-Sleep 6
Snapshot "trace-curl-proxy-50mb-connections"
$p.WaitForExit()

Write-Host "done; output in $Out"
