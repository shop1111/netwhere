<#
Records the known-outcome scenarios of PLAN.md section 6 in one session.

Run from a NORMAL (not elevated) PowerShell in the repository root:

  .\scripts\record-scenarios.ps1 -Mode system-proxy
  .\scripts\record-scenarios.ps1 -Mode tun

One UAC prompt per run starts the elevated recorder; every scenario command
runs in this shell's own environment, which is the point: an elevated shell
may have a different environment (for example no HTTPS_PROXY).

Before -Mode system-proxy: FlClash "system proxy" on, TUN off.
Before -Mode tun:          FlClash TUN on (fake-ip), system proxy off.
Before -Mode singbox:      sing-box running with a mixed inbound and the
                           Clash API; pass -ProxyPort and -Controller.

Output (raw, NOT for committing): testdata\raw\<mode>.ndjson, <mode>.log,
<mode>.manifest.json. Then sanitize:

  python -I scripts\sanitize_recording.py testdata\raw\<mode>.manifest.json testdata\scenarios
#>
param(
  [Parameter(Mandatory = $true)][ValidateSet("system-proxy", "tun", "singbox")][string]$Mode,
  [string]$Controller = "127.0.0.1:9090",
  [int]$ProxyPort = 7890,
  [int]$Bytes = 5000000,
  [string]$OutDir = "testdata\raw",
  [switch]$NoBuild
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this from a normal (unelevated) PowerShell: scenario commands must see your usual environment."
}

if (-not $NoBuild) {
  Push-Location $root
  moon build --target native --release
  if ($LASTEXITCODE -ne 0) { throw "build failed" }
  Pop-Location
}
$exe = Join-Path $root "_build\native\release\build\cmd\netwhered\netwhered.exe"
if (-not (Test-Path $exe)) { throw "missing $exe" }

$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Force $out | Out-Null
$rec = Join-Path $out "$Mode.ndjson"
$log = Join-Path $out "$Mode.log"
$stop = Join-Path $out "$Mode.stop"
$ready = Join-Path $out "$Mode.ready"
foreach ($f in @($rec, $log, $stop, $ready)) { if (Test-Path $f) { Remove-Item $f } }

# --- environment facts that decide the expected routes --------------------
$envProxy = @($env:HTTPS_PROXY, $env:https_proxy, $env:HTTP_PROXY, $env:http_proxy, $env:ALL_PROXY) |
  Where-Object { $_ } | Select-Object -First 1
$gitProxy = (& git config --get http.proxy 2>$null)
$inet = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$systemProxy = ($inet.ProxyEnable -eq 1)
Write-Host "mode=$Mode envProxy=$([bool]$envProxy) gitProxy=$([bool]$gitProxy) systemProxy=$systemProxy"

# --- start the elevated recorder ------------------------------------------
$runner = Join-Path $PSScriptRoot "run-recorder.ps1"
$argList = @(
  "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$runner`"",
  "-Exe", "`"$exe`"", "-Out", "`"$rec`"", "-Stop", "`"$stop`"", "-Ready", "`"$ready`"",
  "-Log", "`"$log`"", "-Controller", $Controller, "-Note", "`"scenarios $Mode`""
)
$recorder = Start-Process powershell -Verb RunAs -WindowStyle Minimized -ArgumentList $argList -PassThru
$deadline = (Get-Date).AddSeconds(90)
while (-not (Test-Path $ready)) {
  if ((Get-Date) -gt $deadline) { throw "recorder did not start; see $log" }
  if ($recorder.HasExited) { throw "recorder exited early; see $log" }
  Start-Sleep -Milliseconds 300
}
Start-Sleep -Seconds 2

# --- scenarios ------------------------------------------------------------
$url = "https://speed.cloudflare.com/__down?bytes=$Bytes"
$small = "https://speed.cloudflare.com/__down?bytes=200000"
$curl = Join-Path $env:SystemRoot "System32\curl.exe"
$scenarios = @()

function Invoke-Scenario($name, $file, $arguments, $expect, [hashtable]$setEnv = @{}) {
  $saved = @{}
  foreach ($k in $setEnv.Keys) {
    $saved[$k] = [Environment]::GetEnvironmentVariable($k, "Process")
    [Environment]::SetEnvironmentVariable($k, $setEnv[$k], "Process")
  }
  try {
    $started = Get-Date
    $p = Start-Process -FilePath $file -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    $code = $p.ExitCode
  } finally {
    foreach ($k in $setEnv.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], "Process") }
  }
  Write-Host ("{0,-18} pid {1,-6} exit {2}" -f $name, $p.Id, $code)
  $script:scenarios += [ordered]@{
    name = $name; command = "$file $arguments"; pid = $p.Id; exit_code = $code
    started = $started.ToUniversalTime().ToString("o"); expect = $expect
  }
  Start-Sleep -Seconds 2
}

if ($Mode -eq "singbox") {
  # sing-box with a mixed inbound on -ProxyPort and the Clash API on
  # -Controller; route: baidu.com -> a direct outbound with a custom tag,
  # everything else -> an http outbound (another proxy). Exits come from
  # sing-box snapshots, and from its multi-line logs for short connections.
  Invoke-Scenario "singbox-node" $curl "-s -o NUL -x http://127.0.0.1:$ProxyPort `"$url`"" @(
    [ordered]@{ process = "curl.exe"; entry = "proxy-port"; exit = "node"; down_min = $Bytes; only = $true }
  )
  Invoke-Scenario "singbox-direct-tag" $curl "-s -o NUL -x http://127.0.0.1:$ProxyPort https://www.baidu.com" @(
    [ordered]@{ process = "curl.exe"; entry = "proxy-port"; exit = "DIRECT (core)"; down_min = 1000; only = $true }
  )
  # Several short connections in one command (different hosts, no reuse):
  # most end between two snapshots, so the logs carry their exits.
  Invoke-Scenario "singbox-short" $curl "-s -o NUL -o NUL -o NUL -x http://127.0.0.1:$ProxyPort https://www.baidu.com/robots.txt `"$small`" https://github.com/robots.txt" @(
    [ordered]@{ process = "curl.exe"; entry = "proxy-port"; exit = "core"; down_min = 1000; only = $true }
  )
} else {
  # Entry expected for a direct (non-proxy-port) connection over IPv4.
  $v4Direct = if ($Mode -eq "tun") { "tun" } else { "bypass" }
  $v4DirectExit = if ($Mode -eq "tun") { "core" } else { "-" }

  Invoke-Scenario "curl-proxy-port" $curl "-s -o NUL -x http://127.0.0.1:$ProxyPort `"$url`"" @(
    [ordered]@{ process = "curl.exe"; entry = "proxy-port"; exit = "core"; down_min = $Bytes; only = $true }
  )
  Invoke-Scenario "curl-noproxy-v4" $curl "-4 -s -o NUL --noproxy * `"$url`"" @(
    [ordered]@{ process = "curl.exe"; entry = $v4Direct; exit = $v4DirectExit; down_min = $Bytes; only = $true }
  )
  Invoke-Scenario "curl-env-proxy" $curl "-4 -s -o NUL `"$url`"" @(
    [ordered]@{ process = "curl.exe"; entry = "proxy-port"; exit = "core"; down_min = $Bytes; only = $true }
  ) @{ HTTPS_PROXY = "http://127.0.0.1:$ProxyPort"; HTTP_PROXY = $null; ALL_PROXY = $null }
  # IPv6 never went through TUN on the probe machine; route facts decide.
  Invoke-Scenario "curl-noproxy-v6" $curl "-6 -s -o NUL --noproxy * `"$url`"" @(
    [ordered]@{ process = "curl.exe"; entry = "route"; exit = "any"; down_min = $Bytes; only = $true }
  )
  # Without a proxy setting the address family is the client's choice (IPv6
  # bypasses TUN on some machines), so only "not through the proxy port" is
  # asserted and the recorded route facts decide the rest.
  $gitEntry = if ($envProxy -or $gitProxy) { "proxy-port" } else { "route" }
  $gitExit = if ($envProxy -or $gitProxy) { "core" } else { "any" }
  Invoke-Scenario "git-ls-remote" "git" "ls-remote https://github.com/git/git HEAD" @(
    [ordered]@{ process = "git-remote-https.exe"; entry = $gitEntry; exit = $gitExit; down_min = 1000; only = $false }
  )
  $iwrEntry = if ($systemProxy) { "proxy-port" } else { "route" }
  $iwrExit = if ($systemProxy) { "core" } else { "any" }
  Invoke-Scenario "powershell-iwr" "powershell" "-NoProfile -Command `"Invoke-WebRequest -UseBasicParsing '$small' | Out-Null`"" @(
    [ordered]@{ process = "powershell.exe"; entry = $iwrEntry; exit = $iwrExit; down_min = 200000; only = $false }
  )
  # UDP: a system proxy cannot carry it (diagnosis: udp-not-proxied). Under
  # TUN the query is routed into TUN and answered by the core's DNS hijack.
  $udpEntry = if ($Mode -eq "tun") { "route" } else { "bypass" }
  $udpExit = if ($Mode -eq "tun") { "any" } else { "-" }
  Invoke-Scenario "nslookup-udp" "nslookup" "example.com 1.1.1.1" @(
    [ordered]@{ process = "nslookup.exe"; entry = $udpEntry; exit = $udpExit; down_min = 20; only = $false }
  )
  if ($Mode -eq "tun") {
    # A socket bound to the physical adapter skips the TUN route although the
    # route table points at TUN (diagnosis: bound-off-tun). The physical
    # address: IPv4 of the adapters with a default route, outside the usual
    # TUN ranges (198.18.0.0/15, 172.19.0.0/16).
    $physical = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
      Sort-Object RouteMetric |
      ForEach-Object { Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue } |
      Where-Object { $_.IPAddress -notmatch '^(198\.1[89]\.|172\.19\.|169\.254\.)' } |
      Select-Object -First 1 -ExpandProperty IPAddress
    if ($physical) {
      Invoke-Scenario "curl-bound-physical" $curl "-4 -s -o NUL --noproxy * --interface $physical `"$url`"" @(
        [ordered]@{ process = "curl.exe"; entry = "bypass"; exit = "-"; down_min = $Bytes; only = $true }
      )
    } else {
      Write-Host "curl-bound-physical: no physical IPv4 address found, skipped"
    }
  }
}

# --- stop the recorder ----------------------------------------------------
Start-Sleep -Seconds 3
New-Item -ItemType File $stop | Out-Null
$deadline = (Get-Date).AddSeconds(60)
while (-not $recorder.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
Remove-Item $stop, $ready -ErrorAction SilentlyContinue

$manifest = [ordered]@{
  mode = $Mode; recording = "$Mode.ndjson"; controller = $Controller; proxy_port = $ProxyPort
  env_proxy = [bool]$envProxy; git_proxy = [bool]$gitProxy; system_proxy = $systemProxy
  scenarios = $scenarios
}
$manifestPath = Join-Path $out "$Mode.manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $manifestPath
Write-Host ""
Get-Content $log
Write-Host ""
Write-Host "manifest: $manifestPath"
Write-Host "next: python -I scripts\sanitize_recording.py `"$manifestPath`" testdata\scenarios"
