# Elevated half of record-scenarios.ps1: runs `netwhered record` and keeps
# its console output in a log file. Started through UAC; do not run directly.
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$Out,
  [Parameter(Mandatory = $true)][string]$Stop,
  [Parameter(Mandatory = $true)][string]$Ready,
  [Parameter(Mandatory = $true)][string]$Log,
  [string]$Controller = "127.0.0.1:9090",
  [string]$Note = ""
)
& $Exe record --out $Out --secs 900 --stop-file $Stop --ready-file $Ready `
  --controller $Controller --note $Note *> $Log
exit $LASTEXITCODE
