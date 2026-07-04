param(
    [Parameter(Mandatory)]
    [ValidateSet("debug", "release")]
    [string]$Config
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root "out/build/vs2022-x64-$Config/bin/$(if ($Config -eq 'debug') { 'Debug' } else { 'Release' })"
$dst = Join-Path $root "output/$Config"

Write-Host ">>> Building Go binaries for $Config..."
Push-Location (Join-Path $root "USBPcapAI")
try {
    go build -o (Join-Path $src "USBPcapMCP.exe") ./cmd/usbpcap-mcp/
    go build -o (Join-Path $src "USBPcapService.exe") ./cmd/usbpcap-service/
} finally {
    Pop-Location
}

Write-Host ">>> Copying artifacts to output/$Config..."
$null = New-Item -Force -ItemType Directory (Join-Path $dst "captures")
Copy-Item (Join-Path $src "USBPcapCMD.exe"), `
         (Join-Path $src "USBPcapMCP.exe"), `
         (Join-Path $src "USBPcapService.exe") `
         $dst

Write-Host ">>> build-all-$Config complete"
