param(
    [Parameter(Mandatory)]
    [ValidateSet("debug", "release")]
    [string]$Config
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root "out/build/vs2022-x64-$Config/bin/$(if ($Config -eq 'debug') { 'Debug' } else { 'Release' })"
$dst = Join-Path $root "output/$Config"

# ---- Read version ----
$versionFile = Join-Path $root "VERSION"
$version = "dev"
if (Test-Path $versionFile) {
    $version = (Get-Content $versionFile).Trim()
}
$ldflags = "-s -w -X main.version=$version"

Write-Host ">>> Building Go binaries for $Config (version=$version)..."
Push-Location (Join-Path $root "USBPcapAI")
try {
    go build -ldflags $ldflags -o (Join-Path $src "USBPcapMCP.exe") ./cmd/usbpcap-mcp/
    go build -ldflags $ldflags -o (Join-Path $src "USBPcapService.exe") ./cmd/usbpcap-service/
} finally {
    Pop-Location
}

Write-Host ">>> Copying artifacts to output/$Config..."
$null = New-Item -Force -ItemType Directory (Join-Path $dst "captures")
Copy-Item (Join-Path $src "USBPcapCap.exe"), `
         (Join-Path $src "USBPcapMCP.exe"), `
         (Join-Path $src "USBPcapService.exe") `
         $dst

# Copy supporting files
if (Test-Path $versionFile) {
    Copy-Item $versionFile $dst
}
Copy-Item (Join-Path $root "doc" "mcp-install-guide.md") $dst

Write-Host ">>> build-all-$Config complete"
