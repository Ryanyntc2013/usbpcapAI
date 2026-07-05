param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("debug", "release")]
    [string]$Config = "release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# ---- Read version ----
$versionFile = Join-Path $root "VERSION"
if (-not (Test-Path $versionFile)) {
    Write-Host "ERROR: VERSION file not found at $versionFile" -ForegroundColor Red
    exit 1
}
$version = (Get-Content $versionFile).Trim()
if ([string]::IsNullOrEmpty($version)) {
    Write-Host "ERROR: VERSION file is empty" -ForegroundColor Red
    exit 1
}
Write-Host ">>> Building USBPcap MCP release package v$version ($Config)..." -ForegroundColor Green

# ---- Directories ----
$buildDir = Join-Path $root "out/build/vs2022-x64-$Config/bin/$(if ($Config -eq 'debug') { 'Debug' } else { 'Release' })"
$pkgName = "usbpcap-mcp-v$version"
$stagingDir = Join-Path $root "output/$pkgName"
$zipFile = Join-Path $root "output/$pkgName.zip"
$goDir = Join-Path $root "USBPcapAI"

# ---- Clean staging ----
if (Test-Path $stagingDir) {
    Remove-Item -Recurse -Force $stagingDir
}
$null = New-Item -Force -ItemType Directory $stagingDir
$null = New-Item -Force -ItemType Directory (Join-Path $stagingDir "captures")

# ---- Step 1: Run Go tests ----
Write-Host ">>> Step 1/4: Running Go tests..." -ForegroundColor Cyan
Push-Location $goDir
try {
    go test ./...
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Go tests failed" -ForegroundColor Red
        Pop-Location
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

# ---- Step 2: Build Go binaries with version ldflags ----
Write-Host ">>> Step 2/4: Building Go binaries (version=$version)..." -ForegroundColor Cyan
$ldflags = "-s -w -X main.version=$version"
Push-Location $goDir
try {
    go build -ldflags $ldflags -o (Join-Path $stagingDir "USBPcapMCP.exe") ./cmd/usbpcap-mcp/
    go build -ldflags $ldflags -o (Join-Path $stagingDir "USBPcapService.exe") ./cmd/usbpcap-service/
} finally {
    Pop-Location
}

# ---- Step 3: Copy C binary (pre-built via cmake) ----
Write-Host ">>> Step 3/4: Copying USBPcapCap.exe..." -ForegroundColor Cyan
$cmdSrc = Join-Path $buildDir "USBPcapCap.exe"
if (-not (Test-Path $cmdSrc)) {
    Write-Host "ERROR: USBPcapCap.exe not found at $cmdSrc. Run cmake build first." -ForegroundColor Red
    exit 1
}
Copy-Item $cmdSrc $stagingDir

# ---- Step 4: Copy supporting files ----
Write-Host ">>> Step 4/4: Copying supporting files..." -ForegroundColor Cyan
Copy-Item (Join-Path $root "VERSION") $stagingDir
Copy-Item (Join-Path $root "doc" "mcp-install-guide.md") $stagingDir

# ---- Step 4b: Copy drivers (if available) ----
$driversSrc = Join-Path $root "drivers"
$driversDst = Join-Path $stagingDir "drivers"
if (Test-Path $driversSrc) {
    # Copy only directories that contain at least one driver file
    $hasDrivers = $false
    Get-ChildItem -Directory $driversSrc | ForEach-Object {
        $osDir = $_
        Get-ChildItem -Directory $osDir.FullName | ForEach-Object {
            $archDir = $_
            $infFiles = Get-ChildItem -Path $archDir.FullName -Filter "*.inf" -ErrorAction SilentlyContinue
            if ($infFiles.Count -gt 0) {
                $dstPath = Join-Path $driversDst $osDir.Name $archDir.Name
                $null = New-Item -Force -ItemType Directory $dstPath
                Copy-Item (Join-Path $archDir.FullName "*") $dstPath
                $hasDrivers = $true
            }
        }
    }
    if ($hasDrivers) {
        Write-Host "  Drivers included." -ForegroundColor DarkGray
    } else {
        Write-Host "  No driver files found in drivers/, skipping." -ForegroundColor DarkYellow
    }
}

# ---- Create zip ----
Write-Host ">>> Creating $zipFile..." -ForegroundColor Cyan
try {
    Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipFile -Force -ErrorAction Stop
} catch {
    # If the file is locked (e.g. open in Explorer), use a timestamped fallback name
    if ($_.Exception.Message -match "being used by another process|access") {
        $ts = Get-Date -Format "yyyyMMdd-HHmmss"
        $fallbackZip = Join-Path $root "output/usbpcap-mcp-v${version}-${ts}.zip"
        Write-Host "WARNING: $zipFile locked, using fallback: $fallbackZip" -ForegroundColor Yellow
        Compress-Archive -Path "$stagingDir\*" -DestinationPath $fallbackZip -Force -ErrorAction Stop
        $zipFile = $fallbackZip
    } else {
        throw
    }
}

# ---- Cleanup staging ----
Remove-Item -Recurse -Force $stagingDir

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Release package created:" -ForegroundColor Green
Write-Host "  $zipFile" -ForegroundColor White
Write-Host "  Version: v$version" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
