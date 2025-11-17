$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Compiling Multi-Server Config Injector" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if embedded client header exists
if (-not (Test-Path "embedded_client_multiserver.h")) {
    Write-Host "ERROR: embedded_client_multiserver.h not found!" -ForegroundColor Red
    Write-Host "Please run Step 2 first (Generate embedded client binary)" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Found embedded_client_multiserver.h" -ForegroundColor Green
Write-Host ""

# Check Visual Studio
Write-Host "Checking Visual Studio environment..." -ForegroundColor Yellow

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $vsPath)) {
    Write-Host "ERROR: Visual Studio 2022 not found at:" -ForegroundColor Red
    Write-Host "  $vsPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Visual Studio 2022 Community or update the path" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Visual Studio 2022 found" -ForegroundColor Green
Write-Host ""

# Compile config injector
Write-Host "Compiling config injector for multi-server version..." -ForegroundColor Yellow
Write-Host "  Source: config_injector_multiserver.cpp" -ForegroundColor Gray
Write-Host "  Output: DNFConfigInjector_MultiServer.exe" -ForegroundColor Gray
Write-Host ""

$compileCommand = @"
"$vsPath" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe:DNFConfigInjector_MultiServer.exe config_injector_multiserver.cpp 2>&1
"@

$output = cmd /c $compileCommand

# Check for compilation errors
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Compilation FAILED!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error output:" -ForegroundColor Yellow
    Write-Host $output
    exit 1
}

# Check for warnings
if ($output -match "warning") {
    Write-Host ""
    Write-Host "Compilation succeeded with warnings:" -ForegroundColor Yellow
    $output | Select-String "warning" | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host ""
}

# Clean up temp files
Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
Remove-Item "config_injector_multiserver.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

# Get file size
if (Test-Path "DNFConfigInjector_MultiServer.exe") {
    $fileSize = (Get-Item "DNFConfigInjector_MultiServer.exe").Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)

    Write-Host "Output file: DNFConfigInjector_MultiServer.exe" -ForegroundColor Cyan
    Write-Host "File size: $fileSizeKB KB" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  1. Run 'DNFConfigInjector_MultiServer.exe'" -ForegroundColor Gray
    Write-Host "  2. Enter API server domain (e.g., config.server.com)" -ForegroundColor Gray
    Write-Host "  3. Enter API port (default: 8080)" -ForegroundColor Gray
    Write-Host "  4. Tool will generate configured client with API config embedded" -ForegroundColor Gray
    Write-Host ""

    Write-Host "Config format embedded in exe:" -ForegroundColor Yellow
    Write-Host '  {"config_api_url":"config.server.com","config_api_port":8080}' -ForegroundColor DarkGray
    Write-Host ""

} else {
    Write-Host "ERROR: Output file not found!" -ForegroundColor Red
    exit 1
}
