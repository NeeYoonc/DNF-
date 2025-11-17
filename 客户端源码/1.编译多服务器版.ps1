$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Compiling DNF Proxy Client v12.4.0" -ForegroundColor Cyan
Write-Host "Multi-Server Version with GUI Selector" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Generate embedded WinDivert files
Write-Host "[1/3] Generating embedded WinDivert files..." -ForegroundColor Yellow
python generate_embedded_windivert.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to generate embedded WinDivert!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ WinDivert files embedded" -ForegroundColor Green
Write-Host ""

# Step 2: Check Visual Studio
Write-Host "[2/3] Checking Visual Studio environment..." -ForegroundColor Yellow

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

# Step 3: Compile resources
Write-Host "[3/4] Compiling resources..." -ForegroundColor Yellow
Write-Host "  - Background image: background.jpg" -ForegroundColor Gray
Write-Host ""

$rcCommand = @"
"$vsPath" >nul 2>&1 && rc /fo app.res app.rc 2>&1
"@

$rcOutput = cmd /c $rcCommand
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Resource compilation FAILED!" -ForegroundColor Red
    Write-Host $rcOutput
    exit 1
}
Write-Host "✓ Resources compiled" -ForegroundColor Green
Write-Host ""

# Step 4: Compile multi-server version
Write-Host "[4/4] Compiling multi-server version..." -ForegroundColor Yellow
Write-Host "  - Main: tcp_proxy_client_no_config.cpp" -ForegroundColor Gray
Write-Host "  - TCP Config: tcp_config_client.cpp" -ForegroundColor Gray
Write-Host "  - GUI: server_selector_gui.cpp" -ForegroundColor Gray
Write-Host "  - Config: config_manager.cpp" -ForegroundColor Gray
Write-Host "  - Auto Update: auto_updater.cpp" -ForegroundColor Gray
Write-Host "  - Resources: app.res" -ForegroundColor Gray
Write-Host ""

$compileCommand = @"
"$vsPath" >nul 2>&1 && cl /EHsc /O2 /std:c++14 /utf-8 /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fe"DNF_Proxy_Client_MultiServer_v12.4.0.exe" tcp_proxy_client_no_config.cpp tcp_config_client.cpp server_selector_gui.cpp config_manager.cpp auto_updater.cpp app.res /link ws2_32.lib advapi32.lib iphlpapi.lib setupapi.lib newdev.lib cfgmgr32.lib shell32.lib comctl32.lib user32.lib gdi32.lib gdiplus.lib ole32.lib WinDivert.lib 2>&1
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
Remove-Item "tcp_proxy_client_no_config.obj" -ErrorAction SilentlyContinue
Remove-Item "tcp_config_client.obj" -ErrorAction SilentlyContinue
Remove-Item "server_selector_gui.obj" -ErrorAction SilentlyContinue
Remove-Item "config_manager.obj" -ErrorAction SilentlyContinue
Remove-Item "auto_updater.obj" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Compilation Successful!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Get file size
if (Test-Path "DNF_Proxy_Client_MultiServer_v12.4.0.exe") {
    $fileSize = (Get-Item "DNF_Proxy_Client_MultiServer_v12.4.0.exe").Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)

    Write-Host "Output file: DNF_Proxy_Client_MultiServer_v12.4.0.exe" -ForegroundColor Cyan
    Write-Host "File size: $fileSizeKB KB ($fileSizeMB MB)" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "New features in v12.4.0:" -ForegroundColor Yellow
    Write-Host "  ✓ TCP protocol integration - fetch server list via TCP (no HTTP备案 needed)" -ForegroundColor Gray
    Write-Host "  ✓ GUI server selector - Windows-style dialog" -ForegroundColor Gray
    Write-Host "  ✓ Remember last choice - saved to %APPDATA%\DNFProxy\" -ForegroundColor Gray
    Write-Host "  ✓ WinDivert embedded - single-file distribution" -ForegroundColor Gray
    Write-Host "  ✓ Auto-update feature - download and replace on startup" -ForegroundColor Gray
    Write-Host ""

    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Use config injection tool to add API config to exe" -ForegroundColor Gray
    Write-Host "     Config format:" -ForegroundColor Gray
    Write-Host "     {`"config_api_url`":`"config.server.com`",`"config_api_port`":35000}" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  2. Setup TCP server to listen and return:" -ForegroundColor Gray
    Write-Host "     - GET_SERVERS: JSON server list" -ForegroundColor DarkGray
    Write-Host "     - GET_VERSION: {`"latest_version`":`"1.0.0`",`"download_url`":`"..`"}" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  3. Run the client (requires admin privileges)" -ForegroundColor Gray
    Write-Host ""

} else {
    Write-Host "ERROR: Output file not found!" -ForegroundColor Red
    exit 1
}
