@echo off
setlocal EnableExtensions

echo Building VOID P2P Messenger for Windows...
cd /d "%~dp0"

where cargo >nul 2>&1
if errorlevel 1 (
    echo cargo not found in PATH.
    exit /b 1
)

cargo tauri --version >nul 2>&1
if errorlevel 1 (
    echo cargo-tauri not found — installing tauri-cli (v2^)...
    cargo install tauri-cli --locked --version "^2.0.0"
    if errorlevel 1 (
        echo Failed to install tauri-cli.
        exit /b %errorlevel%
    )
)

cargo tauri build
if errorlevel 1 (
    echo Build failed!
    exit /b %errorlevel%
)

echo Build succeeded.
echo Copying application and installers to target\ ...

if not exist "target" mkdir target

REM Application binary
if exist "src-tauri\target\release\app.exe" (
    copy /Y "src-tauri\target\release\app.exe" "target\VOID-P2P-Messenger.exe" >nul
)

REM Installers
if exist "src-tauri\target\release\bundle\msi\*.msi" (
    copy /Y "src-tauri\target\release\bundle\msi\*.msi" "target\" >nul
)
if exist "src-tauri\target\release\bundle\nsis\*.exe" (
    copy /Y "src-tauri\target\release\bundle\nsis\*.exe" "target\" >nul
)

echo.
echo Artifacts in target\:
dir /b "target\*.msi" 2>nul
dir /b "target\*.exe" 2>nul
echo Done.
endlocal
