@echo off
setlocal
cd /d "%~dp0"

set "DOTNET_DIR=%LOCALAPPDATA%\Microsoft\dotnet"
if exist "%DOTNET_DIR%\dotnet.exe" (
    set "DOTNET_ROOT=%DOTNET_DIR%"
    set "PATH=%DOTNET_DIR%;%PATH%"
)

set "EXE=%~dp0src\EasyDump.App\bin\Release\net8.0-windows\EasyDump.exe"

if not exist "%EXE%" (
    echo Building EasyDump ^(Release^)...
    dotnet build "%~dp0src\EasyDump.App\EasyDump.App.csproj" -c Release
    if errorlevel 1 (
        echo.
        echo Build failed.
        pause
        exit /b 1
    )
)

start "" "%EXE%"
