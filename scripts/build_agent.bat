@echo off
REM Build the TypeScript Frida agent into agent.js

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set AGENT_DIR=%PROJECT_DIR%\agent
set OUTPUT=%PROJECT_DIR%\clsdumper\frida\scripts\agent.js

echo Building Frida agent...

cd /d "%AGENT_DIR%"

REM Install dependencies if needed
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

REM Build with frida-compile
echo Compiling TypeScript → agent.js...
call npm run build

if exist "%OUTPUT%" (
    echo Build successful: %OUTPUT%
) else (
    echo ERROR: Build failed
    exit /b 1
)
