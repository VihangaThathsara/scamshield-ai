@echo off
setlocal
cd /d "%~dp0"
title ScamShield AI

echo.
echo ==========================================
echo             ScamShield AI
echo ==========================================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    set "PY_CMD=py -3"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PY_CMD=python"
    ) else (
        echo [ERROR] Python was not found.
        echo Install Python 3 and enable "Add Python to PATH".
        echo.
        pause
        exit /b 1
    )
)

if not exist "venv\Scripts\python.exe" (
    echo [1/4] Creating Python environment...
    %PY_CMD% -m venv venv
    if errorlevel 1 (
        echo [ERROR] Environment creation failed.
        pause
        exit /b 1
    )
) else (
    echo [1/4] Python environment is ready.
)

echo [2/4] Checking required packages...
"venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    pause
    exit /b 1
)
if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo Edit .env and set a unique ADMIN_PASSWORD before continuing.
    notepad .env
    pause
)

echo [3/4] Opening the application...
start "" cmd /c "timeout /t 4 /nobreak >nul & start http://127.0.0.1:5000"

echo [4/4] Starting the server...
echo.
echo URL: http://127.0.0.1:5000
echo Admin Username: admin
echo Admin password: the value you set in .env
echo.
echo Keep this window open. Press CTRL+C to stop.
echo.

"venv\Scripts\python.exe" app.py

echo.
echo Server stopped.
pause
