@echo off
setlocal enabledelayedexpansion

title IPsecGuard AI — Launcher

echo ============================================================
echo         IPsecGuard AI — Protocol Analyzer Launcher          
echo ============================================================
echo.

cd /d "%~dp0"

:: 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in PATH.
    echo Please install Python 3.11+ and add it to your PATH.
    pause
    exit /b 1
)

:: 2. Check and generate models if missing
if not exist "models\traffic_classifier.joblib" (
    echo [INFO] Pre-trained models not found. Building dataset and training...
    echo [1/2] Generating synthetic captures...
    python scripts\synth_data.py
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to generate synthetic data.
        pause
        exit /b 1
    )
    echo [2/2] Training AI traffic classifier and anomaly detector...
    python scripts\train.py
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to train models.
        pause
        exit /b 1
    )
    echo [SUCCESS] Models generated successfully.
    echo.
)

:: 3. Launch browser in background after 2 seconds
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000"

:: 4. Start Uvicorn Web Server
echo [INFO] Starting IPsecGuard AI web server on http://localhost:8000...
echo [INFO] Press Ctrl+C in this window to stop the server.
echo.

python -m uvicorn ipsecguard.api.main:app --host 127.0.0.1 --port 8000 --reload

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Web server stopped with an error.
    pause
)
