@echo off
setlocal enabledelayedexpansion

title IPsecGuard AI — Git Auto Sync

echo ============================================================
echo             IPsecGuard AI — Git Feature Sync                
echo ============================================================
echo.

cd /d "%~dp0"

:: 1. Check Git
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Git is not installed or not in PATH.
    pause
    exit /b 1
)

:: 2. Check Git status
echo [1/4] Checking repository status...
git status -s
echo.

:: 3. Determine commit message
set "COMMIT_MSG=%~1"

if "%COMMIT_MSG%"=="" (
    set /p "USER_INPUT=Enter commit message (press Enter for auto timestamp): "
    if "!USER_INPUT!"=="" (
        for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%I"
        if "!DT!"=="" (
            set "COMMIT_MSG=feat: auto sync IPsecGuard update"
        ) else (
            set "YEAR=!DT:~0,4!"
            set "MONTH=!DT:~4,2!"
            set "DAY=!DT:~6,2!"
            set "HOUR=!DT:~8,2!"
            set "MIN=!DT:~10,2!"
            set "COMMIT_MSG=feat: auto sync IPsecGuard update [!YEAR!-!MONTH!-!DAY! !HOUR!:!MIN!]"
        )
    ) else (
        set "COMMIT_MSG=!USER_INPUT!"
    )
)

echo.
echo [2/4] Staging all changed and new files...
git add -A
if %errorlevel% neq 0 (
    echo [ERROR] Git add failed.
    pause
    exit /b 1
)

echo [3/4] Committing with message: "%COMMIT_MSG%"...
git commit -m "%COMMIT_MSG%"
if %errorlevel% neq 0 (
    echo.
    echo [INFO] Nothing new to commit or commit failed.
)

echo.
echo [4/4] Pushing to remote repository...
git push origin HEAD
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Git push failed. Please check network connection or remote credentials.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo [SUCCESS] Repository successfully synced with remote!
echo ============================================================
timeout /t 3 >nul
