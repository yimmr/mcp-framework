@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PyPI One-Click Publisher (mcp-server-core)
echo ========================================================

REM 1. Check if uv is installed
where uv >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] 'uv' command not found. Please ensure uv is in your PATH.
    pause
    exit /b 1
)

REM 2. Read token from .env if present
set "PYPI_TOKEN="
if exist "%~dp0.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0.env") do (
        if "%%A"=="UV_PUBLISH_TOKEN" set "PYPI_TOKEN=%%B"
        if "%%A"=="PYPI_TOKEN" set "PYPI_TOKEN=%%B"
    )
)

if "%PYPI_TOKEN%"=="" (
    if not "%UV_PUBLISH_TOKEN%"=="" (
        set "PYPI_TOKEN=%UV_PUBLISH_TOKEN%"
    )
)

if "%PYPI_TOKEN%"=="" (
    echo [ERROR] PyPI token not found!
    echo Please set UV_PUBLISH_TOKEN in %~dp0.env or as an environment variable.
    pause
    exit /b 1
)

REM 3. Clean old dist and build artifacts
if exist "%~dp0dist" (
    echo [INFO] Cleaning old dist folder...
    rmdir /s /q "%~dp0dist"
)
if exist "%~dp0build" (
    echo [INFO] Cleaning old build folder...
    rmdir /s /q "%~dp0build"
)
if exist "%~dp0mcp_server_core.egg-info" (
    echo [INFO] Cleaning old egg-info folder...
    rmdir /s /q "%~dp0mcp_server_core.egg-info"
)

REM 4. Pre-flight test suite
echo [INFO] Running pre-flight pytest checks...
cd /d "%~dp0"
uv run pytest
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Test suite failed! Publish aborted.
    pause
    exit /b 1
)

REM 5. Build distribution
echo [INFO] Building distributions with uv build...
uv build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] uv build failed!
    pause
    exit /b 1
)

REM 6. Publish to PyPI
echo [INFO] Publishing to PyPI...
uv publish --token "%PYPI_TOKEN%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] uv publish failed!
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   Successfully published to PyPI!
echo ========================================================
pause
