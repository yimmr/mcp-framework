@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"

set MSG=%~1
if "%MSG%"=="" set MSG=chore: release mcp-server-core update

echo ========================================================
echo   [MCP Server Core] 正在发布更新到 GitHub...
echo ========================================================

:: 安全检查：确保 .env 不会被误提交
git status

git add .gitignore pyproject.toml uv.lock README.md CHANGELOG.md SECURITY.md LICENSE release.bat publish.bat
git add mcp_server_core/ tests/
git commit -m "%MSG%"
git push origin main --tags

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] mcp-server-core 已成功发布更新到 GitHub!
    echo 使用端项目更新依赖只需运行: uv lock --upgrade-package mcp-server-core
) else (
    echo.
    echo [ERROR] 推送失败，请检查网络连接或 Git 权限。
)
echo.
pause
