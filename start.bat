@echo off
REM ============================================
REM 校园网自动登录 — 开机自启动脚本
REM
REM 设置：Win+R → shell:startup → 创建快捷方式指向本文件
REM ============================================
cd /d "D:\Project\campus-network-login"
D:\Python\python.exe "D:\Project\campus-network-login\login.py" --loop
pause
