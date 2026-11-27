@echo off
findstr /C:"rutracker.org" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # Direct DNS Poisoning Protection >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.32.39 rutracker.org >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.org >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.tv >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.top >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.me >> "%WINDIR%\System32\drivers\etc\hosts"
)

findstr /C:"cdn.battleye.com" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # BattlEye Anti-Cheat Global CDN >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 185.229.190.148 cdn.battleye.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 185.229.190.148 battleye.becdn.net >> "%WINDIR%\System32\drivers\etc\hosts"
)

ipconfig /flushdns >nul
