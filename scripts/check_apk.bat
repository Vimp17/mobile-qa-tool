@echo off
chcp 65001 >nul
rem Перетащите APK на этот файл — запустится полная проверка и откроется отчёт.
if "%~1"=="" (
  echo Перетащите .apk на этот файл или запустите: check_apk.bat путь\к\app.apk
  pause
  exit /b 1
)
cd /d "%~dp0.."
qa check "%~1" --open --fail-on never
pause
