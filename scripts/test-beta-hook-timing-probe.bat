@echo off
setlocal

set "ROOT=%~dp0.."
set "CXX=%~1"
if not defined CXX set "CXX=c++"
set "WORK=%ROOT%\build\beta-hook-timing-probe-test.%RANDOM%"
set "EXE=%WORK%\beta-hook-timing-probe-test.exe"

mkdir "%WORK%" || exit /b 1
"%CXX%" -std=c++17 -O2 -Wall -Wextra -Werror ^
  -DBETA_HOOK_TIMING_HOST_TEST ^
  -I"%ROOT%\app\src\main\cpp" ^
  "%ROOT%\app\src\main\cpp\beta_hook_timing_probe.cpp" ^
  "%ROOT%\app\src\test\cpp\beta_hook_timing_probe_test.cpp" ^
  -o "%EXE%"
if errorlevel 1 goto failure

"%EXE%"
if errorlevel 1 goto failure

del "%EXE%"
rmdir "%WORK%"
exit /b 0

:failure
if exist "%EXE%" del "%EXE%"
if exist "%WORK%" rmdir "%WORK%"
exit /b 1
