@echo off
setlocal enabledelayedexpansion

:: Define the common username and password
set "username=username"
set "password=foo"

:: Prompt the user to enter a list of IP addresses (separated by new lines)
set "ip_list="
echo Enter IP addresses (separated by new lines, press Ctrl+Z then Enter to finish):
for /f "delims=" %%i in ('type con') do (
    set "ip=%%i"
    if "!ip!"=="" goto :process_ips
    set "ip_list=!ip_list!!ip! "
)
:process_ips

:: Iterate over each IP address and open an SSH session
for %%i in (!ip_list!) do (
    echo Opening SSH session for %%i...
    start C:\ProgramFilesX64\PuTTY\putty.exe -ssh !username!@%%i -pw !password!
)

echo All SSH sessions opened successfully.
exit /b
