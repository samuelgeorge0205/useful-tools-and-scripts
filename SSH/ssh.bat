@echo off

set /p server="Enter hostname or IP : "

start C:\ProgramFilesX64\PuTTY\putty.exe -ssh Username@%server% -pw foo

REM start C:\ProgramFilesX64\PuTTY\putty.exe -ssh Username@%server% -pw foo
exit /b
