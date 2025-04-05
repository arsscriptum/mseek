@echo off
REM Change directory to the script's directory
pushd "%~dp0"

echo -------------------------------------------------
echo Running GenerateAppVersion.ps1...
echo -------------------------------------------------

REM Check for the "version_no_update" file and exit if it exists
if exist "%~dp0version_no_update" (
    echo "%~dp0version_no_update file found. Exiting without updating version."
    popd
    exit /b 0
)

REM Execute the PowerShell script
powershell.exe -noni -nop -f "%~dp0GenerateAppVersion.ps1"

REM Check if the script succeeded
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] GenerateAppVersion.ps1 failed with exit code %ERRORLEVEL%.
    popd
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] GenerateAppVersion.ps1 executed successfully.
)

popd
