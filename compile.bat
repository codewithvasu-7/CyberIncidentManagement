@echo off
echo ====================================================================
echo Compiling Cybersecurity Incident Management System (CIRMS)
echo ====================================================================

set "JAVA_BIN=C:\Program Files\Java\jdk-25.0.2\bin"
if not exist "%JAVA_BIN%\javac.exe" (
    set "JAVA_BIN=javac"
)

set "OUT_DIR=target\classes"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [1/2] Scanning Java source files...
dir /s /b src\main\java\*.java > sources.txt

echo [2/2] Compiling with javac...
"%JAVA_BIN%\javac.exe" -encoding UTF-8 -cp "lib\*" -d "%OUT_DIR%" @sources.txt

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ====================================================================
    echo [SUCCESS] Compilation complete! Output located at %OUT_DIR%
    echo ====================================================================
) else (
    echo.
    echo [ERROR] Compilation failed. Please check compiler errors above.
)

if exist sources.txt del sources.txt
pause
