@echo off
echo ====================================================================
echo Packaging Cybersecurity Incident Management System (.WAR)
echo ====================================================================

set "JAVA_BIN=C:\Program Files\Java\jdk-25.0.2\bin"
if not exist "%JAVA_BIN%\jar.exe" (
    set "JAVA_BIN=jar"
)

call compile.bat

echo [1/3] Preparing WAR staging directory...
set "STAGE=target\staging"
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"

echo [2/3] Copying web application assets...
xcopy /E /I /Y src\main\webapp "%STAGE%"
mkdir "%STAGE%\WEB-INF\classes"
xcopy /E /I /Y target\classes "%STAGE%\WEB-INF\classes"
mkdir "%STAGE%\WEB-INF\lib"
xcopy /E /I /Y lib\mysql-connector-j-26.7.0.jar "%STAGE%\WEB-INF\lib"

echo [3/3] Generating CyberIncidentManagement.war...
cd "%STAGE%"
"%JAVA_BIN%\jar.exe" -cvf "..\CyberIncidentManagement.war" *
cd ..\..

echo.
echo ====================================================================
echo [SUCCESS] WAR Generated: target\CyberIncidentManagement.war
echo Ready to deploy to Apache Tomcat webapps/ folder!
echo ====================================================================
pause
