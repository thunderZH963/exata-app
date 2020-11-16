@echo off

set PATH=%PATH%;%SystemRoot%/System32

REM Find the processor type: 32 or 64 bit
set RegQuery=HKLM\Hardware\Description\System\CentralProcessor\0

REG.exe Query %RegQuery% > %TEMP%\ostype.txt

FIND /i "x86" < %TEMP%\ostype.txt > nul

if %ERRORLEVEL% == 0 (
set is32=1
) else (
set is32=0
)

REM Find the windows edition

ver | find "2003" > nul
if %ERRORLEVEL% == 0 goto ver_2003

ver | find "XP" > nul
if %ERRORLEVEL% == 0 goto ver_xp

ver | find "2000" > nul
if %ERRORLEVEL% == 0 goto ver_2000

ver | find "NT" > nul
if %ERRORLEVEL% == 0 goto ver_nt

if not exist %SystemRoot%\system32\systeminfo.exe goto warnthenexit

systeminfo | find "OS Name" > %Temp%\osname.txt

FOR /F "usebackq delims=: tokens=2" %%I in (%TEMP%\osname.txt) do set vers=%%I

echo %vers% | find "Windows 7" > nul
if %ERRORLEVEL% == 0 goto ver_7_8

echo %vers% | find "Windows 8" > nul
if %ERRORLEVEL% == 0 goto ver_7_8

echo %vers% | find "Windows Server 2008" > nul
if %ERRORLEVEL% == 0 goto ver_2008

echo %vers% | find "Windows Vista" > nul
if %ERRORLEVEL% == 0 goto ver_vista

echo %vers% | find "XP" > nul
if %ERRORLEVEL% == 0 goto ver_xp

goto warnthenexit

:ver_7_8
if %is32% == 1 (
echo Installing 32 bit version of EXata Virtual Adapter for Windows 7
"%~dp0\devcon.exe" install "%~dp0\win7_win8\i386\enetv.inf" "root\enetv"
) else (
echo Installing 64 bit version of EXata Virtual Adapter for Windows 7
"%~dp0\devcon_amd64.exe" install "%~dp0\win7_win8\amd64\enetv.inf" "root\enetv"
)
goto done

:ver_2008
echo Windows Server 2008 platform is not supported
goto done

:ver_vista
if %is32% == 1 (
echo Installing 32 bit version of EXata Virtual Adapter for Windows Vista
"%~dp0\devcon.exe" install "%~dp0\vista\i386\enetv.inf" "root\enetv"
) else (
echo Installing 64 bit version of EXata Virtual Adapter for Windows Vista
"%~dp0\devcon_amd64.exe" install "%~dp0\vista\amd64\enetv.inf" "root\enetv"
)
goto done

:ver_xp
if %is32% == 1 (
echo Installing 32 bit version of EXata Virtual Adapter for Windows XP
"%~dp0\devcon.exe" install "%~dp0\xp\i386\enetv.inf" "root\enetv"
) else (
echo Installing 64 bit version of EXata Virtual Adapter for Windows XP
"%~dp0\devcon_amd64.exe" install "%~dp0\xp\amd64\enetv.inf" "root\enetv"
)
goto done

:ver 2000
echo echo Windows 2000 platform is not supported
goto done

:ver_nt
echo echo Windows NT platform is not supported
goto done


:warnthenexit
echo Cannot determine windows OS

:done
