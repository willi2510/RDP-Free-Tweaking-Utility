@echo off
:: Version #
title RDP Tweaks Free Tweaking Utility
Set Version=1.0

:: Enable Delayed Expansion
setlocal enabledelayedexpansion

:: Set Powershell Execution Policy to Unrestricted
powershell "Set-ExecutionPolicy Unrestricted"

:: Enable ANSI Escape Sequences
reg add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f >> APB_Log.txt

set z=[7m
set i=[1m
set q=[0m
echo %z%Do you want to Create a Restore Point?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto RestorePoint
if '%choice%'=='2' goto Continue

:RestorePoint
:: Creating Restore Point
echo Creating Restore Point
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> APB_Log.txt
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Ancels Performance Batch' -RestorePointType 'MODIFY_SETTINGS'" >> APB_Log.txt

:Continue
cls

:: Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >> APB_Log.txt

echo Checking for Administrative Privileges...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Main Menu
:Menu
cls
chcp 65001 >nul 2>&1
call :Logo
REM for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
echo.
echo		            		              					 		%w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Windows%t%                 %w%[%y% %c%%u%2%q% %t%%w%]%y% %c%Power%t%
echo. 
echo.
echo 		                        			    		 		%w%[%y% %c%%u%3%q%%t% %w%]%y% %c%Network%t%                 %w%[%y% %c%%u%4%q% %t%%w%]%y% %c%Clean%t%
echo.
echo.
echo						                        		 		%w%[%y% %c%%u%5%q%%t% %w%]%y% %c%Debloat%t%                 %w%[%y% %c%%u%6%q%%t% %w%]%y% %c%RDP Tweaks Socials%t%
echo[
echo[
echo %w%Enter Your Choice Here:%t% 
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto WindowsTweaks
if '%choice%'=='2' goto PowerTweaks
if '%choice%'=='3' goto NetworkTweaks
if '%choice%'=='4' goto CleanTweaks
if '%choice%'=='5' goto DebloatTweaks
if '%choice%'=='6' goto RDPSocials

goto DefaultChoice


:WindowsTweaks
cls
call :Logo
echo.
echo		            		       				     %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Windows Basic%t%                 %w%[%y% %c%%u%2%q% %t%%w%]%y% %c%Windows Advanced%t%                  %w%[%y% %c%%u%3%q% %t%%w%]%y% %c%Home%t%
echo %w%Enter Your Choice Here:%t% 
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto WindowsBasic
if '%choice%'=='2' goto PremiumOnly
if '%choice%'=='3' goto Menu

goto DefaultChoice

:WindowsBasic
cls





pause
exit

:PowerTweaks
echo Power Tweaks
pause
exit

:NetworkTweaks
echo Network Tweaks
pause
exit

:CleanTweaks
echo Clean Tweaks
pause
exit

:DebloatTweaks
echo Debloat Tweaks
pause
exit

:RDPSocials
cls
Echo %w%Check Out RDP's Socials:%t% 
Echo[
REM Echo %w%To learn more, please press%t%
Echo %w%[1] Discord%t%
Echo %w%[2] Youtube%t% 
Echo %w%[3] Website%t% 
Echo %w%[4] Go Back Home%t% 
Echo[
echo %w%Enter Your Choice Here:%t% 
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' start https://discord.gg/v9cr6M6eDt && exit
if '%choice%'=='2' start https://www.youtube.com/@rdptweaker && exit
if '%choice%'=='3' start https://rdptweaks.com/ && exit
if '%choice%'=='4' goto Menu

goto DefaultChoice




:PremiumOnly
cls
Echo %w%This Feature is only available in the Premium Version of the Application.%t% 
Echo[
Echo %w%To learn more, please press%t%
Echo %w%[1] to visit RDP's website%t%
Echo %w%[2] to be redirected back to the home screen.%t% 
Echo[
echo %w%Enter Your Choice Here:%t% 
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' start https://rdptweaks.com/ && exit
if '%choice%'=='2' goto Menu

goto DefaultChoice

:DefaultChoice
set t=[0m
set w=[97m
cls
echo %w% Error In Input, Redirecting to Main Menu... %t% 
timeout /t 3 /nobreak >NUL
goto Menu

:Logo
set c=[31m
set t=[0m
set w=[97m
set y=[0m
set u=[4m
set q=[0m
echo[
echo[ 
echo 			%w%██████%t%╗ %w%██████%t%╗ %w%██████%t%╗     %w%███████%t%╗%w%██████%t%╗ %w%███████%t%╗%w%███████%t%╗    %w%████████%t%╗%w%██╗    ██%t%╗%w%███████%t%╗ %w%█████%t%╗ %w%██╗  ██%t%╗%w%██%t%╗%w%███╗   ██%t%╗ %w%██████%t%╗     %w%██╗   ██%t%╗%w%████████%t%%t%╗%w%██%t%╗%w%██%t%╗     %w%██%t%╗%w%████████%t%╗%w%██╗   ██╗
echo 			%w%██╔══██%t%╗%w%██╔══██%t%╗%w%██╔══██%t%╗    %w%██%t%╔════╝%w%██╔══██%t%╗%w%██%t%╔════╝%w%██%t%╔════╝    ╚══%w%██%t%╔══╝%w%██║    ██%t%║%w%██%t%╔════╝%w%██╔══██%t%╗%w%██║ ██%t%╔╝%w%██%t%║%w%████╗  ██%t%║%w%██%t%╔════╝     %w%██║   ██%t%║╚══%w%██%t%╔══╝%w%██%t%║%w%██%t%║     %w%██%t%║╚══%w%██%t%╔══╝╚%w%██╗ ██╔╝
echo 			%w%██████%t%╔╝%w%██║  ██%t%║%w%██████%t%╔╝    %w%█████%t%╗  %w%██████%t%╔╝%w%█████%t%╗  %w%█████%t%╗         %w%██%t%║   %w%██║ █╗ ██%t%║%w%█████%t%╗  %w%███████%t%║%w%█████%t%╔╝ %w%██%t%║%w%██╔██╗ ██%t%║%w%██║  ███%t%╗    %w%██║   ██%t%║   %w%██%t%║   %w%██%t%║%w%██%t%║     %w%██%t%║   %w%██%t%║    ╚%w%████╔╝ 
echo 			%w%██╔══██%t%╗%w%██║  ██%t%║%w%██%t%╔═══╝     %w%██%t%╔══╝  %w%██╔══██%t%╗%w%██%t%╔══╝  %w%██%t%╔══╝         %w%██%t%║   %w%██║███╗██%t%║%w%██%t%╔══╝  %w%██╔══██%t%║%w%██╔═██%t%╗ %w%██%t%║%w%██║╚██╗██%t%║%w%██║   ██%t%║    %w%██║   ██%t%║   %w%██%t%║   %w%██%t%║%w%██%t%║     %w%██%t%║   %w%██%t%║     ╚%w%██╔╝  
echo 			%w%██║  ██%t%║%w%██████%t%╔╝%w%██%t%║         %w%██%t%║     %w%██║  ██%t%║%w%███████%t%╗%w%███████%t%╗       %w%██%t%║   ╚%w%███╔███%t%╔╝%w%███████%t%╗%w%██║  ██%t%║%w%██║  ██%t%╗%w%██%t%║%w%██║ ╚████%t%║╚%w%██████%t%╔╝    ╚%w%██████%t%╔╝   %w%██%t%║   %w%██%t%║%w%███████%t%╗%w%██%t%║   %w%██%t%║      %w%██║   
echo 			╚═╝  ╚═╝╚═%t%════╝ ╚═╝         ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝      ╚═════╝    ╚═╝   ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝                                                                                                                                                                                                                                                                                                                                           
echo[																											         		      %w%Version: %Version%%t%
echo[