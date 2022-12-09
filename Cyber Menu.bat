@echo off
shift /0
title Cyber Patriot
cd %systemroot%\system32
call :IsAdmin
SETLOCAL EnableDelayedExpansion

:MENU
cls
title Cyber Patriot
echo Welcome to CyberPatriot
echo.
echo Choose An Option:
echo 1. Windows Updates
echo 2. Windows FireWall
echo 3. Password Policies
echo 4. Remote Desktop
echo 5. System Integrity Scan
echo 6. Remove Tracking
echo 7. Windows Defender
echo 8. Guest Accounts
echo 9. Network Sharing
echo 0. Bitlocker Drive Encryption

set /p MCPOPTN="Please select an option:"
	if "%MCPOPTN%"=="1" (
	goto WNDWSPDTS
    ) else (
	if "%MCPOPTN%"=="2" (
	goto WNDWSFRWL
	) else (
	if "%MCPOPTN%"=="3" (
	goto PSWDPLC
	) else (
	if "%MCPOPTN%"=="4" (
	goto RMTDSKTP
	) else (
   	if "%MCPOPTN%"=="5" (
	goto SYSINTSCAN
   	) else (
   	if "%MCPOPTN%"=="6" (
	goto RMVTRKNG
   	) else (
	if "%MCPOPTN%"=="7" (
	goto WINDFNDR
	) else (
	if "%MCPOPTN%"=="8" (
	goto GSTACNT
	) else  (
	if "%MCPOPTN%"=="9" (
	goto NTWKSHRNG
	) else (
	if "%MCPOPTN%"=="0" (
	goto DRVENCYPTN
	) else (       
 	goto wrongChoice
	)
	)
	)
	)
	)
	)
	)
    )
    )
    )

:WNDWSPDTS
title Cyber Patriot - Windows Updates
cls
echo 1. Disable Windows Updates
echo 2. Enable Windows Updates
echo 3. Cancel

set /p WINUPDTSOPTN="Please select an option:"
	if "%WINUPDTSOPTN%"=="1" (
	goto DSBLWNDWSPDTS
    ) else (
	if "%WINUPDTSOPTN%"=="2" (
	goto ENBLWNDWSPDTS
	) else (
	if "%WINUPDTSOPTN%"=="3" (
	goto Menu
	) else (
	goto WRNGUPDTSCHCE
	)
	)
	)
	)


:ENBLWNDWSPDTS
cls
net stop wuauserv >nul
net stop WaaSMedicSVC >nul
net stop UsoSvc >nul
sc config wuauserv start= automatic >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul
sc config WaaSMedicSvc start= automatic >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "3" /f >nul
sc config UsoSV start= automatic >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSV" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f >nul

gpupdate /force >nul
Cls & Echo Windows Updates Successfully Enabled...
Timeout /t 3 -NOBREAK >nul & goto MENU

:DSBLWNDWSPDTS
cls
net stop wuauserv>nul
net stop WaaSMedicSVC>nul
net stop UsoSvc>nul
sc config wuauserv start= disabled>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" >nul
sc config WaaSMedicSvc start= disabled>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" >nul
sc config UsoSvc start= disabled>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4">nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul
gpupdate /force >nul
Cls & Echo Windows Updates Successfully Disabled...
Timeout /t 3 -NOBREAK >nul & goto MENU

:WRNGUPDTSCHCE
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK > nul & goto WNDWSPDTS

:WNDWSFRWL
cls
echo 1. Disable Windows Firewall
echo 2. Enable Windows Firewall
echo 3. Windows Firewall Status
echo 4. Cancel
set /p WNDWSFRWLMENU="Please select an option:"
	if "%WNDWSFRWLMENU%"=="1" (
	goto WNDWSFRWLDISABLE
    ) else (
	if "%WNDWSFRWLMENU%"=="2" (
	goto WNDWSFRWLENABLE
	) else (
	if "%WNDWSFRWLMENU%"=="3" (
	goto WNDWSFRWLSTATUS
	) else (
	if "%WNDWSFRWLMENU%"=="4" (
	goto menu
	) else (
	goto WNDWSFRWLWC
	)
	)
	)
	)
	)
	)

:WNDWSFRWLDISABLE
cls
echo Disabling Firewall...
netsh advfirewall set allprofiles state off >nul
cls
echo Windows Firewall Has Been Successfully Disabled...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WNDWSFRWLENABLE
cls
echo Enabling Firewall And Setting Basic Rules...
netsh advfirewall set allprofiles state on >nul
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >nul
netsh advfirewall firewall set rule name="Telnet Server" new enable=no >nul
netsh advfirewall firewall set rule name="netcat" new enable=no >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 00000001 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d 00000000 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 00000001 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 00000000 /f >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mpssvc" /v "Start" /t REG_DWORD /d 2 /f >nul
cls
echo Windows Firewall Has Been Successfully Enabled...
echo Basic Rules For Windows Firewall Have Been Set...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WNDWSFRWLSTATUS
cls
netsh advfirewall show allprofiles 
echo Firewall Status has been shown...
Timeout /t 7 -NOBREAK > nul & goto MENU
goto menu

:WNDWSFRWLWC
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto WNDWSFRWL

:PSWDPLC
cls
title Cyber Patriot - Password Policies
echo Setting Password Policies...
net accounts /lockoutthreshold:5 /MINPWLEN:10 /MAXPWAGE:30 /MINPWAGE:5 /UNIQUEPW:5 >nul
Timeout /t 2 -NOBREAK >nul
echo Password Policies Have Successfully Been Set
echo Displaying New Password Policies...
net accounts
Timeout /t 7 -NOBREAK >nul & goto MENU

:RMTDSKTP
cls
title Cyber Patriot - Remote Desktop
echo 1. Disable Remote Desktop
echo 2. Enable Remote Desktop
echo 3. Cancel

set /p :RMTDSKTPOPTN="Please select an option:"
	if "%RMTDSKTPOPTN%"=="1" (
	goto DSBLRMTDSKTP
    ) else (
	if "%RMTDSKTPOPTN%"=="2" (
	goto ENBLRMTDSKTP
	) else (
	if "%RMTDSKTPOPTN%"=="3" (
	goto Menu
	) else (
	goto WRNGRMTDSKTPCHCE
	)
	)
	)
	)

:DSBLRMTDSKTP
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f >nul
echo Remote Desktop Has Successfully Been Disabled...
Timeout /t 3 -NOBREAK > nul & goto MENU

:ENBLRMTDSKTP
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f >nul
echo Remote Desktop Has Successfully Been Enabled...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WRNGRMTDSKTPCHCE
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto RMTDSKTP

:SYSINTSCAN
cls
echo System Integrity Scan Starting Now...
sfc /SCANNOW
Timeout /t 7 -NOBREAK >nul & goto MENU

:RMVTRKNG
title Cyber Patriot - Remove Tracking
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul
Reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f >nul
Reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f >nul
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable >nul
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >nul
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >nul
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable >nul
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable >nul
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >nul
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable >nul
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable >nul
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable >nul
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable >nul
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" >nul
cls
echo Successfully Disabled Windows Tracking And Spyware...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WINDFNDR
title Cyber Patriot - Windows Defender
cls
echo 1. Disable Windows Defender
echo 2. Enable Windows Defender
echo 3. Cancel

set /p WINDFNDRSOPTN="Please select an option:"
	if "%WINDFNDRSOPTN%"=="1" (
	goto DSBLWNDWSDFNDR
    ) else (
	if "%WINDFNDRSOPTN%"=="2" (
	goto ENBLWNDWSDFNDR
	) else (
	if "%WINDFNDRSOPTN%"=="3" (
	goto Menu
	) else (
	goto WRNGWINDFNDRSCHCE
	)
	)
	)
	)

:DSBLWNDWSDFNDR
title Cyber Patriot - Disabling Windows Defender
cls
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
cls
echo Successfully Disabled Windows Defender...
Timeout /t 3 -NOBREAK > nul & goto MENU




:ENBLWNDWSDFNDR
title Cyber Patriot - Enabling Windows Defender
cls
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "WindowsDefender" /t REG_BINARY /d "060000000000000000000000" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /t REG_EXPAND_SZ /d "\"%%ProgramFiles%%\Windows Defender\MSASCuiL.exe\"" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f >nul
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f
cls
echo Successfully Enabled Windows Defender...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WRNGWINDFNDRSCHCE
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto WINDFNDR

:GSTACNT
title Cyber Patriot - Guest Accounts
cls
echo 1. Disabled Guest Accounts
echo 2. Enable Guest Accounts
echo 3. Cancel

set /p GSTACNTOPTN="Please select an option:"
	if "%GSTACNTOPTN%"=="1" (
	goto DSBLGSTACNT
    ) else (
	if "%GSTACNTOPTN%"=="2" (
	goto ENBLGSTACNT
	) else (
	if "%GSTACNTOPTN%"=="3" (
	goto Menu
	) else (
	goto WRNGGSTACNTCHCE
	)
	)
	)
	)

:DSBLGSTACNT
title Cyber Patriot - Disabling Guest Accounts
cls
net user guest /active:no
cls
echo Successfully Disabled Guest Accounts...
Timeout /t 3 -NOBREAK > nul & goto MENU

:ENBLGSTACNT
title Cyber Patriot - Enabling Guest Accounts
cls
net user guest /active:yes
cls
echo Successfully Enabled Guest Accounts...
Timeout /t 3 -NOBREAK > nul & goto MENU

:WRNGGSTACNTCHCE
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto GSTACNT

:NTWKSHRNG
title Cyber Patriot - Network Sharing
cls
echo 1. Disable Network Sharing
echo 2. Enable Network Sharing
echo 3. Cancel

set /p NTWKSHRNG="Please select an option:"
if "%NTWKSHRNG%"=="1" (
	goto DSBLNTWKSHRNG
    ) else (
	if "%NTWKSHRNG%"=="2" (
	goto ENBLNTWKSHRNG
	) else (
	if "%NTWKSHRNG%"=="3" (
	goto Menu
	) else (
	goto WRNGNTWSHRNGCHCE
	)
	)
	)
	)

:DSBLNTWKSHRNG
title Cyber Patriot - Disabling Network Sharing
cls
net share C$ /DELETE >nul
net stop lanmanserver >nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer" /v "Start" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >nul
cls
echo Successfully Disabled Network Sharing...
Timeout /t 3 -NOBREAK > nul & goto MENU

:ENBLNTWKSHRNG
title Cyber Patriot - Enabling Network Sharing
cls
net stop lanmanserver >nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer" /v "Start" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer" /v "Start" /t REG_DWORD /d "2" /f >nul
cls
echo Successfully Enabled Network Sharing... 
Timeout /t 3 -NOBREAK > nul & goto MENU

:WRNGNTWSHRNGCHCE
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto NTWKSHRNG



:DRVENCYPTN
cls
title Cyber Patriot - Bitlocker Drive Encryption
manage-bde -on C: -RecoveryKey D: -RecoveryPassword
Timeout /t 1 -NOBREAK >nul
manage -bde -status
Timeout /t 7 -NOBREAK >nul
echo.
echo Successfully Enabled Bitlocker...
Timeout /t 3 -NOBREAK > nul & goto MENU









:wrongChoice
cls
echo You have entered an incorrect option, Please try again...
Timeout /t 3 -NOBREAK >nul & goto MENU

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue...
 Timeout /t 3 -NOBREAK >nul & Exit
)
cls
goto MENU