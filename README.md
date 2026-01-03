# Dark-Tools
My private collection of usefull Powershell functions


## Installation
```powershell 7
Install-Module Dark-Tools
```

## Update
```powershell 7
Update-Module Dark-Tools
```

## Functions

- **ConvertFrom-CanonicalUser** - Converts canonical user names to Distinguished Name (DN) format for Active Directory queries.
```powershell
ConvertFrom-CanonicalUser -CanonicalName "contoso.com/Users/John Doe"
CN=John Doe,OU=Users,DC=contoso,DC=com
```

- **ConvertFrom-DistinguishedName** - Converts LDAP Distinguished Names (DN) to canonical name format.
```powershell
ConvertFrom-DistinguishedName -DistinguishedName "CN=John Doe,OU=Users,DC=contoso,DC=com"
contoso.com/Users/John Doe
```

- **Format-MacAddress** - Cleans and formats MAC address strings with customizable separators, case conversion, and split patterns.
```powershell
Format-MacAddress -MacAddress "00:1A:2B:3C:4D:5E" -Separator "-" -Uppercase
00-1A-2B-3C-4D-5E
```

- **Convert-SecondsToHumanReadable** - Converts seconds to human-readable time format (days, hours, minutes, seconds).
```powershell
Convert-SecondsToHumanReadable -Seconds 93784
1 days, 2 hours, 3 minutes, 4 seconds
```

- **Get-ComputerAdGroups** - Retrieves Active Directory group memberships for the current computer.
```powershell
Get-ComputerAdGroups
CN=Office Staff,CN=Users,DC=contoso,DC=com
CN=IT Support,OU=Groups,DC=contoso,DC=com
```

- **Get-ExecutableArchitecture** - Determines whether an executable file is 16-bit, 32-bit, or 64-bit.
```powershell
Get-ExecutableArchitecture C:\windows\system32\calc.exe
64-bit
```

- **Get-FileViaExplorer** - Opens a file browser dialog for interactive file selection with optional filtering.
```powershell
$SelectedFile = Get-FileViaExplorer
```

- **Get-FolderSize** - Calculates the total size of a folder in megabytes with recursive and filtering options.
```powershell
Get-FolderSize -folder "C:\Windows\" -recurse
C:\Windows\: 24.479,0 MB
```

- **Get-GithubData** - Retrieves release information from GitHub repositories and optionally downloads assets.
```powershell
Get-GithubData -User Microsoft -Repo PowerToys -SkipPreview -LatestVersion
v0.96.1
```

- **Get-IconLnkTarget** - Retrieves the target path of Windows shortcut (.lnk) files.
```powershell
 Get-IconLnkTarget -lnk "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\LibreOffice\LibreOffice Calc.lnk"
C:\Program Files\LibreOffice\program\scalc.exe
```

- **Get-ImageInformation** - Retrieves image properties using Windows Image Acquisition (WIA) API.
```powershell
Get-ImageInformation -Filepath "C:\Windows\Wallpapers\super_resolution\computer_keyboard_higher_res.jpg" | Select-Object Height, Width, PixelDepth

Height Width PixelDepth
------ ----- ----------
  3375  6000         24
```

- **Get-LastUserLogon** - Retrieves the last logon time and details for a specific user from Security event log.
***Removed due to poor default retention time in Windows EventLog***

- **Get-ProcessOwner** - Retrieves the owner/user account of running processes by name.
```powershell
Get-ProcessOwner -ProcessName pwsh

ProcessName ProcessId Owner
----------- --------- -----
pwsh            44892 john
```
```powershell
Get-Process pwsh | Get-ProcessOwner

ProcessName ProcessId Owner
----------- --------- -----
pwsh             2672 dark
pwsh            13400 dark
```

- **Set-ScheduledTaskMSA** - Configures scheduled tasks to run under Managed Service Accounts (MSA).
```powershell
Set-ScheduledTaskMSA -TaskName "Cleanup" -TaskPath "\\" -MSAName admin_MSA$ -RunWithHighestPrivileges
```

- **Get-Software** - Retrieves installed software from Windows registry with filtering options.
```powershell
Get-Software "Microsoft Edge" | Select-Object DisplayName, DisplayVersion, UninstallString

DisplayName    DisplayVersion UninstallString
-----------    -------------- ---------------
Microsoft Edge 143.0.3650.96  "C:\Program Files (x86)\Microsoft\Edge\Application\143.0.3650.96\Installer\setup.exe" --uninstall --msedge --channel=stable --system-level --verbose-logging
```

- **Get-RegistryUninstallKey** - Searches for uninstall registry keys matching a search pattern.
```powershell
```

- **Get-UserAdGroups** - Retrieves Active Directory group memberships for the current logged-on user.
```powershell
Get-UserAdGroups
Office Printer
RDP remote users
```

- **Get-Wanip** - Retrieves your public WAN IP address and related information.
```powershell
Get-WanIp
IPAddress   : 123.123.123.123
Location    : Some Location
Hostname    : some.hostname
ISP         : Your Provider
TorExit     : False
City        : Some City
Country     : Some Country
CountryCode : Some Country Cide
```

- **Import-Ods** - Imports ODS (LibreOffice Calc) files by converting them to XLSX and importing with Import-Excel.
```powershell
Import-Ods -FilePath "C:\Temp\calc-sheet.ods"
# Uses the Import-Excel module
# And therefor also Support all the parameters from Import-Excel
Import-Ods -FilePath "C:\Temp\calc-sheet.ods" -WorksheetName "Sheet1" -StartRow 2 -AsText
```

- **Import-TaskXml** - Imports scheduled tasks from XML definition files.
```powershell
Import-TaskXml -TaskXmlPath C:\temp\SomeTask.xml -TaskName "Wanted Taskname"
```

- **Install-Chocolatey** - Installs or detects Chocolatey package manager.
```powershell
Install-Chocolatey
# Same install method as the official method used on https://chocolatey.org
```

- **Install-Notion** - Installs Notion application using Winget silent to "C:\Program Files\Notion".
```powershell
Install-Notion
```

- **Invoke-CleanupHistory** - Cleans Windows Recent files and clipboard history.
```powershell
Invoke-CleanupHistory
```

- **Invoke-PauseWithTimeout** - Pauses script execution with timeout and keystroke detection.
```powershell
Invoke-PauseWithTimeout -message "Wait for 10 seconds" -SleepSeconds 10
Wait for 10 seconds
# Waits for 10 seconds or for a keystroke
```

- **ProcessingAnimation** - Displays an animated spinner while a script block executes
```powershell
ProcessingAnimation -scriptBlock {sleep -Seconds 3}
|
/
-
\
```

- **Search-FileContent** - Searches for specific content within files with filtering and recursion options.
```powershell
Search-FileContent -Path "C:\Windows\CCM\Logs" -Content "ERROR" -Recurse -ShowContent
```

- **Show-Calendar** - Displays a visual calendar with optional date highlighting.
```powershell
Show-Calendar -Start (Get-Date '2025-03-01') -End (Get-Date '2025-05-01')
```

- **Test-NetConnectionContinuous** - Continuously pings a URL with live statistics display.
```powershell
Test-NetConnectionContinuous -Url "google.com"
Ping statistics for google.com:
Recipient IP: 142.250.147.101
Pinging - 32ms
Started: 2026-01-03 17:02:26
Time since start: 4 seconds

Current ping: 32 ms
Highest ping: 32 ms
Lowest ping: 31 ms
Average ping: 31,80 ms
Packets sent: 5
Packets lost: 0
```

- **Test-Numeric** - Tests if a value is numeric.
```powershell
Test-Numeric -Value "123"
True
```

- **Test-PendingReboot** - Checks whether a Windows system requires a reboot.
```powershell
Test-PendingReboot

RebootRequired Reasons
-------------- -------
          True Component Based Servicing, Pending file rename operations
```

- **Test-SoftwareSources** - Checks for invalid software source paths in registry under HKLM:\SOFTWARE\Classes\Installer\Products.
```powershell
Test-SoftwareSources
Total products        : 81
Products with Net     : 81
Products with errors  : 0
```

- **Update-Notion** - Updates Notion application to the latest version.
```powershell
Update-Notion
```

- **Watch-FileChange** - Monitors a file for changes and alerts on modification.
```powershell
Watch-FileChange -Path "C:\system\main.log"
Monitoring file: C:\system\main.log
Press Ctrl+C to stop.

==========================================
 FILE CHANGED: 01/03/2026 17:16:21
==========================================

Press Enter to continue monitoring...:
```

- **Write-CheckFailed** - Writes a failure indicator (✗) to console.
```powershell
Write-CheckFailed -Text "Step in script"
Step in script ✗
```

- **Write-CheckSucces** - Writes a success indicator (✓) to console.
```powershell
Write-CheckSucces -Text "Step in script"
Step in script ✓
```

- **Write-Log** - Logs messages in SCCM-style format with component, timestamp, and severity level.
```powershell
Write-Log -Path "C:\Logs\install.log" -Message "Error occurred" -Component "Setup" -Type Error -OutputFormat Host
```

- **Write-ToLog** - Writes log entries in RN standard format.
```powershell
Write-ToLog -Message "Backup started" -Component "Backup" -LogFilePath "C:\Logs\backup.log"
```


