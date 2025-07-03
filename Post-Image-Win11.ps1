# Housekeeping
set-Strictmode -Version Latest

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
    $arguments = "-NoExit -ExecutionPolicy Bypass & '" + $myinvocation.mycommand.definition + "'"
    Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
    break
}

$pshost = Get-Host
$pshost.UI.RawUI.WindowTitle = "Post-Image Script v2025.1"
$pshost.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# Variables
$image_ver = "23R2"
$apu_lab_layout_path = "Refer to TA OneDrive"
$log_path = "C:\postimage-log-$(Get-Date -Format "ddMMyy")-$image_ver.txt"

# $mount_path = "\\10.61.50.5\drivers"
# $driver_path = "Z:\PC Drivers\"
# $tools_path = "Z:\Post-Image\"
$processes = ([System.Management.Automation.PsParser]::Tokenize((Get-Content "$PSScriptRoot\$($MyInvocation.MyCommand.Name)"), [ref]$null) | 
    Where-Object { $_.Type -eq 'Command' -and $_.Content -eq 'Set-OuterProgress' }).Count
$username = $password = $creds = $pc_name = ""

# Unnecessary ASCII arts
$banner = @'
  _____         _           _           _      _            _     _              _       
 |_   _|__  ___| |__  _ __ (_) ___ __ _| |    / \   ___ ___(_)___| |_ __ _ _ __ | |_ ___ 
   | |/ _ \/ __| '_ \| '_ \| |/ __/ _` | |   / _ \ / __/ __| / __| __/ _` | '_ \| __/ __|
   | |  __/ (__| | | | | | | | (_| (_| | |  / ___ \\__ \__ \ \__ \ || (_| | | | | |_\__ \
   |_|\___|\___|_| |_|_| |_|_|\___\__,_|_| /_/   \_\___/___/_|___/\__\__,_|_| |_|\__|___/
  ____           _       ___                              ____            _       _   
 |  _ \ ___  ___| |_    |_ _|_ __ ___   __ _  __ _  ___  / ___|  ___ _ __(_)_ __ | |_ 
 | |_) / _ \/ __| __|____| || '_ ` _ \ / _` |/ _` |/ _ \ \___ \ / __| '__| | '_ \| __|
 |  __/ (_) \__ \ ||_____| || | | | | | (_| | (_| |  __/  ___) | (__| |  | | |_) | |_ 
 |_|   \___/|___/\__|   |___|_| |_| |_|\__,_|\__, |\___| |____/ \___|_|  |_| .__/ \__|
                                             |___/                         |_|        
'@

$wallpaper = @'                                                                                                                        
                                                         &@@*                                                           
                                                        @@@@@@                                                          
                         /@              @@@@@         %@@@@@@(            @@@@@&         @@@@                          
                       @@@@@@           @@@@@@@          @@@@@             @@@@@@        @@@@@@                         
                      @@@@@@@@         @@@@@@@         @&  @  @@          #@@@@@#       @@@@@@@@                        
                      @@@@@@@#         @@@@@@@.   %@@@@@@  @   @@@@@        @@@@        @@@@@@@@                        
                      @@@@@@@      @@@@@@@@@@@@@@ @@@@@@@@(@@   @@@@      @@@@@@@@@@*(@@@@@@@@@@                        
                   @@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@#  @@@@@@@@@@@@@@@@@@@@@@@@@@@&                     
                  @@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@* @@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     
                @@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
              @@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@                    
                  @@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@   @@@@@@@@@@@@@@@                   
                  @@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@   @@@@@@@@@@@@@*                   
                    @@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@  @@@@@@@@@@@@@@                    
                    @@@@@@@@@@@@     @@@@@@@@@@@@@  @@@@@@@@@@@@@@@@    @@@@@@@@@@@@.(@@@@@@@@@@@@@%                    
                    @@@@@@@@@@@.      @@@@@@@@@@@@   @@@@@@@@@@@@@@@    @@@@@@@@@@@  @@@@@@@@@@@@@@                     
                    @@@@@@@@@@@        @@@@@@@@@@(   @@@@@@@%@@@@@@@    @@@@@@@@@@@  @@@@@@@@@@@@@@                     
                     @@@@@@@@@@         *@@@@@@@@     @@@@@@ @@@@@@@    @@@@@@@@@@@   @@@@@@@@@@@@@                     
                      @@@@@@@@@          /@@@@@@@     @@@@@   @@@@@@    @@@@@@@@@@    @@@@@@@@@@@@@                     
                      %@@@@@@@@           @@@@@@@     @@@@@   @@@@@@    .@@@@@@@@@     @@@@/ @@@@@@                     
                        @@@@@@@@         /@@@@@       @@@@@    @@@@     *@@@@@@@@@     @@@@  @@@@@#                     
                        @@@@@@@@         @@@@@@       /@@@@    @@@@      @@@@@@@@@.    @@@@@ @@@@@                      
                        %@@@@@@@         @@@@@         @@@@    @@@@      @@@@@@@@@.    @@@@@ @@@@@                      
                         @@@@@@@,        @@@@@         @@@@    @@@@       @@@@@@@@/    @@@@@@@@@@                       
                         @@@@@@@,        @@@@@@        @@@@   @@@@        &@@@@@@@@    @@@@@@@@@&                       
                         @@@@@@@         @@@@@@@@       @@@    @@@@@     .@@@@@@@@@    @@@@@@@@@                        
                        @@@ @@@,         @@@@&         @@@@       @@        @@@@,    ,@@@@@@@@@%                      
                          @@.               @@                              @@        ,@@     /@                     
                        _____       _         _         _     _          _    _            _      
                       |_   _|__ __| |_  _ _ (_)__ __ _| |   /_\   _____(_)__| |_ __ _ _ _| |_ ___
                         | |/ -_) _| ' \| ' \| / _/ _` | |  / _ \ (_-<_-< (_-<  _/ _` | ' \  _(_-<
                         |_|\___\__|_||_|_||_|_\__\__,_|_| /_/ \_\/__/__/_/__/\__\__,_|_||_\__/__/



'@

# Usage   : Write-Status message_content status_type
# Options : status_type   1     - Red
#                         2     - Yellow
#                         3     - Green
#                         4     - Blue
#                         5     - Gray
function Write-Status($msg, $status) {
    switch ($status) {
        1 { $fontColor = 'Red' }
        2 { $fontColor = 'Yellow' }
        3 { $fontColor = 'Green' }
        4 { $fontColor = 'Blue' }
        5 { $fontColor = 'Gray' }
        Default { $fontColor = 'White' }
    } 
    $host.UI.RawUI.ForegroundColor = $fontColor
    Write-Host "$msg"
    $host.UI.RawUI.ForegroundColor = "White"
}

# Usage   : Write-Log log_content status_type
# Options : status_type   1     - Infomational
#                         2     - Warning
#                         3     - Error
#                         4     - Fatal
function Write-Log($message, $status) {
    switch ($status) {
        1 {
            $status = "[ INFO  ]"
            $fontColor = 'DarkGray'
        }
        2 {
            $status = "[WARNING]" 
            $fontColor = 'Yellow'
        }
        3 {
            $status = "[ ERROR ]" 
            $fontColor = 'Red'
        }
        4 {
            $status = "[ FATAL ]" 
            $fontColor = 'Magenta'
        }
    }
    $log_content = "$(Get-Date -Format "dd/MM/yyyy hh:mm:ss") $status  $message"
    Out-File -FilePath $log_path -InputObject $log_content -Encoding ascii -Append
    Write-Host $message -ForegroundColor $fontColor
}

function Set-OuterProgress ($activity, $subroutine, $count) {
    $progress = [Math]::Round($count / $processes * 100)
    $OuterLoopProgressParameters = @{
        Activity         = $activity
        Status           = "$progress% Complete:"
        PercentComplete  = $progress
        CurrentOperation = $subroutine
    }
    Write-Progress @OuterLoopProgressParameters
}

function Set-InnerProgress ($activity, $subroutine, $i, $j, $completed) {
    $progress = [Math]::Round($i / $j * 100)
    if ($progress -gt 100) {
        $progress = 100
    }
    $InnerLoopProgressParameters = @{
        ID               = 1
        Activity         = $activity
        Status           = "$progress% Complete:"
        PercentComplete  = $progress
        CurrentOperation = $subroutine
    }
    if ($completed -eq 1) {
        Write-Progress @InnerLoopProgressParameters -Completed
    }
    else {
        Write-Progress @InnerLoopProgressParameters
    }
    
}

function Get-Creds {
    while ($username.Length -eq 0) {
        Write-Host " Enter credential for domain joining (Example: wei.lun)."
        $username = Read-Host -Prompt " Username"
        if ($username -NotLike '*@*') {
            $dom_username = "$username@techlab"
        }
        else {
            $dom_username = $username
        }
    }
	
    while ($password.Length -eq 0) {
        $password = Read-Host -Prompt " Password" -AsSecureString
    }

    $script:creds = New-Object System.Management.Automation.PSCredential ($dom_username, $password)
    
    # Try {
    #     New-PSDrive -Name "Z" -PSProvider FileSystem -Root $mount_path -Credential $creds -Scope script -Persist -ErrorAction Stop
    #     while (!(Test-Path Z:\)) { Start-Sleep 1 }
    #     $script:username = $username
    #     return $true
    # }
    # catch {
    #     Write-Log "Domain account $username is used and fail to authenticate." 3
    #     $username = ""
    #     return $false
    # }
}

<# function Write-To-Csv ($a, $b, $c, $d, $e, $f, $g, $h, $i) {
	$time = $(Get-Date -Format "dd/MM/yyyy hh:mm:ss")
    $csvfile = Import-Csv "Z:\Post-Image\Reimage.csv"
    $csvfile.time = $time
    $csvfile.pc_name = $a
    $csvfile.ta_name = $b
    $csvfile.pc_model = $c
    $csvfile.cpu = $d
    $csvfile.ram = $e
    $csvfile.gpu = $f
    $csvfile.ip_addr = $g
    $csvfile.service_tag = $h
    $csvfile.disk_serial = $i
    $csvfile | Export-CSV "Z:\Post-Image\Reimage.csv" -Append
} #>

function Set-Services ($service, $action) {
    if ($action -eq 0) {
        Stop-Service $service -Force
        Set-Service -StartupType Disable $service
    }
    elseif ($action -eq 1) {
        Set-Service -StartupType Automatic $service
        Start-Service $service
    }
    else {
        Stop-Service $service -Force
        Set-Service -StartupType manual $service
    }
}

# function Install-Drivers ($model, $path) {
#     robocopy.exe $path C:\Drivers /MIR > null
#     $drivers = Get-ChildItem -Path C:\Drivers -Recurse -filter "*.inf"
#     $i = 0
#     $j = $drivers | Measure-Object -Property Directory | Select-Object -Expand Count
#     $drivers | ForEach-Object { 
#         $driver = $_.Name
#         Set-InnerProgress "Installing drivers for $model" $driver $i $j 0
#         Write-Log "Attempted to install $driver." 1 
#         try {
#             PNPUtil.exe /add-driver $_.FullName /install > null
#             Write-Log "Installed $driver." 1 
#         }
#         catch {
#             Write-Log "Fail to install $driver." 3 
#         }
#         $i++
#     } 
#     Set-InnerProgress "Drivers for $model are installed." "Complete" 1 1 1
#     Remove-Item C:\Drivers -Recurse -Force > null
#     Start-Sleep 3
# }

function Install-DeepFreeze ($lab) {
    $installer = [regex]::match($lab.ToUpper(), 'TL\d{2}-\w{2,4}')
    robocopy.exe "$tools_path\DeepFreeze\" "C:\" "$installer.exe" > null
    Start-Process -FilePath "C:\$installer.exe" -WorkingDirectory "C:\" -ArgumentList "/DFNoReboot", "/Thaw" -Wait
    Remove-Item "C:\$installer.exe" -Force > null
}
<# Edited by Jin Ann #>
Function Install-Teams {
    $TeamsPath = [System.IO.Path]::Combine("C:\Users\localadmin\AppData\Local", 'Microsoft', 'Teams')
    $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')

    try {
        if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
            Write-Log "Uninstalling existing Teams application" 1
            $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
            $proc.WaitForExit()
        }
        If (Test-Path $TeamsPath) {
            Write-Log "Deleting Teams directory" 1
            Remove-Item -path $TeamsPath -Recurse -Force
        }

        $OfficeRegPath = "HKCU:\Software\Microsoft\Office"
        $OfficeTeamsRegKey = "Teams"
        $OfficeTeamsRegKeyExists = (Get-ItemProperty -Path $OfficeRegPath | Select-Object -ExpandProperty $OfficeTeamsRegKey -ErrorAction SilentlyContinue)

        If ($null -ne $OfficeTeamsRegKeyExists) {
            $TeamsRegPath = "$OfficeRegPath\$OfficeTeamsRegKey"
            $TeamsRegKey = "PreventInstallationFromMsi"
            $TeamsRegKeyExists = (Get-ItemProperty -Path $TeamsRegPath | Select-Object -ExpandProperty $TeamsRegKey -ErrorAction SilentlyContinue)
            If ((Test-Path $TeamsRegPath) -And ($null -ne $TeamsRegKeyExists)) {
                Write-Log "Removing Teams PreventInstallationFromMsi registry key-value" 1
                Remove-ItemProperty HKCU:\Software\Microsoft\Office\Teams -Name PreventInstallationFromMsi -Verbose -Force
            }
        }
        
        $TeamsMachineWideInstallerGUID = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"
        If (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$TeamsMachineWideInstallerGUID") {
            Write-Log "Uninstalling Teams Machine Wide Installer" 1
            Start-Process msiexec -ArgumentList "/x $TeamsMachineWideInstallerGUID /q" -Wait
        }

        $TeamsMsiPath = "C:\Users\localadmin\Downloads\Teams_windows_x64.msi"
        Copy-Item "\\10.61.50.5\SoftwareHub\MSOffice\Teams_windows_x64.msi" -Destination $TeamsMsiPath -Force
        Write-Log "Installing Teams Machine Wide installer for all users" 1
        Start-Process msiexec -ArgumentList "/i $TeamsMsiPath ALLUSERS=1 /q" -Wait

        Write-Log "Ensuring that the AutoStart is enabled" 1
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        $Name = 'TeamsMachineInstaller'
        $Value = ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

        # ref: https://superuser.com/questions/1413830/how-do-you-disable-startup-programs-that-only-exist-in-the-task-manager-startup
        # Create the key if it does not exist 
        If (-NOT (Test-Path $RegistryPath)) {
            New-Item -Path $RegistryPath -PropertyType Binary -Force | Out-Null
        }
        
        # Now set the value
        Set-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -Force 
    }
    catch {
        Write-Log "Uninstall failed with exception $_.exception.message" 3
    }
}

# Function Copy-AutomationStudio {
#     Write-Log "Copying Automation Studio config files" 1
#     $Destination = "C:\Users\Default\AppData\Roaming\Famic Technologies\Automation Studio E6.3"
#     $Source = "\\10.61.50.5\drivers\Post-Image\Famic Technologies\Automation Studio E6.3"
#     Copy-Item -Path $Source -Destination $Destination -Recurse -Force
#     Copy-Item -Path $Source -Destination "C:\Users\localadmin\AppData\Roaming\Famic Technologies\Automation Studio E6.3" -Recurse -Force
# }

Function Set-LockScreen {
    param (
        [Parameter(Mandatory = $true)][String]$wallpaperNameWithExtension
    )

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Write-Log "registryPath=$registryPath" 1

    $lockscreenPath = "C:\ProgramData\Wallpaper\lockscreen.jpg"
    Write-Log "lockscreenPath=$lockscreenPath" 1

    $sharedBasePath = "\\10.61.50.5\SoftwareHub\Scripts\Change Wallpaper"

    Write-Log "Checking whether $registryPath exists" 1
    If ((Test-Path $registryPath) -eq $false) {
        Write-Log "PATH NOT FOUND: $registryPath" 1
        New-Item -Path $registryPath -Force
        Write-Log "Created the registry key" 1
    }

    $LockScreenImageKeyExists = (Get-ItemProperty -Path $registryPath | Select-Object -ExpandProperty "LockScreenImage" -ErrorAction SilentlyContinue)
    
    Write-Log "Matching value from '$LockScreenImageKeyExists' with '$lockscreenPath'" 1
    If (($null -eq $LockScreenImageKeyExists) -or ($LockScreenImageKeyExists -ne $lockscreenPath)) {
        Write-Log "DOES NOT MATCH!" 1
        Set-ItemProperty -Path $registryPath -Name "LockScreenImage" -Value $lockscreenPath
        Write-Log "Set $registryPath\LockScreenImage to $lockscreenPath" 1
    }

    $ParentDirectory = [System.IO.Path]::GetDirectoryName($lockscreenPath)
    Write-Log "Checking whether $lockscreenPath parent directory exists" 1
    If ((Test-Path $ParentDirectory) -eq $false) {
        Write-Log "DIRECTORY NOT FOUND: $lockscreenPath" 1
        New-Item -Path ($ParentDirectory) -ItemType Directory -Force
        Write-Log "Created the directory" 1
    }

    try {
        Copy-Item -Path "$sharedBasePath\$wallpaperNameWithExtension" -Destination $lockscreenPath -Force
        Write-Log "Copied $wallpaperNameWithExtension to $lockscreenPath" 1
    }
    catch {
        Write-Log "Error copying $wallpaperNameWithExtension to ${lockscreenPath}: $_" 3
    }

}

Function Set-OneDriveGPO { 
    $OneDrivePath = "C:\Program Files\Microsoft OneDrive"
    $AdmxParentFolder = Get-ChildItem $OneDrivePath | Where-Object { ($_.Name -Match '\d+') -And $_.PSIsContainer }

    $AdmxSource = "$OneDrivePath\$AdmxParentFolder\adm\OneDrive.admx"
    $AdmlSource = "$OneDrivePath\$AdmxParentFolder\adm\OneDrive.adml"

    $AdmxDestination = "C:\Windows\PolicyDefinitions"
    $AdmlDestination = "$AdmxDestination\en-US"

    If (-Not (Test-Path $AdmxDestination)) {
        Copy-Item -Path $AdmxSource -Destination $AdmxDestination -Force
        Write-Log "Copied admx file to $AdmxDestination" 1
    }
    If (-Not (Test-Path $AdmlDestination)) {
        Copy-Item -Path $AdmlSource -Destination $AdmlDestination -Force
        Write-Log "Copied admx file to $AdmlDestination" 1
    }

    $GroupPolicyRegistry = @'
    Windows Registry Editor Version 5.00
    
    [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive]
    "KFMSilentOptIn"="0fed03a3-402d-4633-a8cd-8b308822253e"
    "KFMSilentOptInWithNotification"=dword:00000001
    "SilentAccountConfig"=dword:00000001
    "FilesOnDemandEnabled"=dword:00000001
    "GPOSetUpdateRing"=dword:00000000
'@
    Write-Log "Applying registry (equivalent to GPO)" 1
    $PathToRegFile = "C:\Windows\Temp\onedriveGpo.reg"
    Set-Content -Path $PathToRegFile -Value $GroupPolicyRegistry -Force
    Start-Process "C:\Windows\regedit.exe" -ArgumentList "/s $PathToRegFile" -Wait
    Remove-Item $PathToRegFile -Force

    Write-Log "Ensures that the AutoStart is enabled" 1
    $StartupApprovedRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    $StartupApprovedRegKey = 'OneDrive'
    $StartupApprovedRegValue = ([byte[]](0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

    # ref: https://superuser.com/questions/1413830/how-do-you-disable-startup-programs-that-only-exist-in-the-task-manager-startup
    # Create the key if it does not exist
    If (-NOT (Test-Path $StartupApprovedRegPath)) {
        New-Item -Path $StartupApprovedRegPath -PropertyType Binary -Force | Out-Null
    }
          
    # Now set the value
    Set-ItemProperty -Path $StartupApprovedRegPath -Name $StartupApprovedRegKey -Value $StartupApprovedRegValue -Force 
    
    $AutoStartupRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $AutoStartupRegKey = 'OneDrive'
    $AutoStartupRegValue = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe"'

    # Create the key if it does not exist
    If (-NOT (Test-Path $AutoStartupRegPath)) {
        New-Item -Path $AutoStartupRegPath -PropertyType String -Force | Out-Null
    }
          
    # Now set the value
    Set-ItemProperty -Path $AutoStartupRegPath -Name $AutoStartupRegKey -Value $AutoStartupRegValue -Force 
}

Function Remove-Nuke {
    $ShortcutPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Nuke 13"

    If (Test-Path "C:\Program Files\Nuke13") {
        Start-Process "C:\Program Files\Nuke13\Uninstall.exe" -ArgumentList "/S" -Wait -ErrorAction Ignore
    }
    Else {
        Write-Log "No Nuke installation found, skipping.." 1
    }

    If (Test-Path "$ShortcutPath") {
        Remove-Item "$ShortcutPath" -Force -Recurse -ErrorAction Ignore
    }
    Else {
        Write-Log "No shortcut found, skipping.." 1
    }

    Write-Host "Done uninstalling Nuke! Kindly check if Nuke exists in the Start Menu." -ForegroundColor Green
}

Function Install-Bambu {
    $InstallerName = "Bambu_Studio_win-v01.07.07.89.exe"
    $Destination = "$env:TEMP\$InstallerName"
    $Source = "\\10.61.50.5\SoftwareHub\Engineering\Bambu_Studio_win-v01.07.07.89.exe"
    Copy-Item $Source $Destination -Force
    Start-Process "$Destination" -ArgumentList "/s" -Wait
    Remove-Item "$Destination" -Force
}

Function Install-Ultimaker {
    $InstallerName = "UltiMaker-Cura-5.6.0-win64-X64.msi"
    $Destination = "$env:TEMP\$InstallerName"
    $Source = "\\10.61.50.5\SoftwareHub\Engineering\UltiMaker-Cura-5.6.0-win64-X64.msi"
    Copy-Item $Source $Destination -Force
    Start-Process "msiexec" -ArgumentList "/i $Destination /passive" -Wait
    Remove-Item "$Destination" -Force
}

Function Install-MTS {
    $Destination = "$env:TEMP\MTS"
    Start-Process "cmd" -ArgumentList "/c robocopy \\10.61.50.5\SoftwareHub\Engineering\MTS $Destination /s /e" -Wait
    $Installers = Get-ChildItem -Path $Destination -Recurse | Where-Object { "$_.Name" -Match ".*setup.*" }
    foreach ($Installer in $Installers) { 
        Start-Process "$($Installer.FullName)" -ArgumentList "/silent" -Wait
    }
    Remove-Item -Recurse "$Destination" -Force
}

Function Activate-VisioProject {
    Start-Process "cscript" -ArgumentList "`"C:\Program Files\Microsoft Office\Office16\OSPP.VBS`" /act" 
}
Function Hide-NetworkIcon {
    $HideNetworkIconRegContent = @'
    Windows Registry Editor Version 5.00
    
    [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
    "DontDisplayNetworkSelectionUI"=dword:00000001
'@
    $PathToRegFile = "C:\Windows\Temp\hideNetworkIconReg.reg"
    Set-Content -Path $PathToRegFile -Value $HideNetworkIconRegContent -Force
    Start-Process "C:\Windows\regedit.exe" -ArgumentList "/s $PathToRegFile" -Wait
    Remove-Item $PathToRegFile -Force
}
# Script begins here
# Pardon for the bad coding practices Σ(°△°|||)︴

# Clean up any existing connections
Remove-SmbMapping * -Force

Write-Host $banner
Out-File -FilePath $log_path -InputObject "$(Get-Date -Format "dd/MM/yyyy hh:mm:ss") [ INFO  ]  Post-Image initialized." -Encoding ascii   # Not using Write-Log to allow overwriting
Write-Host "`n Running Post-Image script designed for Lab Image $image_ver."
Write-Host " To view logs, find it at $log_path.`n"

Do {
    $status = $false
    if (Get-Creds -eq $true) {
        Write-Log "Domain account $username is used and authenticated successfully." 1
        $status = $true
    }
    else {
        Clear-Host
        Write-Status " Username or Password incorrect!" 1
    }
} Until ($status -eq $true)

Clear-Host
Write-Host $banner
Write-Status "`n Hello $username! Post-Image script will continue running." 3
Write-Host "`n Below are the hardware specifications of this workstation.`n Please check if the information are correct before continuing.`n`n ==============================================`n`n`n`n`n       Collecting information...`n`n`n`n ==============================================`n"

$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$cpu = (Get-WmiObject Win32_Processor).Name
$ram = Get-WmiObject CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
$gpu = (Get-WmiObject Win32_VideoController).Name -join ", "
$ip = (Get-NetIPConfiguration -InterfaceAlias "Ethernet*").IPv4Address.IPAddress
if (!$ip) {
    $ip = (Get-NetIPConfiguration -InterfaceAlias "*Wi-Fi*").IPv4Address.IPAddress 
}
$service_tag = (Get-WmiObject win32_bios).SerialNumber
$serial_number = (Get-WmiObject Win32_PhysicalMedia).SerialNumber


Clear-Host
Write-Host $banner
Write-Status "`n Hello $username! Post-Image script will continue running." 3
Write-Log "`n Below are the hardware specifications of this workstation.`n Please check if the information are correct before continuing.`n`n ==============================================`n`n PC Model    : $model`n CPU Model   : $cpu`n RAM Size    : $ram GB`n GPU Model   : $gpu`n IP Address  : $ip`n Service Tag : $service_tag`n Disk Serial : $serial_number`n`n ==============================================`n`n" 1

# Write-Log "Detected PC model: $model" 1
# Write-Log "Detected CPU model: $cpu" 1
# Write-Log "Detected RAM size: $ram GB" 1
# Write-Log "Detected GPU model: $gpu" 1
# Write-Log "IP address: $ip" 1
# Write-Log "Service tag: $service_tag" 1
# Write-Log "Disk Serial Number: $serial_number" 1

Read-Host " Press Enter to continue or press Ctrl + C to abort"

$domain_joined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($domain_joined) {
    $pc_name = hostname
}
while ($domain_joined -eq $false) {
    Clear-Host
    Write-Host $banner
    Write-Status "`n Workstation is not joined to domain.`n" 2
    Write-Status " Please enter the PC Name associated to this seat. Refer to lab layout if you are not sure." 4
    Write-Status " APU Lab layout: $apu_lab_layout_path`n" 4
    

    while ($pc_name.Length -eq 0) {
        $pc_name = Read-Host -Prompt " PC Name"
    }

    Write-Status "`n Are you sure?" 2
    $confirm = Read-Host ' Spell "yes" to confirm, or anything else to re-enter PC name' 

    if ($confirm -eq "yes") {
        try {
             Rename-Computer -NewName $pc_name -ErrorAction "Stop"
        }
        catch {
            Clear-Host
            Write-Host $banner
            Write-Status "`n There's some issue renaming the PC name." 1
            Write-Status "`n Please diagnose and fix the issue first by referring to the error logged at $log_path`n then try to run Post Image script again.`n`n" 4
            Write-Log "Something prevented renaming to $pc_name. The following error might help:" 4
            Write-Log $_ 4
            Write-Log "Post-Image ended." 1
            exit
        }
        $domain_joined = $true
        Write-Log "$pc_name joined domain successfully." 1
        Start-Sleep 1
    }
    else {
        $pc_name = ""
    }
}


Clear-Host
Write-Host $banner
Write-Status "`n PC renamed to $pc_name successfully.`n" 3
Write-Status " Please join the PC to Entra ID manually by following the guide provided by Software FU." 3
$enter = Read-Host ' Once completed, press Enter to continue' 

Clear-Host
Write-Status " Post-Image script will run automatically in 5 seconds..." 5
Write-Status ' Please click "Run" when prompted later.' 2
Start-Sleep 5

<# Write-To-Csv $pc_name $username $model $cpu $ram $gpu $ip $service_tag $serial_number #>

Clear-Host
Set-OuterProgress "Warming up..." "" 0
Start-Sleep 2
Write-Host "`n`n`n`n`n`n`n`n`n`n`n$wallpaper"

Set-OuterProgress "Reconfiguring..." "Power plans and power settings" 1
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -monitor-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0
powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
Write-Log "Configured device to stay awake." 1
Start-Sleep 3

Set-OuterProgress "Reconfiguring..." "System settings" 2
Start-Process -FilePath "$tools_path\OOSU10.exe" -WorkingDirectory $tools_path -ArgumentList "$image_ver.cfg", "/quiet", "/nosrp" -Wait
Write-Log "Disabled unneccessary functions using OOShutUp." 1

Start-Sleep 3

Set-OuterProgress "Reconfiguring..." "Services" 3

Set-Services wuauserv 0
Set-Services defragsvc 2
Set-Services Sysmain 0
Set-Services StorSvc 1
Set-Services ShellHWDetection 1

Start-Sleep 3

Set-OuterProgress "Reconfiguring..." "Other system settings" 4
bcdedit /set '{current}' hypervisorlaunchtype off > null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f > null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f > null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "dontdisplaylastusername" /t REG_DWORD /d 1 /f > null
reg import "$tools_path\wpv_restore.reg" > null
#Remove-Item Path "$env:ProgramData\ABB\RobotStudio\*" -Recurse -Force
#Start-Process "C:\Program Files (x86)\ABB\RobotStudio 2019\Bin\RobotStudio.Installer.exe" -ArgumentList "Install"
#Start-Process "C:\Program Files (x86)\ABB\RobotStudio 2019\Bin\RobotStudio.Installer.exe" -ArgumentList "SetServer rupert"
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" -Value "0" -type String
#Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*Lite*" -Force

Start-Sleep 3

Set-OuterProgress "Installing..." "System drivers" 5

Switch -Wildcard ($model) {
    "*OptiPlex 980*" {
        Install-Drivers $model "$driver_path\Optiplex-980"
    }
    "*Optiplex 990*" {
		Install-Drivers $model "$driver_path\Optiplex-990"
    }
    "*Optiplex 9010*" {
     
    }
    "*Optiplex 7470*" {
        Install-Drivers $model "$driver_path\Optiplex-7470"
    }
    "*Optiplex 7450*" {
        Install-Drivers $model "$driver_path\Optiplex-7450"
    }
    "*OptiPlex 9030*" {
        Install-Drivers $model "$driver_path\Optiplex-9030"
    }
    "*Precision T1700*" {
        Install-Drivers $model "$driver_path\Precision-T1700"
    }
    "*OptiPlex 3050 AIO*" {

    }
    "*Precision Tower 3620*" {
        Install-Drivers $model "$driver_path\Precision-T3620"
    }
    "*Precision 3260*" {
        Install-Drivers $model "$driver_path\Precision-3260-Compact"
    }
    "*Alienware Area-51 R2*" {

    }
    "*Alienware Aurora R5*" {
        Install-Drivers $model "$driver_path\Alienware Aurora R7"
    }
    "*Alienware Aurora R7*" {
        Install-Drivers $model "$driver_path\Alienware Aurora R7"
    }
    "*Alienware Aurora R9*" {
        Install-Drivers $model "$driver_path\Alienware Aurora R9"
    }
    "*3630*" {

    }
    default {
        Set-OuterProgress "Skipping... (No driver store)" "System drivers" 7
        Write-Log "PC Model: $model does not have a driver store on cobalt. Skipping driver installation." 1
        Start-Sleep 5
    }
}

Start-Sleep 3

Set-OuterProgress "Installing..." "Lab specific software" 8
Switch -Wildcard ($pc_name) {
    "*6-01*" {
        addEncase
    }
    "*6-02*" {
        addNetsim
    }
    "*6-08*" {
        addNetsim
    }
    "*APLC-L*" {
        robocopy "\\cobalt\Drivers\AutomatedPrograms" "C:\Users\localadmin\Desktop" APLC-Update.bat
    }
    "CGI*" {
        Install-AdobeXD -SetupPath "\\cobalt\Installers\New Lab Image (Temporary)\New Cobalt\4. Multimedia\Adobe CC 2019-2020\XdOnly-Aug-2020\Build\setup.exe"
        Copy-Item "\\cobalt\Drivers\Shotcuts\*XD*" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Force
    }
    "VFX*" {
        Install-AdobeXD -SetupPath "\\cobalt\Installers\New Lab Image (Temporary)\New Cobalt\4. Multimedia\Adobe CC 2019-2020\XdOnly-Aug-2020\Build\setup.exe"
        Copy-Item "\\cobalt\Drivers\Shotcuts\*XD*" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Force
    }
    "ID*" {
        Install-AdobeXD -SetupPath "\\cobalt\Installers\New Lab Image (Temporary)\New Cobalt\4. Multimedia\Adobe CC 2019-2020\XdOnly-Aug-2020\Build\setup.exe"
        Copy-Item "\\cobalt\Drivers\Shotcuts\*XD*" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Force
    }
    "*3-FAB*" {
        Install-Ultimaker
        Install-Bambu
    }
    "*CADCAM*" {
        Install-MTS
    }
    default {
        Set-OuterProgress "Skipping... (No additional software required)" "Lab specific software" 9
        Write-Log "Lab for $pc_name does not require additional software installation. Skipping software installation." 1
        Start-Sleep 5
    }
}

Install-Teams
Copy-AutomationStudio
Set-OneDriveGPO
Remove-Nuke
Activate-VisioProject
Hide-NetworkIcon

$wallpaperName = "LockscreenStartupHackathon.png"
Set-LockScreen -wallpaperNameWithExtension "$wallpaperName"

Start-Sleep 3

Set-OuterProgress "Cleaning up..." "Running DISM" 10
dism /online /cleanup-image /restorehealth > null

Set-OuterProgress "Cleaning up..." "Running SFC" 11
sfc /scannow > null

Set-OuterProgress "Installing DeepFreeze" "Running installer" 12
Install-DeepFreeze $pc_name



# Show update on Teams channel
$ta_email = "https://teams.microsoft.com/l/chat/0/0?users=$script:username@cloudmails.apu.edu.my"
$msg = '{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "00bfa5",
    "summary": "Reimage Notification",
    "sections": [{
        "activityTitle": "Reimage Notification",
        "activitySubtitle": "' + $(Get-Date -Format g) + '",
        "activityImage": "https://i.kym-cdn.com/photos/images/original/002/477/529/b46.gif",
        "facts": [{
            "name": "TA Name",
            "value": "' + $script:username + '"
        },{
            "name": "PC Name",
            "value": "'+ $pc_name + '"
        },{
            "name": "PC IP",
            "value": "'+ $ip + '"
        }],
        "markdown": true
    }],
    "potentialAction": [{
        "@type": "ActionCard",
        "name": "Actions",
        "actions": [{
            "@type": "OpenUri",
            "name": "Chat with this TA",
            "targets": [
                { "os": "default", "uri": "' + $ta_email + '" }
            ]
        }]
    }]
}'
$url = "https://cloudmails.webhook.office.com/webhookb2/50c827ce-2f31-4a2b-a485-ffaf1b1add46@0fed03a3-402d-4633-a8cd-8b308822253e/IncomingWebhook/92fe4d9718494ced888b087dfb9b93f4/739c0520-071d-4ed9-810b-3c940e6b7207"
Invoke-WebRequest -UseBasicParsing $url -ContentType "application/json" -Method POST -Body $msg > null


# Write-Host "Clearing with CCleaner"
# Write-Host "Please wait for 30 seconds"
# & \\temp\sub\ccsetup544\CCleaner64.exe /AUTO
# Start-sleep -s 30

# Creates DATA Partition
<# 
$testpsdrive = get-psdrive -PSProvider FileSystem -Name D -ErrorAction SilentlyContinue
$testvol = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue
If ( (($testpsdrive).Description -eq "DATA") -or (($testvol).FileSystemLabel -eq "DATA") ) {
    Write-Host "DATA partition already exists on D. Not creating."
    Write-Host "Hiding Drive D:"
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -Value 8
    Read-Host "Press Enter to continue"
}
elseif ((Get-Partition -DriveLetter C).Size -lt 400GB) {
    addStatus "C partition is less than 300G. Not creating DATA partition." "fail"
    Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDrives -ErrorAction SilentlyContinue
    Read-Host "Press Enter to continue"
}
else {
    Write-Host "Creating DATA partition..."
    if ($CDDrive = Get-Volume | Where-Object -Property "DriveType" -eq "CD-ROM") {
        $name = $CDDrive.DriveLetter
        $letter = $name + ":"
        $ID = mountvol $letter /L
        $ID = $ID.Trim()

        mountvol $letter /D
        mountvol F:\ $ID
    }
    if ($USBDrive = Get-Volume | Where-Object -Property "DriveType" -eq "Removable") {
        Write-Host "Detected USB Drive. Changing USB Drive Letter..."
        $name2 = $USBDrive.DriveLetter
        $letter2 = $name2 + ":"
        $ID2 = mountvol $letter2 /L
        $ID2 = $ID2.Trim()

        mountvol $letter2 /D
        mountvol G:\ $ID2
    }
    if (Test-Path D:\) {
        Set-Partition -DriveLetter D -NewDriveLetter G
    }

    $NewCSize = (Get-Partition -DriveLetter C).Size / 2
    Resize-Partition -DriveLetter C -Size $NewCSize
    $DPartition = New-Partition -DiskNumber (Get-Partition -DriveLetter C).DiskNumber -UseMaximumSize
    $DPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false
    $DPartition | Set-Partition -NewDriveLetter D

    Start-sleep -s 10

    if (!(get-psdrive -PSProvider FileSystem -Name D).Description -eq "DATA") {
        addStatus "Failed to create DATA partition on D. Please verify manually." "fail"
        Read-Host "Press Enter to continue"
    }
    else {
        Write-Host "Hiding Drive D:"
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -Value 8
    }
}
 #>

<#
$Disks = $true
Do {
    $BootDisk = Get-Partition | Where-Object { $_.DriveLetter -eq ($env:SystemDrive).Substring(0, 1) } 
    $BootDiskNumber = $BootDisk.DiskNumber

    # Get all physical disks excluding the boot disk
    $Disks = @(Get-Disk | Where-Object { $_.Number -ne $BootDiskNumber -and $_.OperationalStatus -eq 'Online' })
    If ($Disks.Count -eq 0) {
        Write-Log "No extra HDD found. Automatic partitioning skipped." 1
    }
    ElseIf ($Disks.Count -eq 1) {
        # Disks.Count will not be valid property if there's only one or no disk.
        $TargetDisk = $Disks
    }
    Else {
        # Sort the remaining disks by disk number
        $SortedDisks = $Disks | Sort-Object -Property Number

        # Display a list of disks and their details to the user
        Write-Host "Extra disks:"
        for ($i = 0; $i -lt $SortedDisks.Count; $i++) {
            Write-Host "Disk [$($SortedDisks[$i].Number)]: $($SortedDisks[$i].FriendlyName)"
        }

        # Prompt the user to select a disk
        Do { $TargetDiskNumber = Read-Host "Enter the disk number to be overwritten" }
        While (-Not (($TargetDiskNumber -Match "\d") -and ([int]$TargetDiskNumber -ge 0) -and ([int]$TargetDiskNumber -ne $BootDiskNumber)))

        $TargetDisk = Get-Disk | Where-Object { $_.Number -eq $TargetDiskNumber }

    }
    # Only ask when there's extra disk other than the booted one.
    If ($Disks) {
        $ConfirmMessage = "Enter `"yes`" if it's the correct target"
        Write-Host "Please confirm that the following is the target drive.`nThe target drive will be wiped and formatted as D drive.`nALL DATA WITHIN IT WILL BE OVERWRITTEN!!!" -ForegroundColor Cyan

        Write-Host ("=" * $ConfirmMessage.Length)
        $TargetDisk | Format-List FriendlyName, @{Name = "Total Size"; Expression = { "$($_.Size / 1MB) MB" } }
        Write-Host ("=" * $ConfirmMessage.Length)

        $ConfirmTarget = (Read-Host "Enter `"yes`" if it's the correct target").ToLower()
    }
} While ( $Disks -and (-Not ($ConfirmTarget -in @( "yes", "skip" ))))

If (($null -ne $ConfirmTarget) -and ($ConfirmTarget -ne "skip") ) {
    if ($CDDrive = Get-Volume | Where-Object -Property "DriveType" -eq "CD-ROM") {
        $name = $CDDrive.DriveLetter
        If ($null -ne $name) {
            $letter = $name + ":"
            $ID = mountvol $letter /L
            $ID = $ID.Trim()
            mountvol $letter /D
            mountvol F:\ $ID
        }
        
    }
    if ($USBDrive = Get-Volume | Where-Object -Property "DriveType" -eq "Removable") {
        Write-Host "Detected USB Drive. Changing USB Drive Letter..."
        $name2 = $USBDrive.DriveLetter
        $letter2 = $name2 + ":"
        $ID2 = mountvol $letter2 /L
        $ID2 = $ID2.Trim()

        mountvol $letter2 /D
        mountvol G:\ $ID2
    }
    if (Test-Path D:\) {
        Set-Partition -DriveLetter D -NewDriveLetter G
    }

    #$TargetDisk | Initialize-Disk -PartitionStyle GPT -Confirm:$false -ErrorAction SilentlyContinue
    Set-Disk -Number $TargetDisk.Number -IsOffline $true
    Get-Partition -DiskNumber $TargetDisk.Number | Remove-Partition -Confirm:$false

    # Create a new partition using the maximum available space
    $DPartition = New-Partition -DiskNumber $TargetDisk.Number -UseMaximumSize

    Set-Disk -Number $TargetDisk.Number -IsOffline $false
    # Format the partition with NTFS and set the label to DATA
    $DPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false
    # Assign D: to the partition
    $DPartition | Set-Partition -NewDriveLetter "D"

    if (!(Get-PSDrive -PSProvider FileSystem -Name D).Description -eq "DATA") {
        Write-Log "Failed to create DATA partition on D. Please verify manually." 3
        Read-Host "Press Enter to continue..."
    }
    else {
        Write-Host "Hiding Drive D:"
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -Value 8
    }

}
Else {
    Write-Log "Skipped automatic D Drive partitioning." 1
}
#>
Remove-PSDrive Z

Clear-Host
Write-Host "Post-Image script have completed. Please do not use the computer after restarting until further notice."
Read-Host "Press Enter to restart"
Write-Log "Post-Image ended." 1

# Cleanup and restart
Remove-Item -Path C:\Users\localadmin\Desktop\*.ps1 -Force
Remove-Item -Path C:\Users\localadmin\Desktop\*.lnk -Force
Remove-Item -Path C:\Users\localadmin\Desktop\*.bat -Force
Start-Process -FilePath "C:\Windows\System32\shutdown.exe" -ArgumentList "/f /r /t 10"
