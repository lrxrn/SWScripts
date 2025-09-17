# Post-Image-Win11.ps1
set-Strictmode -Version Latest

# Ensure script is running as Administrator
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
$image_ver = "24H2"
$debug_logging = $true  # Set to $true to enable debug logging
$apu_lab_layout_path = "Refer to Documentation on Sharepoint: https://cloudmails-my.sharepoint.com/:u:/r/personal/ta_cloudmails_apu_edu_my/taportal/SitePages/APU-Lab-Layout.aspx"
$log_path = "C:\postimage-log-$(Get-Date -Format "ddMMyy")-$image_ver.txt"

# Mount path for Apollo
$mount_path = "\\10.61.50.5\Apollo"
$df_path = "Z:\Post-Image\DeepFreeze"
$tools_path = "Z:\Post-Image\Tools"
# Note: Dell Command Update will handle driver downloads automatically from Dell's servers

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
                      @@@@@@@@@          /@@@@@@@     @@@@@   @@@@@@    .@@@@@@@@@     @@@@/ @@@@@@                     
                      %@@@@@@@@           @@@@@@@     @@@@@   @@@@@@    .@@@@@@@@@     @@@@  @@@@@#                     
                        @@@@@@@@         /@@@@@       @@@@@    @@@@     *@@@@@@@@@     @@@@  @@@@@                      
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
#                         5     - Debug (only shows if debug_logging is enabled)
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
        5 {
            if (-not $debug_logging) { return }
            $status = "[ DEBUG ]"
            $fontColor = 'Cyan'
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
        Write-Host "Enter credentials for Domain joining and access to Apollo server (Example: wei.lun)."
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
    
    Try {
        New-PSDrive -Name "Z" -PSProvider FileSystem -Root $mount_path -Credential $creds -Scope script -Persist -ErrorAction Stop
        while (!(Test-Path Z:\)) { Start-Sleep 1 }
        $script:username = $username
        return $true
    }
    catch {
        Write-Log "Domain account $username is used and fail to authenticate. Please check your credentials." 3
        $username = ""
        return $false
    }
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

function Install-DellCommandUpdate {
    Write-Log "Starting Dell Command Update installation and driver update process" 1
    Write-Log "Debug logging enabled: $debug_logging" 5
    
    $dcu_installer = "$tools_path\Dell-Command-Update-Windows-Universal-Application_C8JXV_WIN64_5.5.0_A00.exe"
    $dcu_path = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    
    Write-Log "Checking if DCU installer exists at: $dcu_installer" 5
    if (-not (Test-Path $dcu_installer)) {
        Write-Log "Dell Command Update installer not found at $dcu_installer" 3
        Write-Log "Available files in tools path:" 5
        if (Test-Path $tools_path) {
            Get-ChildItem $tools_path | ForEach-Object { Write-Log "  - $($_.Name)" 5 }
        }
        return $false
    }
    
    Write-Log "Dell Command Update installer found, proceeding with installation" 1
    Write-Log "Installing Dell Command Update silently..." 1
    
    try {
        # Install DCU silently using start /wait method
        Write-Log "Installing Dell Command Update silently..." 1
        Write-Log "Executing: start /wait $dcu_installer /s" 5
        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "start", "/wait", $dcu_installer, "/s" -Wait -PassThru -NoNewWindow
        Write-Log "DCU installer exit code: $($process.ExitCode)" 5
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Dell Command Update installed successfully" 1
        } else {
            Write-Log "Dell Command Update installation failed with exit code: $($process.ExitCode)" 3
            return $false
        }
        
        # Wait for installation to complete and verify
        Write-Log "Waiting for DCU installation to complete..." 5
        $timeout = 120  # Extended timeout for silent installation
        $counter = 0
        while (-not (Test-Path $dcu_path) -and $counter -lt $timeout) {
            Start-Sleep -Seconds 5
            $counter += 5
            Write-Log "Waiting for DCU CLI... ($counter/$timeout seconds)" 5
        }
        
        if (-not (Test-Path $dcu_path)) {
            Write-Log "DCU CLI not found after installation timeout" 3
            return $false
        }
        
        Write-Log "DCU CLI found at: $dcu_path" 1
        
        # Apply all available updates silently with auto-reboot if needed
        Write-Log "Running Dell Command Update silently with auto-reboot if needed..." 1
        Write-Log "This may take several minutes depending on the number of updates..." 1
        Write-Log "System may reboot automatically if updates require it..." 2
        
        $updateProcess = Start-Process -FilePath $dcu_path -ArgumentList "/applyUpdates", "-reboot=enable", "-silent" -Wait -PassThru -NoNewWindow
        Write-Log "DCU silent update exit code: $($updateProcess.ExitCode)" 5
        
        switch ($updateProcess.ExitCode) {
            0 { 
                Write-Log "All driver updates applied successfully" 1 
            }
            1 { 
                Write-Log "Some updates were applied, but a reboot is required" 2 
            }
            2 { 
                Write-Log "No updates were available" 1 
            }
            3 { 
                Write-Log "Updates failed to apply" 3 
            }
            4 { 
                Write-Log "Updates applied but some require manual intervention" 2 
            }
            default { 
                Write-Log "Unknown exit code from DCU update process: $($updateProcess.ExitCode)" 2 
            }
        }
        
        # Generate update report
        Write-Log "Generating driver update report..." 5
        $reportPath = "C:\DCU-Report-$(Get-Date -Format 'ddMMyy-HHmm').txt"
        $reportProcess = Start-Process -FilePath $dcu_path -ArgumentList "/report=$reportPath" -Wait -PassThru -NoNewWindow
        Write-Log "DCU report generation exit code: $($reportProcess.ExitCode)" 5
        
        if (Test-Path $reportPath) {
            Write-Log "Driver update report generated at: $reportPath" 1
            Write-Log "Report contents:" 5
            Get-Content $reportPath | ForEach-Object { Write-Log "  $_" 5 }
        }
        
        return $true
        
    } catch {
        Write-Log "Exception occurred during Dell Command Update process: $_" 3
        Write-Log "Exception details: $($_.Exception.Message)" 5
        return $false
    }
}

function Install-Drivers ($model, $path) {
    Write-Log "Legacy Install-Drivers function called for model: $model" 5
    Write-Log "This function is deprecated - using Dell Command Update instead" 2
    
    # Check if this is a Dell system
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    Write-Log "System manufacturer: $manufacturer" 5
    
    if ($manufacturer -like "*Dell*") {
        Write-Log "Dell system detected, using Dell Command Update for driver installation" 1
        return Install-DellCommandUpdate
    } else {
        Write-Log "Non-Dell system detected ($manufacturer), skipping automatic driver installation" 2
        Write-Log "Manual driver installation may be required for this system" 2
        return $true
    }
}

function Install-DeepFreeze ($lab) {
    Write-Log "Initiating DeepFreeze setup for computer: $lab" 1
    Write-Log "DeepFreeze files located at: $df_path" 5
    
    # Prompt user to enter lab name to determine installer
    $df_lab_name = Read-Host -Prompt " Enter Lab name to find DeepFreeze installer (e.g., TL06-01, S-06-02, etc.)"
    $installer = $null
    # Search for installer matching lab name
    if ($df_lab_name.Length -gt 0) {
        $installer = Get-ChildItem $df_path -Filter "*.exe" | Where-Object { $_.Name -like "*$df_lab_name*" } | Select-Object -First 1
        if ($installer) {
            $installer = $installer.BaseName
            Write-Log "Located appropriate DeepFreeze package for lab: $installer" 1
        } else {
            Write-Log "DeepFreeze package not found for lab: $df_lab_name, Installation canceled." 3
            return $false
        }
    } else {
        Write-Log "Lab name required to select correct DeepFreeze package" 3
        return $false
    }
    
    $installer_name = "$installer.exe"
    $source_path = "$df_path\$installer_name"
    $dest_path = "C:\$installer_name"
    
    Write-Log "Searching for installer: $installer_name" 5
    Write-Log "Original location: $source_path" 5
    Write-Log "Target location: $dest_path" 5
    
    if (-not (Test-Path $source_path)) {
        Write-Log "Unable to locate DeepFreeze installer at: $source_path" 3
        Write-Log "Contents of DeepFreeze directory:" 5
        if (Test-Path $df_path) {
            Get-ChildItem $df_path | ForEach-Object { Write-Log "  - $($_.Name)" 5 }
        }
        return $false
    }
    
    try {
        # Copy installer to C:\ drive
        Write-Log "Transferring DeepFreeze installer to local drive..." 1
        robocopy.exe $df_path "C:\" $installer_name > $null
        
        if (-not (Test-Path $dest_path)) {
            Write-Log "Transfer of DeepFreeze installer to local drive unsuccessful" 3
            return $false
        }
        
        Write-Log "Launching DeepFreeze installation process..." 1
        Write-Log "Running command: $dest_path /DFNoReboot /Thaw" 5
        
        $process = Start-Process -FilePath $dest_path -WorkingDirectory "C:\" -ArgumentList "/DFNoReboot", "/Thaw" -Wait -PassThru
        Write-Log "Installation process returned code: $($process.ExitCode)" 5
        
        if ($process.ExitCode -eq 0) {
            Write-Log "DeepFreeze deployment completed successfully" 1
        } else {
            Write-Log "DeepFreeze setup finished with return code: $($process.ExitCode)" 2
        }
        
        # Clean up installer
        Write-Log "Removing temporary installation files..." 5
        Remove-Item $dest_path -Force
        Write-Log "DeepFreeze setup procedure finished" 1
        
        return $true
        
    } catch {
        Write-Log "Error encountered during DeepFreeze installation: $_" 3
        Write-Log "Error specifics: $($_.Exception.Message)" 5
        
        # Attempt cleanup
        if (Test-Path $dest_path) {
            Remove-Item $dest_path -Force -ErrorAction SilentlyContinue
        }
        
        return $false
    }
}

# Script actually begins here
# Pardon for the even worse coding practices Σ(°△°|||)︴

# Clean up any existing connections
Remove-SmbMapping * -Force

Write-Host $banner

# Check if script has already been run
if (-not (Test-ScriptAlreadyRun)) {
    Write-Log "Script terminated as it detected log files indicating the post-image script was already run." 1
    exit
}

Out-File -FilePath $log_path -InputObject "$(Get-Date -Format "dd/MM/yyyy hh:mm:ss") [ INFO ]  Post-Image initialized." -Encoding ascii   # Not using Write-Log to allow overwriting
Write-Host "`n Running Post-Image script designed for Lab Image $image_ver."
Write-Host " To view logs, find it at $log_path.`n"

Do {
    $status = $false
    if (Get-Creds -eq $true) {
        Write-Log "Authentication successful for domain account $username." 1
        $status = $true
    }
    else {
        Clear-Host
        Write-Status "Username or Password incorrect! Please try again." 1
    }
} Until ($status -eq $true)

Clear-Host
Write-Host $banner
Write-Status "`n Welcome $username! The Post-Image script is now in progress." 3
Write-Host "`n This workstation's hardware specifications are shown below.`n Please verify this information is accurate before proceeding.`n`n ==============================================`n`n`n`n`n       Gathering system details...`n`n`n`n ==============================================`n"

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
Write-Status "`n Welcome $username! The Post-Image script is now in progress." 3
Write-Log "`n Below are the hardware specifications of this workstation.`n Please verify this information is accurate before proceeding.`n`n ==============================================`n`n PC Model    : $model`n CPU Model   : $cpu`n RAM Size    : $ram GB`n GPU Model   : $gpu`n IP Address  : $ip`n Service Tag : $service_tag`n Disk Serial : $serial_number`n`n ==============================================`n`n" 1

# Write-Log "Detected PC model: $model" 1
# Write-Log "Detected CPU model: $cpu" 1
# Write-Log "Detected RAM size: $ram GB" 1
# Write-Log "Detected GPU model: $gpu" 1
# Write-Log "IP address: $ip" 1
# Write-Log "Service tag: $service_tag" 1
# Write-Log "Disk Serial Number: $serial_number" 1

Read-Host " Press Enter to continue or press Ctrl + C to abort"
Write-Status "Joining domain..." 1
Write-Host "Domain joining requires network connectivity. Please ensure the Ethernet cable / WiFi is connected properly.`n`n"

$domain_joined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($domain_joined) {
    $pc_name = hostname
}
while ($domain_joined -eq $false) {
    Clear-Host
    Write-Host $banner
    Write-Status "`n This workstation has not been joined to the domain yet.`n" 2
    Write-Status " Enter the correct PC Name for this workstation (check lab layout if unsure)." 4
    Write-Status " Lab layout reference: $apu_lab_layout_path`n" 4
    
    while ($pc_name.Length -eq 0) {
        $pc_name = Read-Host -Prompt " Enter PC Name"
    }

    Write-Status "`n Please confirm your selection" 2
    $confirm = Read-Host ' Type "yes" to confirm, or any other input to re-enter PC name' 

    if ($confirm -eq "yes") {
        try {
             Rename-Computer -NewName $pc_name -ErrorAction "Stop"
        }
        catch {
            Clear-Host
            Write-Host $banner
            Write-Status "`n An error occurred while attempting to rename this PC." 1
            Write-Status "`n Please review the error details in the log file at $log_path`n and try running the Post-Image script again after resolving the issue.`n`n" 4
            Write-Log "Computer rename operation to $pc_name failed with the following error:" 4
            Write-Log $_ 4
            Write-Log "Post-Image process terminated due to rename failure." 1
            exit
        }
        $domain_joined = $true
        Write-Log "Successfully renamed computer to $pc_name and joined domain." 1
        Start-Sleep 1
    }
    else {
        $pc_name = ""
    }
}

Clear-Host
Write-Status " Post-Image script will run continue in 5 seconds..." 5
Write-Status ' Please click "Run" when prompted later.' 2
Start-Sleep 5

Write-Log "Dell Command Update will handle driver downloads automatically" 1

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

Set-OuterProgress "Reconfiguring..." "Services" 2

Set-Services wuauserv 0
Set-Services defragsvc 2
Set-Services Sysmain 0
Set-Services StorSvc 1
Set-Services ShellHWDetection 1

Start-Sleep 3

Set-OuterProgress "Reconfiguring..." "Other system settings" 3
bcdedit /set '{current}' hypervisorlaunchtype off > null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f > null

Start-Sleep 3

Set-OuterProgress "Installing..." "System drivers" 4

# Check system manufacturer and model
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Log "System manufacturer: $manufacturer" 1
Write-Log "System model: $model" 1

if ($manufacturer -like "*Dell*") {
    Write-Log "Dell system detected - using Dell Command Update for driver installation" 1
    Write-Log "This will automatically detect and install all necessary drivers" 1
    
    $dcu_success = Install-DellCommandUpdate
    if ($dcu_success) {
        Write-Log "Dell Command Update driver installation completed successfully" 1
    } else {
        Write-Log "Dell Command Update driver installation failed" 3
        Write-Log "Manual driver installation may be required" 2
    }
} else {
    Write-Log "Non-Dell system detected: $manufacturer" 2
    Write-Log "Dell Command Update cannot be used for non-Dell systems" 2
    Write-Log "Manual driver installation may be required" 2
    
    Write-Log "Skipping automatic driver installation for non-Dell system" 1
}

Write-Log "Driver installation phase completed" 1

Start-Sleep 3

Set-OuterProgress "Cleaning up..." "Running DISM" 5
dism /online /cleanup-image /restorehealth > null

Set-OuterProgress "Cleaning up..." "Running SFC" 6
sfc /scannow > null

Set-OuterProgress "Installing DeepFreeze" "Running installer" 7
Install-DeepFreeze $pc_name

Start-Sleep 3

# Show update on Teams channel
$msg = '{
    "pc": "' + $pc_name + '",
    "ta": "' + $username + '",
    "ip": "' + $ip + '",
    "model": "' + $model + '",
    "cpu": "' + $cpu + '",
    "ram": "' + $ram + '",
    "gpu": "' + $gpu + '",
    "serviceTag": "' + $serviceTag + '",
    "serialNumber": "' + $serialNumber + '"
}'
$url = "https://cloudmails.webhook.office.com/webhookb2/50c827ce-2f31-4a2b-a485-ffaf1b1add46@0fed03a3-402d-4633-a8cd-8b308822253e/IncomingWebhook/92fe4d9718494ced888b087dfb9b93f4/739c0520-071d-4ed9-810b-3c940e6b7207"
Invoke-WebRequest -UseBasicParsing $url -ContentType "application/json" -Method POST -Body $msg > null

Set-OuterProgress "Finalizing..." "Disconnecting network drives" 8
Remove-PSDrive Z

Clear-Host
Write-Host "Post-Image process completed successfully for $pc_name."
Read-Host "Press Enter to restart"
Write-Log "Post-Image ended." 1

# Cleanup downloaded files and restart
Remove-DownloadedFiles
Remove-Item -Path C:\Users\localadmin\Desktop\*.ps1 -Force
Remove-Item -Path C:\Users\localadmin\Desktop\*.lnk -Force
Remove-Item -Path C:\Users\localadmin\Desktop\*.bat -Force
Start-Process -FilePath "C:\Windows\System32\shutdown.exe" -ArgumentList "/f /r /t 10 /c `"Post-Image script completed. System will restart in 10 seconds.`"" -NoNewWindow

function Remove-DownloadedFiles {
    Write-Log "Cleaning up downloaded files..." 1
    try {
        if (Test-Path $download_path) {
            Remove-Item -Path $download_path -Recurse -Force
            Write-Log "Removed temporary download directory." 1
        }
        if (Test-Path $tools_path) {
            Remove-Item -Path $tools_path -Recurse -Force
            Write-Log "Removed installer packages directory." 1
        }
        if (Test-Path $df_path) {
            Remove-Item -Path $df_path -Recurse -Force
            Write-Log "Removed DeepFreeze installers directory." 1
        }
    }
    catch {
        Write-Log "Error during cleanup: $_" 2
        Write-Log "Cleanup error details: $($_.Exception.Message)" 5
    }
}

function Test-ScriptAlreadyRun {
    Write-Log "Checking if Post-Image script has already been run..." 5
    
    # Check for existing log files
    $existing_logs = Get-ChildItem -Path "C:\" -Filter "postimage-log-*-$image_ver.txt" -ErrorAction SilentlyContinue
    
    if ($existing_logs.Count -gt 0) {
        Write-Log "Found existing Post-Image log files:" 2
        $existing_logs | ForEach-Object { Write-Log "  - $($_.Name)" 2 }
        
        Write-Status "`n WARNING: Post-Image script appears to have been run already!" 2
        Write-Status " Found existing log file(s) for image version $image_ver" 2
        Write-Status " Running the script again may cause issues or conflicts.`n" 2
        
        Write-Status " What would you like to do?" 4
        Write-Status " 1. Continue anyway (may cause issues)" 2
        Write-Status " 2. Exit and check logs first" 3
        
        do {
            $choice = Read-Host " Enter your choice (1 or 2)"
        } while ($choice -notin @("1", "2"))
        
        switch ($choice) {
            "1" {
                Write-Log "User chose to continue despite existing log files" 2
                Write-Status " Continuing with Post-Image script..." 2
                Write-Status " Please monitor the logs carefully for any issues.`n" 2
                return $true
            }
            "2" {
                Write-Log "User chose to exit due to existing log files" 1
                Write-Status " Exiting Post-Image script." 1
                Write-Status " Please review the existing log files before running again." 1
                Write-Status " Log files are located at: C:\postimage-log-*-$image_ver.txt`n" 1
                return $false
            }
        }
    } else {
        Write-Log "No existing log files found, proceeding with script" 5
        return $true
    }
}

# Check if script has already been run
if (-not (Test-ScriptAlreadyRun)) {
    Write-Log "Script terminated by user choice." 1
    exit
}