param (
    [string]$LogPath = "C:\Users\localadmin\Documents\Deployment_Wallpaper_19072025_RE.txt",
    [string]$ZipURL = "https://cloudmails-my.sharepoint.com/:u:/g/personal/hammad_imran_cloudmails_apu_edu_my/EavXPUlg965GtkaMuDBR5isBZdFUNAUA-nrNXj3L4qK9kg?download=1",
    [string]$Deployment = "Wallpaper_19072025_RE"
)

function Send-Status {
    param (
        [string]$Status,
        [string]$ErrorMessage = ""
    )
    $pcName = $env:COMPUTERNAME
    $headers = @{ "Content-Type" = "application/json" }
    $body = @{
        pcName = $pcName
        deployment = $Deployment
        status = $Status
        errorMessage = $ErrorMessage
    } | ConvertTo-Json -Compress
    Invoke-WebRequest -Uri "https://script.google.com/macros/s/AKfycbxjqGXAp2pVi4r5U6DTw_bTW-SjCqw9uiXp6eUGtZb77CdlbOmtI6bK_Nk9PCeZlYHopg/exec" `
        -Method POST `
        -Headers $headers `
        -Body $body `
        -UseBasicParsing
}

# Skip execution if log already exists
if (Test-Path $LogPath) {
    Send-Status -Status "Skipped"
    exit
}

Add-Content -Path $LogPath -Value ("[{0}] Starting wallpaper update." -f (Get-Date))

# Define paths
$downloadPath = "C:\Users\localadmin\Downloads\lockscreen.zip"
$extractPath = "C:\Users\localadmin\Downloads\ExtractedWallpaper"
$wallpaperDir = "C:\ProgramData\Wallpaper"
$imagePath = "$wallpaperDir\lockscreen.png"
$regKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

# Detect Windows 11 via build number
$targetImageName = "Lockscreen 10.png"
try {
    $buildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    if ([int]$buildNumber -ge 22000) {
        $targetImageName = "Lockscreen 11.png"
    }
} catch {
    # Default to Lockscreen 10.png if detection fails
    $targetImageName = "Lockscreen 10.png"
}
$targetImage = "$extractPath\lockscreen\$targetImageName"

$didFail = $false
$errorText = ""

try {
    Invoke-WebRequest -Uri $ZipURL -OutFile $downloadPath -UseBasicParsing

    if (Test-Path $wallpaperDir) {
        Remove-Item $wallpaperDir -Recurse -Force
    }

    Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractPath -Force

    if (!(Test-Path $targetImage)) {
        throw "Wallpaper file '$targetImageName' not found at expected location: $targetImage"
    }

    New-Item -Path $wallpaperDir -ItemType Directory -Force | Out-Null
    Copy-Item -Path $targetImage -Destination $imagePath -Force

    if (-not (Test-Path $regKeyPath)) {
        New-Item -Path $regKeyPath -Force | Out-Null
    }

    Set-ItemProperty -Path $regKeyPath -Name 'LockScreenImage' -Value $imagePath
}
catch {
    $didFail = $true
    $errorText = $_.Exception.Message
    Add-Content -Path $LogPath -Value ("[{0}] Wallpaper update failed: {1}" -f (Get-Date), $errorText)
}

# Cleanup
Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue

# Final status
if ($didFail) {
    #Send-Status -Status "Failed" -ErrorMessage $errorText
    exit 1
} else {
    Add-Content -Path $LogPath -Value ("[{0}] Wallpaper update succeeded." -f (Get-Date))
    #Send-Status -Status "Done"
}
