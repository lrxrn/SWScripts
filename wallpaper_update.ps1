param (
    [string]$LogPath,
    [string]$ZipURL,
    [string]$Deployment
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
    } | ConvertTo-Json
    Invoke-WebRequest -Uri "https://script.google.com/macros/s/AKfycbxjqGXAp2pVi4r5U6DTw_bTW-SjCqw9uiXp6eUGtZb77CdlbOmtI6bK_Nk9PCeZlYHopg/exec" `
        -Method POST `
        -Headers $headers `
        -Body $body
}

if (Test-Path $LogPath) {
    Send-Status -Status "Skipped"
    exit
}

Add-Content -Path $LogPath -Value ("[{0}] Starting wallpaper update." -f (Get-Date))

$downloadPath = "$env:USERPROFILE\Downloads\lockscreen.zip"
$extractPath = "$env:USERPROFILE\Downloads\ExtractedWallpaper"
$wallpaperDir = "C:\ProgramData\Wallpaper"
$imagePath = "$wallpaperDir\lockscreen.png"
$targetImage = "$extractPath\Wallpaper\Lockscreen 10.png"
$regKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

try {
    Invoke-WebRequest -Uri $ZipURL -OutFile $downloadPath -UseBasicParsing
    if (Test-Path $wallpaperDir) {
        Remove-Item $wallpaperDir -Recurse -Force
    }

    Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractPath -Force

    if (!(Test-Path $targetImage)) {
        throw "Wallpaper file not found at expected location: $targetImage"
    }

    New-Item -Path $wallpaperDir -ItemType Directory -Force | Out-Null
    Copy-Item -Path $targetImage -Destination $imagePath -Force

    if (-not (Test-Path $regKeyPath)) {
        New-Item -Path $regKeyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regKeyPath -Name 'LockScreenImage' -Value $imagePath

    Remove-Item $extractPath -Recurse -Force
    Remove-Item $downloadPath -Force

    Add-Content -Path $LogPath -Value ("[{0}] Wallpaper update succeeded." -f (Get-Date))
    Send-Status -Status "Done"
}
catch {
    $errorText = "$($_.Exception.Message)"
    Add-Content -Path $LogPath -Value ("[{0}] Wallpaper update failed: $errorText" -f (Get-Date))
    Send-Status -Status "Failed" -ErrorMessage $errorText
    exit 1
}
