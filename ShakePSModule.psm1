#################################################################################################################################
############                        SHAKE'S PowerShell Module                        ############
#################################################################################################################################

################### System Utilities #############################
function Test-CommandExists {
    param ( $command )
    $exists = $null -ne ( Get-Command $command -ErrorAction SilentlyContinue )
    return $exists
}

function touch ( $file ) { "" | Out-File $file -Encoding ASCII }

function ff ( $name ) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | 
        ForEach-Object { Write-Output "$($_. FullName)" }
}

function unzip ( $file ) {
    Write-Output( "Extracting", $file, "to", $pwd )
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Ar chive -Path $fullFile -DestinationPath $pwd
}

function grep ( $regex, $dir ) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function far ( $file, $find, $replace ) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which ( $name ) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export ( $name, $value ) {
    set-item -force -path "env:$name" -value $value;
}

function k9 { Stop-Process -Name $args[0] }

function pkill ( $name ) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pget ( $name ) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10, [switch]$f = $false)
  Get-Content $Path -Tail $n -Wait:$f
}

function nf { param ( $name ) New-Item -ItemType "file" -Path . -Name $name }

function mkcd { param ( $dir ) mkdir $dir -Force; Set-Location $dir }

## Signs PS Scipts locally ##
function Set-Cert {
   param (
        [Parameter ( Mandatory=$true )]
        [string] $scriptPath
    )     
    # Correct the certificate store path
    Set-Location -Path cert:\CurrentUser\My
    # Retrieve the certificate by its thumbprint
    $cert = Get-ChildItem | Where-Object { $_.Thumbprint -eq "75D9BC347BB03DD7DF87AF9B8607C7E3DFD7D591" }
    if ( $null -eq $cert ) {
        Write-Host "Error: Certificate with thumbprint 75D9BC347BB03DD7DF87AF9B8607C7E3DFD7D591 not found" -ForegroundColor Red
        home   
        return
    }
    # Apply the Authenticode signature
    try {
        Set-AuthenticodeSignature -Certificate $cert -FilePath $scriptPath
        Write-Host "Successfully signed the script at $scriptPath" -ForegroundColor Green
        home
    } 
    catch {
        Write-Host "Error signing the script: $_" -ForegroundColor Red
        home   
    }
}
############### SHORTCUTS #####################################
function home { Set-Location -Path $HOME }
function scripts {
    $UserName = whoami 
    if ( "$UserName" -eq "shake-mini\shake" ) {
        Set-Location -Path D:\Documents\PowerShell\Scripts
    }    
    else {    
        Set-Location -Path $HOME\Documents\PowerShell\Scripts 
    }
}
function c { Set-Location -Path C:\ }
function d { Set-Location -Path D:\ }
function dl { 
    $UserName = whoami
    if ( "$UserName" -eq "shake-mini\shake" ) {
        Set-Location -Path D:\Downloads
    }
    else{
        Set-Location -Path $HOME\Downloads 
    }
}
function docs { 
    $UserName = whoami
    if ( "$UserName" -eq "shake-mini\shake" ) {
        Set-Location -Path D:\Documents
    }
    else {
        Set-Location -Path $HOME\Documents 
    }
}
function dtop { Set-Location -Path $HOME\Desktop }

################### Editing and Reload the Profile ##########
function ep { code $PROFILE }

function epv { nvim $PROFILE }

function reloadprofile {
    & $PROFILE
}

################# Enhanced Listing ############
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

################ Git Shortcuts #################
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { __zoxide_z github }

function gcl { git clone "$args" }

function gcom {
    git add .
    git commit -m "$args"
}

function lazyg {
    git add .
    git commit -m "$args"
    git push
}

###########  UTILITIES  ##############
# Open Chris Titus WinUtil
function winutil {
	Invoke-WebRequest -useb https://christitus.com/win | Invoke-Expression
}

########## Junk Files and Ram Clean Up ############
## Starts BleachBit ##
function bb { 
    $BleachbitPath = "$HOME\AppData\Local\BleachBit\bleachbit.exe"
    $UserName = whoami
    if ( $UserName -eq "shake-mini\shake" ) {
        $BleachbitPath = "D:\Program Files\BleachBit\bleachbit.exe"
        }
    Write-Host "Starting BleachBit..." -ForegroundColor DarkCyan
    Start-Process -FilePath $BleachbitPath -Verb RunAs
    return
}
## Starts RAMMap ##
function rammap { 
    Write-Host "Starting RAMMap..." -ForegroundColor DarkCyan
    RAMMap64 
    return
}
## Delete Junk Files ##
function junk {
    $Paths = @(
        "$env:TEMP\*"
        "C:\Windows\Temp\*"
        "C:\Windows\Downloaded Program Files\*"
        "C:\Windows\Prefetch\*"
        "C:\ProgramData\Microsoft\Windows\WER\*"
        "C:\Windows\Minidump\*"
        "$env:LOCALAPPDATA\Temp\*"
        "$HOME\AppData\Local\Microsoft\Windows\INetCache\*"
        "$HOME\AppData\LocalLow\Sun\Java\Deployment\cache\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache2\entries\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Media Cache"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies-Journal"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Application Cache\Cache\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\ShaderCache\*"
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network Action Predictor\*"
        "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2\entries\*"
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite"
        "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\offlineCache\*"
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\sessionstore-backups\*"
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\formhistory.sqlite"
        "$env:APPDATA\Mozilla\Firefox\Crash Reports\*"
        "$env:LOCALAPPDATA\Mozilla\Firefox\Crash Reports\pending\*"
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\content-prefs.sqlite"
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\security_state"    
    )   
    Write-Host "Deleting Junk Files from: " -ForegroundColor DarkCyan 
    Foreach ( $Path in $Paths ) {
        Write-Host "    $Path " -ForegroundColor Cyan
        Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | 
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    try {
        Stop-Process -Name WinStore.App -ErrorAction SilentlyCont
        $cachePath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*"
        Get-ChildItem -Path $cachePath -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Process -Name WinStore.App 
    }
    catch {
        Write-Host "Could not Delete: $Path" -ForegroundColor Cyan
    }
    # Delete the contents of the SoftwareDistribution folder, suppress errors
    try {
        $cachePath = "C:\Windows\Microsoft\Windows\SoftwareDistribution\Download\*"
        Stop-Service -Name wuauserv -ErrorAction SilentlyContinue 
        Get-ChildItem -Path $cachePath -Recurse -ErrorAction SilentlyContinue | 
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } 
    catch {
        Write-Host "Could not Delete Software Distribution Download folder" -ForegroundColor Cyan
    }
    Write-Host "Junk Files Deleted." -ForegroundColor Green
    return
}
## Delete Junk Files, Open RamMap and BleachBit  ##
function cleanjunk {
    bb
    rammap
    junk
    flushdns
}
## Starts HW Monitor and Cinebench ##
function bench {
    Write-Host "Starting HW Monitor and Cinebench..." -ForegroundColor Yellow
    $UserName = whoami
    $HWMonPath = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe"
    $CineBenchPath = "$HOME\AppData\Local\Microsoft\WinGet\Packages\Maxon.CinebenchR23_Microsoft.Winget.Source_8wekyb3d8bbwe\Cinebench.exe"
    
    if ( $UserName -eq "shake-mini\shake" ) {
        $CineBenchPath = "D:\Program Files\CinebenchR23\Cinebench.exe"
        $HWMonPath = "D:\Program Files\hwmonitor\HWMonitor.exe"
    }
    Start-Process -FilePath $HWMonPath -Verb RunAs
    Start-Process -FilePath $CineBenchPath -Verb RunAs
    return
}
##########   UPDATES   ##########
### Update PowerShell ##
function psup {
    try {
        Write-Host "Checking for PowerShell Updates..." -ForegroundColor DarkCyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ( $currentVersion -lt $latestVersion ) {
            $updateNeeded = $true
        }
        if ( $updateNeeded ) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated." -ForegroundColor Green
            Write-Host "Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Current PowerShell Version:  $currentVersion" -ForegroundColor Yellow
            Write-Host "PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_" -ForegroundColor DarkRed
    }
    return
}
## Update Winget ##
function winup {
    if ( -not ( Get-Command winget -ErrorAction SilentlyContinue )) {
        Write-Host "Winget is not installed. Installing Winget now..." -ForegroundColor DarkCyan
        $installerUrl = "https://aka.ms/getwinget"
        $tempInstallerPath = "$env:TEMP\winget_installer.msixbundle"
        try {
            Invoke-WebRequest -Uri $installerUrl -OutFile $tempInstallerPath -ErrorAction Stop        
            Start-Process -FilePath $tempInstallerPath -Wait -ArgumentList "/quiet"
            Write-Host "Winget installation completed successfully." -ForegroundColor Green
        } 
        catch {
            Write-Host "Failed to install Winget. Please download and install it manually from the Microsoft Store." -ForegroundColor DarkRed
        }
        return
    }
    Write-Host "Checking Winget for Updates..." -ForegroundColor DarkCyan
    $wingetUpgrade = winget upgrade winget
    $wingetVersion = winget --version
    if ( $wingetUpgrade -like "*No available upgrade found*" ) {
        Write-Host "Current Winget version: $wingetVersion" -ForegroundColor Yellow
        Write-Host "Winget is up to date." -ForegroundColor Green
        return
    }
    try {
        Write-Host "Updating Winget..." -ForegroundColor Yellow
        winget upgrade winget --accept-package-agreements --accept-source-agreements --silent
        Write-Host "Winget updated successfully." -ForegroundColor Green
        Write-Host "Current Winget version: $wingetVersion" -ForegroundColor Yellow
        return    
    }
    catch {
        Write-Host "Failed to update Winget. Please update it manually." -ForegroundColor DarkRed   
        return
    }
}
## Check all apps for upgrades ##
function winupall {
    Write-Host "Checking for app updates via Winget..." -ForegroundColor DarkCyan
    $wingetUpdates = Get-WinGetPackage | Where-Object IsUpdateAvailable | Select-Object Name, Id
    if ( -not $wingetUpdates ) {
        Write-Host "All packages are up to date." -ForegroundColor Green 
        return       
    }
    try {
        $wingetUpdateNames = $wingetUpdates | Select-Object -ExpandProperty Name
        $wingetUpdateIds = $wingetUpdates | Select-Object -ExpandProperty Id
        Write-Host "Attempting to Update the following Packages via Winget:" -ForegroundColor Yellow
        Write-Output $wingetUpdateNames 
        $wingetUpdateArgs = @(
            "--accept-package-agreements"
            "--accept-source-agreements"
            "--silent"
            "--force" 
        )
        Foreach ( $wingetUpdateId in $wingetUpdateIds ) {
            winget upgrade --id $wingetUpdateId @wingetUpdateArgs 
        }
        Write-Host "All updates have been installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to update some packages. Please update them manually." -ForegroundColor DarkRed
    }
    return
}
## Update Windows ##
function windowup {
    if ( -not ( Get-Module -ListAvailable -Name PSWindowsUpdate )) {
        Write-Host "PSWindowsUpdate module not found. Installing..." -ForegroundColor Green
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
    }
    Write-Host "Checking for Windows Updates..." -ForegroundColor DarkCyan
    Import-Module PSWindowsUpdate
    $updates = Get-WindowsUpdate 
    if ( -not $updates ) {
        Write-Host "Windows is up to date." -ForegroundColor Green
        return
    }
    Write-Host "The following updates will be installed:" -ForegroundColor Yellow
    $updates | Format-Table -Property Title, Size, KBArticleIDs
    Write-Host "Installing Windows updates..." -ForegroundColor DarkCyan
    Write-Host "The computer may restart automatically." -ForegroundColor DarkYellow
    Install-WindowsUpdate -AcceptAll -AutoReboot
    Write-Host "Windows has been updated." -ForegroundColor Green
    return    
}
## Update PowerShell Modules ##
function PSModuleUpdate {
    Write-Host "Attempting to update the following PowerShell Modules:" -ForegroundColor DarkCyan
    $Modules = Get-PSResource | Where-Object Name -NotLike "*Azure*" | Select-Object Name
    Foreach ( $Module in $Modules) {
        Write-Host "    $($Module.Name)" -ForegroundColor Cyan
        Update-PSResource -Name $Module.Name -Force
    }
    Write-Host "PowerShell Modules have been updated." -ForegroundColor Green
    return
}
## Update PowerShell, Winget, Programs and Windows ##
function ud {
    psup
    winup
    winupall
    PSModuleUpdate
    windowup
}
###################
##  Virus Scan  ##
function dvs {    
    Update-MpSignature -UpdateSource MicrosoftUpdateServer
    Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor DarkCyan
    # Start a quick scan
    $scanResult = Start-MpScan -ScanType QuickScan
    $scanResult | Wait-Job    
    # Get scan results
    $scanResults = Get-MpThreatDetection
    Write-Host "Scan Complete..." -ForegroundColor Green
    if ( $scanResults ) {
        Write-Host "Threats Detected:" -ForegroundColor DarkRed
        Get-MPThreatDetection
        return
    }  
    Write-Host "No threats detected by Windows Defender." -ForegroundColor Green
    return               
}
## Start Malwarebytes ##
function mwb {
    Write-Host "Starting Malwarebytes..." -ForegroundColor DarkCyan
    Start-Process -FilePath "D:\Program Files\Malwarebytes\Malwarebytes.exe" -Verb RunAs
    return
}
## Virus Scan with Malwarebytes ##
function vscan {
    $UserName = whoami
    if ( "$UserName" -eq "shake-mini\shake" ) { mwb } 
    dvs
}
###############################################################################
# Winget with FZF search and select
###############################################################################
## WingetInstall with FZF ##
function winpick {
    param ( $WingetCommand )
    Clear-GlobalAppVariables
    # Prompt for a package name if $WingetCommand is not provided
    if ( -not $WingetCommand ) {
        Write-Host "Enter Package To Search For:" -ForegroundColor DarkCyan
        $PackName =  Read-Host
        $WingetCommand = Find-WingetPackage $PackName
    }
    # Create a custom object list using Add-Member
    $AppObject = $WingetCommand | ForEach-Object {
        $app = New-Object PSObject
        $app | Add-Member -MemberType NoteProperty -Name 'Name'              -Value $_.Name
        $app | Add-Member -MemberType NoteProperty -Name 'Id'                -Value $_.Id
        $app | Add-Member -MemberType NoteProperty -Name 'Source'            -Value $_.Source
        $app | Add-Member -MemberType NoteProperty -Name 'IsUpdateAvailable' -Value $_.IsUpdateAvailable
        $app | Add-Member -MemberType NoteProperty -Name 'AvailableVersions' -Value (($_.AvailableVersions | Select-Object -First 5) -join ', ')
        if ($_.Version) {
            $app | Add-Member -MemberType NoteProperty -Name 'Version'       -Value $_.Version 
        }
        elseif ($_.InstalledVersion) {
            $app | Add-Member -MemberType NoteProperty -Name 'Version'       -Value $_.InstalledVersion
        }
        $app
    }
    # Prepare a fixed-width format for fzf
    $formattedAppList = $AppObject | ForEach-Object {
        '{0,-70} {1,-20} {2 }' -f $_.Name, $_.Version, $_.Id
    }
    # Select an app via fzf
    $selectId = $formattedAppList | fzf --prompt=" Select a package: "
    if ( $selectId ) {
        # Parsing selection
        $selectId = $selectId -replace '┬«', '®' -replace 'ΓÇô', '-' -replace 'ΓÇª', ' '
        $selectAppId = $selectId.Substring(90).Trim()
        # Filter selected AppObject
        $selectApp = $AppObject | Where-Object { 
            ( $_.Id -eq $selectAppId ) 
        }
        # Set global variables with selected app information
        $selectApp | ForEach-Object {
            $Global:AppName      = $_.Name 
            $Global:AppVersion  = $_.Version 
            $Global:AppId       = $_.Id
            $Global:AppInfo     = "$Global:AppName  (Id: $Global:AppId | Version: $Global:AppVersion)"
        }
        Write-Host "You selected:" -ForegroundColor DarkCyan
        $Global:FullAppInfo = $selectApp | Format-List   
        Write-Host "$Global:AppInfo" -ForegroundColor DarkGreen
        $Global:FullAppInfo
    }
    return
}
function winshow {
    $wingetAppInfo = winget show --Id $Global:AppId --accept-source-agreements
    if ( $wingetAppInfo -Like '*No package found matching input criteria.*') {
        $wingetAppInfo = winget show --Name $Global:AppName --Version $Global:AppVersion --accept-source-agreements
    }
    Write-Output $wingetAppInfo
    return
}

function winlist {
    Write-Host "These programs are isntalled.  Select a Package for More Info." -ForegroundColor DarkCyan
    $PackList = Get-WinGetPackage
    winpick $PackList
    winshow
    Clear-GlobalAppVariables
}

function winin {
    param (
        [string]$PackName
    )
    if ( -not $PackName ) {
    Write-Host "Enter Program to Install:" -ForegroundColor Cyan
    $PackName = Read-Host
    }
    $PackId = Find-WinGetPackage $PackName 
    if ( -not $PackId ) {
        Write-Host "No Packages found." -ForegroundColor Red
        return
    }
    winpick $PackId
    if  ( -not $Global:AppName ) {
        Write-Host "No Package Selected." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
    }
    Write-Host "Enter [y] to show more info about $Global:AppName." -ForegroundColor DarkCyan
    $MoreInfo = Read-Host
    if ( $MoreInfo -match '^[Yy]$' ) {
        winshow
    }
    Write-Host "Install $Global:AppName [y] or [n]?" -ForegroundColor Magenta
    $YorN = Read-Host
    if ( $YorN -NotMatch '^[Yy]$' ) {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
    }
    $UserName = whoami    
    if ( $UserName -ne "shake-mini\shake" ) { 
        StandardInstall 
        return
    }
    InstallChoice
    return            
}
## Standard Winget Installation ##
function StandardInstall {
    $wingetInstallArgs = @(
        "--accept-package-agreements"
        "--accept-source-agreements"
        "--disable-interactivity"
        "--silent"
    )
    try {
        Write-Host "Installing $Global:AppName..." -ForegroundColor Yellow
        winget install --id $Global:AppID $wingetInstallArgs
        Write-Host "$Global:AppInfo installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not install $Global:AppInfo with winget. Error: $_" -ForegroundColor Red
    }
    finally {
        Clear-GlobalAppVariables
    }
    return
}
## Option to install on D-Drive ##
function InstallChoice {
    Write-Host "Please choose an Option for $Global:AppInfo :" -ForegroundColor DarkYellow
    Write-Host "  1. Standard winget installation." -ForegroundColor Green
    Write-Host "  2. Create new folder "$Global:AppName" in 'D:\Program Files'" -ForegroundColor Cyan
    Write-Host "  3. Do Not Install $Global:AppName" -ForegroundColor Red
    $InstallOption = Read-Host 
    if ( $InstallOption -eq '1' ) {
        StandardInstall
    }
    if ( $InstallOption -eq '2' ) {            
        try {
            $InstallPath = "D:\Program Files\$Global:AppName"
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
            Write-Host "New folder created: $InstallPath" -ForegroundColor DarkCyan
            Write-Host "Opening $InstallPath check for successful operation." -ForegroundColor Yellow
            Start-Process explorer.exe -ArgumentList "$InstallPath"
            Write-Host "Installing $Global:AppName..." -ForegroundColor Yellow
            $wingetChoiceArgs = @(
                "--accept-package-agreements"
                "--accept-source-agreements"
                "--disable-interactivity"
                "--silent"
            )
            winget install --id $Global:AppID --location $InstallPath $wingetChoiceArgs
            Write-Host "$Global:AppInfo installed successfully." -ForegroundColor Green             
        }
        catch {
            Write-Host "Could not install $Global:AppInfo with winget. Error: $_" -ForegroundColor Red
        }
        finally {
            Clear-GlobalAppVariables
        }
        return
    }
    else {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
    }
}
## Winget Uninstall with FZF ##
function winun {
    Write-Host "Select a Package to Uninstall:" -ForegroundColor Yellow
    $PackId = Get-WinGetPackage
    if ( -not $PackId ) {
        Write-Host "No valid package selected." -ForegroundColor DarkRed
        return
    }
    winpick $PackId
    if  ( -not $Global:AppName ) {
        Write-Host "No Package Selected." -ForegroundColor DarkRed
        Clear-GlobalAppVariables
        return
    }
    Write-Host "Uninstall  $Global:AppName [y] or [n]?" -ForegroundColor DarkRed
    $YorN = Read-Host
    if ( $YorN -match '^[Yy]$' ) {
        $wingetUninstallArgs = @(
            "--accept-source-agreements"
            "--disable-interactivity"                            
            "--silent"
            "--purge"
            "--force"
        )
        try {
            if ( $Global:AppId -like 'ARP/*' -or  $Global:AppId -like 'MSIX/*' ) {
                winget uninstall --id $Global:AppID --all-versions $wingetUninstallArgs
                Write-Host "$Global:AppInfo uninstalled successfully." -ForegroundColor Green
            }
            else {
                winget uninstall --id $Global:AppID $wingetUninstallArgs 
                Write-Host "$Global:AppInfo uninstalled successfully." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Unable to Uninstall: " -ForegroundColor DarkRed
            Write-Host $Global:FullAppInfo
            Write-Host "Error: $_" -ForegroundColor DarkRed
        }
    }
    else {
        Write-Host "$Global:AppInfo is still installed." -ForegroundColor DarkCyan
    }
    Clear-GlobalAppVariables
    return
}
function Clear-GlobalAppVariables {
    $GlobalVariables = @(
        "AppName",
        "AppID",
        "AppVersion",
        "AppInfo",
        "FullAppInfo"
        )
    Remove-Variable -Name $GlobalVariables -Scope Global -ErrorAction SilentlyContinue
}

############# Oh-My-Posh Theme fzf selection ######
# Set Oh-My-Posh Theme 
function SetOmpTheme {
    param ()
    [string] $OmpTheme 
    $OmpThemeLocation = "$env:LOCALAPPDATA\Programs\oh-my-posh\themes"
    $OmpThemePath = Join-Path $OmpThemeLocation $OmpTheme
    $FZFThemePath = Test-Path $OmpThemePath
    if (( -not $FZFThemePath ) -or ( $OmpTheme -eq "" )) {
        Write-Host "$OmpTheme not found." -ForegroundColor Red
        Write-Host "Select another Oh-My-Posh Theme." -ForegroundColor DarkYellow
        ChangePoshTheme        
    }
    oh-my-posh init pwsh --config $OmpThemePath | Invoke-Expression
    return
}

function ChangePoshTheme {
    $ThemePath = "$env:LOCALAPPDATA\Programs\oh-my-posh\themes"
    $NewTheme = Get-ChildItem "$ThemePath" | Select-Object Name | fzf
    if ( -not $NewTheme ) {
        Write-Host "No theme selected." -ForegroundColor DarkRed
        return
    }
    ChangeOmpThemeInProfile "$NewTheme"
    & $PROFILE
    Clear-Host
    Write-Host "Theme Set to $NewTheme" -ForegroundColor Green
    Write-Host "Profile Location: $PROFILE " -ForegroundColor Yellow
    return
}

function ChangeOmpThemeInProfile {
    param ()
    [string] $NewTheme    
    $ProfilePath = $PROFILE
    $OmpThemeInProfile = '(?<=\$OmpTheme\s=\s")[^"]+'
    $profileContents = Get-Content -Path $ProfilePath -Raw
    if ( $profileContents -notmatch $OmpThemeInProfile ) {
        Write-Host "Could not find OmpTheme variable in the profile." -ForegroundColor Red
        return
    }
    $updatedContents = $profileContents -replace $OmpThemeInProfile, $NewTheme
    Set-Content -Path $ProfilePath -Value $updatedContents
    return
} 
    
############# System Information ##################
function sysinfo { Get-ComputerInfo }

function uptime {
    if ( $PSVersionTable.PSVersion.Major -eq 5 ) {
        Get-WmiObject win32_operatingsystem | 
            Select-Object @{Name='LastBootUpTime';
            Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | 
            Format-Table -HideTableHeaders
    } else {
        net statistics workstation | 
            Select-String "since" | 
            ForEach-Object { $_.ToString().Replace('Stat istics since ', '') }
    }
}
###################################################
############# Network Utilities ###################
## Get IP Address ##
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }
## Flush DNS ##
function flushdns {
	Clear-DnsClientCache
	Write-Host "DNS has been flushed" -ForegroundColor Green
}
## Shows DNS Servers ##
function showdns {
    Get-DnsClientServerAddress | 
    Where-Object { $_.InterfaceAlias -like "Wi-Fi" } | 
    Select-Object @{ Name = 'InterfaceIndex';
        Expression = { [string]$_.InterfaceIndex }},
        @{ Name = 'AddressFamily'; 
        Expression = {if ($_.AddressFamily -eq 23) {"IPv6"} else {"IPv4"}}},
        @{ Name = 'ServerAddresses'; 
        Expression = { $_.ServerAddresses -join ', ' }}
}
## Reset Network ##
function ReNet {
    ipconfig /release
    flushdns
    ipconfig /renew
    netsh int ip reset
    netsh winsock reset    
    # Prompt the user to restart
    $restart = Read-Host "TCP/IP stack has been reset. Do you want to restart now? (Y/N)"
    if ( $restart -match '^[Yy]$' ) {
        Restart-Computer
    } 
    else {
    Write-Host "Please remember to restart the computer for changes to take effect." -ForegroundColor Yellow
    }
}
## Establish preconfigured WinRM Session  ##
function rem {
    param ( 
        [string] $CpuName 
    )
    if ( -not $CpuName ){
        Write-Host "Enter ComputerName:" -ForegroundColor DarkCyan
        $CpuName = Read-Host
    }
    Write-Host "Provide your Log-In Credentials for $CpuName :" -ForegroundColor DarkCyan
    $cred = Get-Credential
    Write-Host "Starting Remote Session with $CpuName..." -ForegroundColor Yellow
    $sessionParams = @{
        ComputerName       = $CpuName
        Credential         = $cred
        Authentication     = "CredSSP"
        ConfigurationName  = "PowerShell.7"
        ErrorAction        = "Stop"
    }

    try {
        Enter-PSSession @sessionParams
    }
    catch {
        Write-Host "Could not connect to $CpuName." -ForegroundColor Red
    }
}
################################################## 
############  Remove items from PowerShell History
## Remove Items from PSReadLine History 
function Remove-PSReadlineHistory {
    param (
        [Parameter ( Mandatory = $true )]
        [string] $Pattern
    )

    $historyPath = (Get-PSReadLineOption).HistorySavePath
    $historyLines = [System.IO.File]::ReadAllLines($historyPath)
    $filteredLines = $historyLines | Where-Object { $_ -notmatch $Pattern }
    [System.IO.File]::WriteAllLines($historyPath, $filteredLines)

    Write-Host "Removed $($historyLines.Count - $filteredLines.Count) line(s) from PSReadLine history."
}
## Removes Items PSHistory
function Remove-PSHistory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )
    
    $historyLines = Get-History
    $matchingLines = $historyLines | Where-Object { $_.CommandLine -match $Pattern }
    $matchingLines | ForEach-Object { Clear-History -Id $_.Id }
     Write-Host "Removed $($matchingLines.Count) line(s) from PowerShell history."
}
## Removes Items from PSHistory and PSReadlineHistory simultaneosly ##
function rehis {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    Remove-PSReadlineHistory -Pattern $Pattern
    Remove-PSHistory -Pattern $Pattern
}
################ Clipboard Utilities ##########################
## Copy ##
function cpy { Set-Clipboard $args[0] }
## Paste ##
function pst { Get-Clipboard }
#######################################################################################
############### CALL PSInit in your Profile Script to start this section ##############
############### SETUP MODULES #################################
## Install Modules ##
function ModInstall {
    $modName = @(
        "PowerShellGet"
        "DnsClient"
        "Terminal-Icons"
        "PSReadLine"
        "PSFzf"
        "Microsoft.Winget.Client"
    )
    Foreach ( $mod in $modName) {
    if ( -not ( Get-Module -ListAvailable -Name $mod )) {
        Install-Module -Name $mod -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module -Name $mod
    }        
    Invoke-FuzzyFasd
    Invoke-FuzzyZLocation
    Set-LocationFuzzyEverything
    Invoke-FzfTabCompletion

    $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if ( Test-Path ( $ChocolateyProfile )) {
        Import-Module "$ChocolateyProfile"
    }
}
## PS ReadLine Setup ##
function PSRLsetup {
    Set-PSReadLineOption -Colors @{
        Emphasis = 'Green'
        Command = 'DarkYellow'
        Parameter = 'Magenta'
        String = 'Blue'
        Comment = 'DarkGray'
        Keyword = 'DarkMagenta'
        Number = 'Yellow'
        Operator = 'DarkRed'
        Variable = 'Cyan'
        Type = 'DarkBlue'
        Error = 'Red'    
        Selection = 'White'
    }
    if ( $PSVersionTable.PSVersion.Major -eq 7 ) {
        Set-PSReadLineOption -Colors @{
            ListPrediction = 'DarkGreen'
            Selection = "$($PSStyle.Background.Blue)$($PSStyle.Foreground.White)"
            InlinePrediction = $PSStyle.Foreground.BrightYellow + $PSStyle.Background.BrightBlack
        }
        if ( -not ( Get-Module -ListAvailable -Name CompletionPredictor )) {
            Install-Module -Name CompletionPredictor -Scope CurrentUser -Force -SkipPublisherCheck
        }
        Set-PSReadLineOption -PredictionSource HistoryAndPlugin
        Set-PSReadLineOption -PredictionViewStyle ListView        
    }
    
    Set-PSReadLineKeyHandler -Chord 'Enter' -Function ValidateAndAcceptLine
    Set-PSReadLineOption -EditMode Windows
    Set-PSReadLineOption -BellStyle None
    Set-PSReadLineOption -HistorySearchCursorMovesToEnd:$True
    Set-PSReadLineKeyHandler -Key Tab -ScriptBlock { Invoke-FzfTabCompletion }
    Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
    #####
    Register-ArgumentCompleter -Native -CommandName '*' -ScriptBlock {
        param ( $commandName, $wordToComplete, $cursorPosition )
        Invoke-CompletionPredictor -WordToComplete $wordToComplete -CursorPosition $cursorPosition
    }
}
## Setup Zoxide ##
function ZoxSetUp {
    if ( Get-Command zoxide -ErrorAction SilentlyContinue ) {
        Invoke-Expression (& { ( zoxide init powershell | Out-String ) }) 
    } 
    else {
        Write-Host "zoxide command not found. Attempting to install via winget..." -ForegroundColor DarkCyan
        try {
            winget install -e --id ajeetdsouza.zoxide
            Write-Host "zoxide installed successfully. Initializing..." -ForegroundColor Green
            Invoke-Expression (& { (zoxide init powershell | Out-String) })
        }
        catch {
            Write-Error "Failed to install zoxide. Error: $_" -ForegroundColor Red
        }
    }
}
## Set Aliases ##
function AliasSetup {
    #Set aliases for NeoVim
    Set-Alias -Name vi -Value nvim -Option AllScope -Scope Global -Force
    Set-Alias -Name vim -Value nvim -Option AllScope -Scope Global -Force
    # Set UNIX-like aliases for the admin command, so sudo <command> will run the command with elevated rights.
    Set-Alias -Name su -Value admin -Option AllScope -Scope Global -Force
    # Set aliases for Zoxide
    Set-Alias -Name z -Value __zoxide_z -Option AllScope -Scope Global -Force
    Set-Alias -Name zi -Value __zoxide_zi -Option AllScope -Scope Global -Force
    Set-Alias -Name cd -Value z -Option AllScope -Scope Global -Force
}
## Calls Initialization functions ##
function PSInit {
    ModInstall
    PSRLsetup
    ZoxSetUp
    AliasSetup
}
###############################################################################
Write-Host "Use 'listcom' to show list of commands" -ForegroundColor DarkYellow
function listcom { @"
PowerShell Profile Help
=======================

Test-CommandExits - Test if "command" exists.

touch <file> - Creates a new empty file.

ff <name> - Finds files recursively with the specified name.

unzip <file> - Extracts a zip file to the current directory.

grep <regex> [dir] - Searches for a regex pattern in files within the specified directory or from the pipeline input.

df - Displays information about volumes.

far <file> <find> <replace> - Replaces text in a file.

which <name> - Shows the path of the command.

export <name> <value> - Sets an environment variable.

k9 <name> - Kills a process by name.

pkill <name> - Kills processes by name.

pget <name> - Lists processes by name.

head <path> [n] - Displays the first n lines of a file (default 10).

tail <path> [n] - Displays the last n lines of a file (default 10).

nf <name> - Creates a new file with the specified name.

mkcd <dir> - Creates and changes to a new directory.

Set-Cert <path> - Sets the certificate on the script at 'path\to\script.ps1'

home - to Sets the current directory to - $HOME.

Scripts- to Sets the current directory to - $PSHOME\Scripts

c - to Sets the current directory to - C:\

d - to Sets the current directory to - D:\

dl- to Sets the current directory to - $HOME\Downloads

docs - to Sets the current directory to - $HOME\Documents

dtop - to Sets the current directory to - $HOME\Desktop

ep - Opens $PROFILE for editing with VSCode.

epv - Opens the $PROFILE for editing with NeoVim.

reloadprofile - Reloads $PROFILE

la - Lists all files in the current directory with detailed formatting.

ll - Lists all files, including hidden, in the current directory with detailed formatting.

gs - Shortcut for 'git status'.

ga - Shortcut for 'git add .'.

gc <message> - Shortcut for 'git commit -m'.

gp - Shortcut for 'git push'.

g - Changes to the GitHub directory.

gcl - Changes to the GitHub Clone directory.

gcom <message> - Adds all changes and commits with the specified message.

lazyg <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.

winutil - Runs the WinUtil script from Chris Titus Tech.

junk - Deletes Temporary Files

rammap - Opens the RAMMap.

bb - Opens BleachBit.

cleanjunk - Deletes Temporary File, Opens BleachBit, and RAMMap.

bench - Opens HW Monitior and Cinebench R23

ud - Checks PowerShell, winget and windows for updates and installs any updates found.

psup - Checks PowerShell for updates and installs any updates found.

winup - Checks Winget and Packages for updates and installs any updates found.

windowup - Checks Windows for updates and installs any updates found.

vscan - Opens Malwarebytesa and runs a Defender Quick Scan

dvs - Runs Defender Quick Scan

winpick - Search for Package with winget using FZF

winlist - Show installed Packages with FZF

winin - Searh for and install Package with winget using FZF

winun -  Uninstall Package with winget using FZF

ChangePoshTheme - Select New Oh-My-Posh Theme with FZF

sysinfo - Displays detailed system information.

uptime - Displays the system uptime.

Get-PubIP - Retrieves the public IP address of the machine.

flushdns - Clears the DNS cache.

showdns - Shows the current DNS cache.

ReNet - Resets Network, requires restart to take effect.

rem <ComputerName> - Starts preconfigured WinRm session with 'ComputerName'

rehis <String> - Removes command from PSReadLine and PS History

cpy <text> - Copies the specified text to the clipboard.

pst - Retrieves text from the clipboard.

ZoxSetUp - Sets up Zoxide.

ModInstall - Downloads and Installs required Modules.

PSRLsetup - Sets up PSReadLine.

AliasSetup - Sets Aliases.

PSInit - Runs: ZoxSetUp, ModInstall, PSRLsetup and AliasSetup.

Get-PoshThemes - List of available Oh My Posh! themes.

rmbb - Starts BleachBit and RAMMap.

bench - Starts Cinbench and monitors.


Use 'listcom' to display this help message.
"@
}

##################################################################
##################################################################
##################################################################

