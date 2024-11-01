#################################################################################################################################
############                        SHAKE'S PowerShell Module                        ############
#################################################################################################################################

################### System Utilities #############################
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

function touch($file) { "" | Out-File $file -Encoding ASCII }

function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function far($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function k9 { Stop-Process -Name $args[0] }

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pget($name) {
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

function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

## Signs PS Scipts locally ##
function Set-Cert {
   param(
        [Parameter(Mandatory=$true)]
        [string]$scriptPath
    )     
    # Correct the certificate store path
    Set-Location -Path cert:\CurrentUser\My
    # Retrieve the certificate by its thumbprint
    $cert = Get-ChildItem | Where-Object { $_.Thumbprint -eq "75D9BC347BB03DD7DF87AF9B8607C7E3DFD7D591" }
    if ($null -eq $cert) {
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
    if ("$UserName" -eq "shake-mini\shake") {
        Set-Location -Path D:\Documents\PowerShell\Scripts
    }    
    else {    
        Set-Location -Path $HOME\Documents\WindowsPowerShell\Scripts 
    }
}
function c { Set-Location -Path C:\ }
function d { Set-Location -Path D:\ }
function dl { 
    $UserName = whoami
    if ("$UserName" -eq "shake-mini\shake") {
        Set-Location -Path D:\Downloads
    }
    else{
        Set-Location -Path $HOME\Downloads 
    }
}
function docs { 
    $UserName = whoami
    if ("$UserName" -eq "shake-mini\shake") {
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
    foreach ($Path in $Paths) {
        Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Stop any running Microsoft Store processes
    try {
        Stop-Process -Name WinStore.App -ErrorAction SilentlyCont
        $cachePath = "$env:LocalAppData\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache"
        Remove-Item -Path $cachePath\* -Recurse -Force        
    }
    catch {
        # Suppress errors, do nothing
    }
    # Delete the contents of the SoftwareDistribution folder, suppress errors
    Try {
        Stop-Service -Name wuauserv -ErrorAction SilentlyContinue 
        Get-ChildItem -Path 'C:\Windows\SoftwareDistribution\Download\*' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } 
    Catch {
        # Suppress errors, do nothing
    }
    Write-Host "Junk Files Deleted." -ForegroundColor Green
}
## Update PowerShell, Winget, Programs and Windows ##
function ud {
    psup
    wgetup
    winup
}
function psup {
    try {
        Write-Host "Checking for PowerShell Updates..." -ForegroundColor Blue
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }
        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_" -ForegroundColor DarkRed
    }
}
function wgetup {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget is not installed. Installing Winget now..." -ForegroundColor Blue
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
    Write-Host "Checking Winget for Updates..." -ForegroundColor Blue
    $wingetVersion = winget --version
    $wingetUpdateAvailable = winget upgrade --source winget | Where-Object { $_ -match "winget" }
    if ($wingetUpdateAvailable) {
        Write-Host "Updating Winget..." -ForegroundColor Blue
        try {
            winget upgrade winget --silent
            Write-Host "Winget updated successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to update Winget. Please update it manually." -ForegroundColor DarkRed
        }
    }
    else {
        Write-Host "Current Winget version: $wingetVersion" -ForegroundColor Yellow 
        Write-Host "Winget is up to date." -ForegroundColor Green       
    }  

    # Check all apps for upgrades
    Write-Host "Checking for app updates via Winget..." -ForegroundColor Blue
    $wingetUpdates = winget upgrade --source winget
    if ($wingetUpdates -match "No installed packages found") {
        Write-Host "All packages are up to date." -ForegroundColor Green        
    }
    else {
        Write-Host "The following updates will be installed via Winget:" -ForegroundColor Yellow
        try {
            winget upgrade --all
            Write-Host "All updates have been installed successfully." -ForegroundColor Green
        } 
        catch {
            Write-Host "An error occurred while installing updates." -ForegroundColor DarkRed
        }
    }
}
function winup {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "PSWindowsUpdate module not found. Installing..." -ForegroundColor Green
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
    }
    Write-Host "Checking for Windows Updates..." -ForegroundColor Blue
    Import-Module PSWindowsUpdate
    $updates = Get-WindowsUpdate 
    if ($updates) {
        Write-Host "The following updates will be installed:" -ForegroundColor Yellow
        $updates | Format-Table -Property Title, Size, KBArticleIDs
        Write-Host "Installing Windows updates..." -ForegroundColor Blue
        Write-Host "The computer may restart automatically." -ForegroundColor DarkRed
        Install-WindowsUpdate -AcceptAll -AutoReboot
    }
    else {
        Write-Host "Windows is up to date." -ForegroundColor Green
    }
}

##  Virus Scan  ##
function vscan {
    # Start Malwarebytes with elevated privileges
    $UserName = whoami
    if ("$UserName" -eq "shake-mini\shake") {
        Start-Process -FilePath "D:\Program Files\Malwarebytes\Malwarebytes.exe" -Verb RunAs
        Write-Host "Starting MalwareBytes..." -ForegroundColor Yellow
    }
    dvs
}
function dvs {    
    Update-MpSignature -UpdateSource MicrosoftUpdateServer
    Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor Blue
    # Start a quick scan
    $scanResult = Start-MpScan -ScanType QuickScan
    $scanResult | Wait-Job    
    # Get scan results
    $scanResults = Get-MpThreatDetection
    Write-Host "Scan Complete..." -ForegroundColor Green
    if ($scanResults) {
        Write-Host "Threats Detected:" -ForegroundColor DarkRed
        Get-MPThreatDetection
    }  
    else {
        Write-Host "No threats detected by Windows Defender." -ForegroundColor Green
    }               
}
###############################################################################
# Winget with FZF search and select
###############################################################################
## WingetInstall with FZF ##
function winselect {
    param ( $WingetCommand
        )
    $packages = $WingetCommand | ForEach-Object {
        [PSCustomObject]@{
            Name               = $_.Name
            Id                 = $_.Id
            Version            = $_.Version
            InstalledVersion   = $_.InstalledVersion 
            IsUpdateAvailable  = $_.IsUpdateAvailable
            Source             = $_.Source
            AvailableVersions  = ($_.AvailableVersions | Select-Object -First 5) -join ', '
        }
    }

    $formattedPackages = $packages | ForEach-Object {
        if ($_.Version){
            "$($_.Name)`t`t-- $($_.Version)`t`t--$($_.Id)"
        }
        if ($_.InstalledVersion) {
        "$($_.Name)`t`t--$($_.InstalledVersion)`t`t--$($_.Id)"
        }
    }

    $selectedApp = $formattedPackages | fzf --prompt="Select a package: "
    
    if ($selectedApp) {
        $selectedId = $selectedApp -split "`t`t--" | Select-Object -Last 1
        $selectedApp = $packages | Where-Object { $_.Id -eq $selectedId }
    
        $selectedApp | ForEach-Object {
            $Global:AppName = $($_.Name) 
            $Global:AppVersion = $($_.InstalledVersion ?? $_.Version) 
            $Global:AppId = $($_.Id)
            $Global:AppInfo = "$Global:AppName  (Id: $Global:AppId | Version: $Global:AppVersion)"
        }
    Write-Output "You selected:"
    $Global:FullAppInfo = $selectedApp | Format-List   
    Write-Output $Global:FullAppInfo
    }
    return
}
function winin {
    Write-Host "Enter Program to Install:" -ForegroundColor Cyan
    $PackName = Read-Host
    $PackID = Find-WinGetPackage $PackName 
    if (-not $PackID) {
        Write-Host "No Packages found." -ForegroundColor Red
        return
    }
    winselect $PackID
    if  (-not $Global:AppName) {
        Write-Host "No Package Selected." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
        }
    Write-Host "Install [y] or [n]?" -ForegroundColor Magenta
    $YorN = Read-Host
    if ($YorN -match '^[Nn]$') {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
    }
    elseif  ( $YorN -match '^[Yy]$') { 
        $UserName = whoami    
        if ($UserName -eq "shake-mini\shake") {
            InstallChoice 
        }
        else { 
            StandardInstall 
        }        
    }
    else {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
        Clear-GlobalAppVariables
        return
    }
}
## Standard Winget Installation ##
function StandardInstall {
    try {
        Write-Host "Installing $Global:AppName..." -ForegroundColor Yellow
        winget install --id $Global:AppId --accept-source-agreements --accept-package-agreements --silent
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
    Write-Host "Please choose an option for $Global:AppInfo :" -ForegroundColor DarkYellow
    Write-Host "  1. Standard winget installation." -ForegroundColor Cyan
    Write-Host "  2. Create new folder "$Global:AppName" in 'D:\Program Files'" -ForegroundColor Cyan
    Write-Host "     --This may revert to the standard installation--" -ForegroundColor Red
    Write-Host "  3. Do Not Install $Global:AppName" -ForegroundColor Cyan
    $Opt = Read-Host 
    if ($Opt -eq '1') {
        StandardInstall
    }
    elseif ($Opt -eq '2') {            
        try {
            $InPath = "D:\Program Files\$Global:AppName"
            New-Item -ItemType Directory -Path $InPath -Force | Out-Null
            Write-Host "New folder created: $InPath" -ForegroundColor Blue
            Write-Host "Opening $InPath check for successful operation." -ForegroundColor Yellow
            Start-Process explorer.exe -ArgumentList "$InPath"
            Write-Host "$InPath will remain empty if winget could not set the Destination" -ForegroundColor Red
            Write-Host "Installing $Global:AppName..." -ForegroundColor Yellow
            winget install --id $Global:AppId --location $InPath --accept-source-agreements --accept-package-agreements --silent
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
    elseif ($Opt -eq '3') {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
    }
    else {
        Write-Host "$Global:AppInfo was not installed." -ForegroundColor Red
    }
    Clear-GlobalAppVariables
    return
}
## Winget Uninstall with FZF ##
function winun {
    Write-Host "Select a Package to Uninstall:" -ForegroundColor Yellow
    $PackID = Get-WinGetPackage
    if (-not $PackID) {
        Write-Host "No valid package selected." -ForegroundColor DarkRed
        return
    }
    else {
        winselect $PackID
        winuncheck
    }
}

function winuncheck {
    Write-Host "Uninstall [y] or [n]?" -ForegroundColor DarkRed
    $YorN = Read-Host
    if ($YorN -match '^[Yy]$') {
        try {
            winget uninstall  --id $Global:AppID
            Write-Host "$Global:AppInfo uninstalled successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Unable to Uninstall $Global:AppInfo." -ForegroundColor DarkRed
        }
    } else {
        Write-Host "$Global:AppInfo is still installed." -ForegroundColor Blue
    }
    Clear-GlobalAppVariables
    return
}
function Clear-GlobalAppVariables {
    Remove-Variable -Name AppName, AppID, AppVersion, AppInfo -Scope Global -ErrorAction SilentlyContinue
}

############# System Information ##################
function sysinfo { Get-ComputerInfo }

function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

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
    if ($restart -eq 'Y' -or $restart -eq 'y') {
        Restart-Computer
    } 
    else {
    Write-Host "Please remember to restart the computer for changes to take effect." -ForegroundColor Yellow
    }
}
function teloptout {
    if ([bool]([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem) {
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', 
        [System.EnvironmentVariableTarget]::Machine)
    }
}
## Remove Items from PSReadLine History and PSHistory
function Remove-PSReadlineHistory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    $historyPath = (Get-PSReadLineOption).HistorySavePath
    $historyLines = [System.IO.File]::ReadAllLines($historyPath)
    $filteredLines = $historyLines | Where-Object { $_ -notmatch $Pattern }
    [System.IO.File]::WriteAllLines($historyPath, $filteredLines)

    Write-Host "Removed $($historyLines.Count - $filteredLines.Count) line(s) from PSReadLine history."
}

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

####################### CALL PSInit in your Profile Script to start this section ##############
############### SETUP MODULES #################################
## Setup Zoxide ##
function ZoxSetUp {
    if (Get-Command zoxide -ErrorAction SilentlyContinue) {
        Invoke-Expression (& { (zoxide init powershell | Out-String) }) 
    } 
    else {
        Write-Host "zoxide command not found. Attempting to install via winget..." -ForegroundColor Blue
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
## Install Modules ##
function ModInstall {
    $modName = @(
        "PowerShellGet"
        "DnsClient"
        "Terminal-Icons"
        "PSReadLine"
        "PSFzf"
        "Microsoft.Winget.Client"
        "CompletionPredictor"
    )
    foreach ($mod in $modName) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Install-Module -Name $mod -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module -Name $mod
    }        
    Invoke-FuzzyFasd
    Invoke-FuzzyZLocation
    Set-LocationFuzzyEverything
    Invoke-FzfTabCompletion

    $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if (Test-Path($ChocolateyProfile)) {
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
    if ($PSVersionTable.PSVersion.Major -eq 7 ) {
        Set-PSReadLineOption -Colors @{
            ListPrediction = 'DarkGreen'
            Selection = "$($PSStyle.Background.Blue)$($PSStyle.Foreground.White)"
            InlinePrediction = $PSStyle.Foreground.BrightYellow + $PSStyle.Background.BrightBlack
        }
        if (-not (Get-Module -ListAvailable -Name CompletionPredictor)) {
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
        param($commandName, $wordToComplete, $cursorPosition)
        Invoke-CompletionPredictor -WordToComplete $wordToComplete -CursorPosition $cursorPosition
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

function Show-Help { @"
PowerShell Profile Help
=======================

Update-PowerShell - Checks for the latest PowerShell release and updates if a new version is available.

ud - Checks winget and windows for updates and installs any updates found.

touch <file> - Creates a new empty file.

ff <name> - Finds files recursively with the specified name.

Get-PubIP - Retrieves the public IP address of the machine.

winutil - Runs the WinUtil script from Chris Titus Tech.

uptime - Displays the system uptime.

reloadprofile - Reloads the current user's PowerShell profile.

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

Scripts- Changes the current directory to the Scripts folder.

Set-Cert <path> - Sets the certificate on the script at the given path...use 'path_to_script'

winin - Searh for and install Package with winget using FZF

winun -  Uninstall Package with winget using FZF

vscan - Opens Malwarebytesa and runs a Defender Quick Scan

dvs - Runs Defender Quick Scan

home - Changes the current directory to $HOME.

dl- Changes the current directory to the Downloads folder.

docs - Changes the current directory to the Documents folder.

dtop - Changes the current directory to the Desktop folder.

junk - Deletes Temporary Files

rmbb - Starts BleachBit and RAMMap.

bench - Starts Cinbench and monitors.

ep - Opens the profile for editing with VSCode.

epv - Opens the profile for editing with NeoVim.

Get-PoshThemes - List of available Oh My Posh! themes.

la - Lists all files in the current directory with detailed formatting.

ll - Lists all files, including hidden, in the current directory with detailed formatting.

gs - Shortcut for 'git status'.

ga - Shortcut for 'git add .'.

gc <message> - Shortcut for 'git commit -m'.

gp - Shortcut for 'git push'.

g - Changes to the GitHub directory.

gcom <message> - Adds all changes and commits with the specified message.

lazyg <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.

sysinfo - Displays detailed system information.

flushdns - Clears the DNS cache.

ReNet - Resets Network, requires restart to take effect.

cpy <text> - Copies the specified text to the clipboard.

pst - Retrieves text from the clipboard.

rehis <String> - Removes command from PSReadLine and PS History

teleoptout - Opt out of PowerShell Telemetry, must be Admin.

Use 'Show-Help' to display this help message.
"@
}
##################################################################
##################################################################
##################################################################

