#################################################################################################################################
############                        SHAKE'S PowerShell Module                        ############
#################################################################################################################################
$UserName = whoami
if ($UserName -ne "shake-mini\shake") {
    InstallPrograms
    Update-PowerShell
}
###############################
# Program List and Stored Paths
$Programs = @(
    "Microsoft.Sysinternals.RAMMap",
    "Malwarebytes.Malwarebytes",
    "BleachBit.BleachBit",
    "Maxon.CinebenchR23",
    "CPUID.HWMonitor",
    "Git.Git"
)
# Hash table to store the installation paths for specific programs
$ProgramPaths = @{}

# Loop through the list of programs and install them
function InstallPrograms {
    foreach ($Program in $Programs) {
        switch ($Program) {
            "Microsoft.Sysinternals.RAMMap" {
            # Try to find both RAMMap.exe and RAMMap64.exe
                InstalList -Program $Program -ExeName "rammap.exe"
                $rammap64Path = Get-Command "RAMMap64.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                if ($rammap64Path) {
                    $ProgramPaths[$Program] = $rammap64Path
                    Write-Host "RAMMap64.exe found at: $rammap64Path" -ForegroundColor Cyan
                }
            }
            "Malwarebytes.Malwarebytes" {
            # Try to find both mbam.exe and Malwarebytes.exe
                InstalList -Program $Program -ExeName "mbam.exe"
                $malwarebytesPath = Get-Command "Malwarebytes.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                if ($malwarebytesPath) {
                    $ProgramPaths[$Program] = $malwarebytesPath
                    Write-Host "Malwarebytes.exe found at: $malwarebytesPath" -ForegroundColor Cyan
                }
            }
            "BleachBit.BleachBit" {
                InstalList -Program $Program -ExeName "bleachbit.exe"
            }
            "Maxon.CinebenchR23" {
                InstalList -Program $Program -ExeName "Cinebench.exe"
            }
            "CPUID.HWMonitor" {
                InstalList -Program $Program -ExeName "HWMonitor.exe"
            }
            default {
                InstalList -Program $Program
            }
        }
    }
    Write-Host "Installation Complete." -ForegroundColor Green    
}
# This Function is called in the 'InstallPrograms' Function
#Function to Install a Program and Store Its Path 
function InstalList {
    param (
        [String]$Program,
        [String]$ExeName  # The name of the executable to find (optional)
    )
    Write-Host "Checking for ${Program}..." -ForegroundColor Yellow
    # Check if the program is already installed
    $isInstalled = winget list --id $Program -e | Select-String -Pattern $Program
    if ($isInstalled) {
        Write-Host "$Program is already installed." -ForegroundColor Green
        # If an executable name is provided, try to get its path
        if ($ExeName) {
            $exePath = Get-Command $ExeName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
            if ($exePath) {
                $ProgramPaths[$Program] = $exePath
                Write-Host "${Program} path: ${exePath}" -ForegroundColor Cyan
            } else {
                Write-Host "Could not find executable for ${Program}." -ForegroundColor Red
            }
        }
    } 
    else {
        Write-Host "Installing ${Program}..." -ForegroundColor Yellow
        try {
            winget install --id $Program --silent --accept-package-agreements --accept-source-agreements -e
            if ($?) {
                Write-Host "${Program} installed successfully." -ForegroundColor Green
                # Store the executable path if provided
                if ($ExeName) {
                    $exePath = Get-Command $ExeName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    if ($exePath) {
                        $ProgramPaths[$Program] = $exePath
                        Write-Host "${Program} path: ${exePath}" -ForegroundColor Cyan
                    } 
                    else {
                        Write-Host "Could not find executable for ${Program}." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "${Program} installation failed." -ForegroundColor Red
            }
        } 
        catch {
                    Write-Host "Error installing ${Program}: $_" -ForegroundColor Red
        }
    }
}        

# Function to start a program using its stored path
function StartProgram {
    param (
        [String]$ProgramName
    )    
    if ($ProgramPaths.ContainsKey($ProgramName)) {
        $path = $ProgramPaths[$ProgramName]
        Write-Host "Starting $ProgramName from $path..." -ForegroundColor Yellow
        Start-Process $path
    } 
    elseif ($ProgramName -eq "Malwarebytes.Malwarebytes") {
        $mbamPath = Get-Command "mbam.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
        if (-not $mbamPath) {
            # Check common installation path
            $commonPath = "C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe"
            if (Test-Path $commonPath) {
                $mbamPath = $commonPath
            }
        }
        if ($mbamPath) {
            Write-Host "Starting Malwarebytes from $mbamPath..." -ForegroundColor Yellow
            Start-Process $mbamPath
        }
        else {
            Write-Host "Malwarebytes executable not found." -ForegroundColor Red
        }
    }
    elseif ($ProgramName -eq "BleachBit.BleachBit") {
        $bleachbitPath = Get-Command "bleachbit.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
        if (-not $bleachbitPath) {
            $commonPath = "C:\Program Files\BleachBit\bleachbit.exe"
            $commonPath2 = "$HOME\AppData\Local\Programs\BleachBit\bleachbit.exe"
            if (Test-Path $commonPath) {
                $bleachbitPath = $commonPath
            }
            elseif (Test-Path $commonPath2) {
                $bleachbitPath = $commonPath2
            }
            else {
                # Log a message if neither path is found
                Write-Host "BleachBit not found in PATH or common installation path." -ForegroundColor Red
            }
        }
        if ($bleachbitPath) {
            Write-Host "Starting BleachBit from $bleachbitPath..." -ForegroundColor Yellow
            Start-Process $bleachbitPath
        } 
        else {
            Write-Host "BleachBit executable not found." -ForegroundColor Red
        }
    } 
    elseif ($ProgramName -eq "CPUID.HWMonitor") {
        # Attempt to start HWMonitor as HWMonitor.exe if it's installed
        $hwmonitorPath = Get-Command "HWMonitor.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
        if (-not $hwmonitorPath) {
            # Check common installation path
            $commonPath = "C:\Program Files\CPUID\HWMonitor\HWMonitor.exe"
            $commonPath2 = "$HOME\AppData\Local\Programs\CPUID\HWMonitor\HWMonitor.exe"
            if (Test-Path $commonPath) {
                $hwmonitorPath = $commonPath
            }
            elseif (Test-Path $commonPath2) {
                $hwmonitorPath = $commonPath2
            }
            else {
                # Log a message if neither path is found
                Write-Host "HWMonitor not found in PATH or common installation path." -ForegroundColor Red
            }
        }
        if ($hwmonitorPath) {
            Write-Host "Starting HWMonitor from $bleachbitPath..." -ForegroundColor Yellow
            Start-Process $hwmonitorPath
        } 
        else {
            Write-Host "HWMonitor executable not found." -ForegroundColor Red
        }
    } 
    elseif ($ProgramName -eq "Maxon.CinebenchR23") {
        # Attempt to start Cinebench as Cinebench.exe if it's installed
        $cinebenchPath = Get-Command "Cinebench.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
        if (-not $cinebenchPath) {
            # Check common installation path
            $commonPath = "C:\Program Files\Maxon Cinebench R23\Cinebench.exe"
            $commonPath2 = "$HOME\AppData\Local\Programs\Maxon Cinebench R23\Cinebench.exe"
            if (Test-Path $commonPath) {
                $cinebenchPath = $commonPath
            }
            elseif (Test-Path $commonPath2) {
                $cinebenchPath = $commonPath2
            }
            else {
                # Log a message if neither path is found
                Write-Host "Cinebench not found in PATH or common installation path." -ForegroundColor Red
            }
        }
        if ($cinebenchPath) {
            Write-Host "Starting Cinebench from $cinebenchPath..." -ForegroundColor Yellow
            Start-Process $cinebenchPath
        } 
        else {
            Write-Host "Cinebench executable not found." -ForegroundColor Red
        }
    } 
    else {
        Write-Host "$ProgramName path not found in stored paths." -ForegroundColor Red
    }
}

function Update-PowerShell {
    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Blue
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
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}

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
################### Open WinUtil from Chris Titus Tech   ##################
function winutil {
	Invoke-WebRequest -useb https://christitus.com/win | Invoke-Expression
}

################### System Utilities #############################
function admin {
    if ($args.Count -gt 0) {
        $argList = "& '$args'"
        Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    } else {
        Start-Process wt -Verb runAs
    }
}

function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
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

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
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

function home { Set-Location -Path $HOME }

function scripts {
    $UserName = whoami 
    if ($UserName -eq "shake-mini\shake") {
        Set-Location -Path D:\Documents\PowerShell\Scripts
    }    
    else {    
        Set-Location -Path $HOME\Documents\WindowsPowerShell\Scripts 
    }
}

function dl { 
    $UserName = whoami
    if ($UserName -eq "shake-mini\shake") {
        Set-Location -Path D:\Downloads
    }
    else{
        Set-Location -Path $HOME\Downloads 
    }
}

function docs { 
    $UserName = whoami
    if ($UserName -eq "shake-mini\shake") {
        Set-Location -Path D:\Documents
    }
    else {
        Set-Location -Path $HOME\Documents 
    }
}

function dtop { Set-Location -Path $HOME\Desktop }

function junk {
    # Clean up temporary files, redirect errors to $null to suppress them
    Get-ChildItem -Path $env:TEMP\* -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 2>$null
    Get-ChildItem -Path 'C:\Windows\Temp\*' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 2>$null
    Get-ChildItem -Path 'C:\Windows\Downloaded Program Files\*' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 2>$null
    Get-ChildItem -Path 'C:\Windows\Prefetch\*' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 2>$null

    # Delete the contents of the SoftwareDistribution folder, suppress errors
    Try {
        Stop-Service -Name wuauserv -ErrorAction SilentlyContinue 2>$null
        Get-ChildItem -Path 'C:\Windows\SoftwareDistribution\Download\*' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 2>$null
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue 2>$null
    } Catch {
        # Suppress errors, do nothing
    }
}

function ud {
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
        Write-Host "Updating Winget to the latest version..." -ForegroundColor Blue
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
        Write-Host "The following updates will be installed from Winget:" -ForegroundColor Yellow
        try {
            winget upgrade --all
            Write-Host "All updates have been installed successfully." -ForegroundColor Green
        } 
        catch {
            Write-Host "An error occurred while installing updates." -ForegroundColor DarkRed
        }
    }
    # Ensure the PSWindowsUpdate module is available
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "PSWindowsUpdate module not found. Installing..." -ForegroundColor Green
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
    }

    Write-Host "Checking for Windows updates..." -ForegroundColor Blue
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

function vscan {
    # Start Malwarebytes with elevated privileges
    $UserName = whoami
    if ($UserName -eq "shake-mini\shake") {
        Start-Process -FilePath "D:\Program Files\Malwarebytes.exe" -Verb RunAs
        Write-Host "Starting MalwareBytes..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Attempting to Start Malwarebytes..." -ForegroundColor Yellow
        StartProgram -ProgramName "Malwarebytes.Malwarebytes"
    }
    # Update Windows Defender definitions
    Update-MpSignature -UpdateSource MicrosoftUpdateServer
    Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor Blue
    # Start a quick scan
    $scanResult = Start-MpScan -ScanType QuickScan
    $scanResult | Wait-Job    
    # Get scan results
    $scanResults = Get-MpThreatDetection
    Write-Host "Scan Complete..." -ForegroundColor Green
    if ($scanResults) {
        # Filter out specific threats (e.g., threats related to urbackup_srv.exe or ThreatID 2147519003)
        $filteredResults = $scanResults | Where-Object {
            $_.ProcessName -notlike '*urbackup_srv.exe*' -and
            $_.ThreatID -ne 2147519003
        }
        if ($filteredResults) {
            Write-Host "Scan Results:" -ForegroundColor DarkRed
            foreach ($result in $filteredResults) {
                Write-Host "Threat Name: $($result.ThreatName)" -ForegroundColor DarkRed
                Write-Host "Action Taken: $($result.ActionTaken)" -ForegroundColor DarkRed
                Write-Host "Severity: $($result.Severity)" -ForegroundColor DarkRed
                Write-Host "------------------------------------------------------------" -ForegroundColor DarkRed
            }
        } else {
            Write-Host "No significant threats detected." -ForegroundColor Green
        }
    } 
    else {
        Write-Host "No threats detected with Windows Defender." -ForegroundColor Green
    }               
}

# Search and install Winget Package in a new 'D' drive Folder
function winstall {
    param (
        [string]$PackName
    )
    $SearchResults = winget search $PackName
    if ($SearchResults -like "*No package found matching input criteria.*") {
        Write-Host "No package found for '$PackName'." -ForegroundColor Red
        return     
    }   
    if ($SearchResults) {
        Write-Host "Search results for '$PackName':" -ForegroundColor Green
        $SearchResults | Format-Table -AutoSize
    } 
    else {
        Write-Host "No results found for '$PackName'." -ForegroundColor Red
        return
    }    
    # Prompt user for a selection
    Write-Host "Enter ID of the package you want to install:" -ForegroundColor Yellow
    $selectedPackId = Read-Host
    # Validate user input
    if ($selectedPackId) {
        try {
            $AppId = $selectedPackId
            if (winget list | Where-Object { $_ -like "*$AppId*" }) {
                Write-Host "$PackName is already installed.  Checking for updates..." -ForegroundColor Yellow
                winget upgrade --id $AppId --accept-source-agreements --accept-package-agreements
                return
            }
            else {
                $packageInfo = winget show $AppId
                # Extract Name and Version
                $AppVersion = ($packageInfo | Where-Object { $_ -like 'Version:*' }).Split(':')[1].Trim()
                $FLine = $packageInfo | Where-Object { $_ -match '^Found' }
                $AppName = ($FLine -split '\[')[0].Replace('Found', '').Trim()        
                # Output selected package details
                Write-Host "You selected: $AppName -ID:$AppId -Version:$AppVersion" -ForegroundColor DarkYellow        
                # Get confirmation to install
                $UserName = whoami
                if ($UserName -eq "shake-mini\shake") {InstallChoice}
                else {StandardInstall}
            }
        }   
        catch {
            Write-Host "Could not install $AppName. Please try again. Error: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Invalid selection. Rerun 'winstall' to try again." -ForegroundColor Red
    }
}

function StandardInstall {
    try {
        Write-Host "Installing $AppName..." -ForegroundColor Yellow
        winget install -e --id $AppId --accept-source-agreements --accept-package-agreements
        Write-Host "$AppName installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not install $AppName with winget. Error: $_" -ForegroundColor Red
    }
}

function InstallChoice {
    Write-Host "Please choose an option for $AppName :" -ForegroundColor Yellow
    Write-Host "    1. Standard winget installation." -ForegroundColor Cyan
    Write-Host "    2. Create new folder $AppName in 'D:\Program Files'" -ForegroundColor Cyan
    Write-Host "       Note: This may revert to the standard installation." -ForegroundColor Red
    Write-Host "    3. Do Not Install $AppName" -ForegroundColor Cyan
    $Opt = Read-Host
    if ($Opt -eq '1') {
        StandardInstall
    }
    elseif ($Opt -eq '2') {            
        try {
            $InPath = "D:\Program Files\$AppName"
            New-Item -ItemType Directory -Path $InPath -Force | Out-Null
            Write-Host "New folder created: $InPath" -ForegroundColor Blue
            Write-Host "Opening $InPath check for successful operation." -ForegroundColor Yellow
            Start-Process explorer.exe -ArgumentList "$InPath"
            Write-Host "$InPath will remain empty if winget could not set the Destination" -ForegroundColor Red
            Write-Host "Installing $AppName..." -ForegroundColor Yellow
            winget install -e --id $AppId --location $InPath --accept-source-agreements --accept-package-agreements     
            Write-Host "$AppName installed successfully." -ForegroundColor Green             
        }
        catch {
            Write-Host "Could not install $AppName with winget. Error: $_" -ForegroundColor Red
        }    
    }
    elseif ($Opt -eq '3') {
        Write-Host "$AppName was not installed." -ForegroundColor Red
    }
    else {
        Write-Host "$AppName was not installed." -ForegroundColor Red
    }
}

function bench {
    $UserName = whoami
    if ($UserName -eq "shake-mini\shake") {
        Write-Host "Starting Cinebench, the '-Z's and HW Monitor..." -ForegroundColor Yellow
        Start-Process -FilePath "D:\WindowsApps\MAXONComputerGmbH.Cinebench_23.2.0.0_x64__rsne5bsk8s7tj\bin\Cinebench.exe"
        Start-Process -FilePath "D:\Program Files\hwmonitor\HWMonitor.exe" -Verb RunAs
        Start-Process -FilePath "D:\Program Files\cpu-z\cpuz.exe" -Verb RunAs
        Start-Process -FilePath "C:\Program Files (x86)\GPU-Z\GPU-Z.exe" -Verb RunAs
    }
    else {
        Write-Host "Attempting to Start HWMonitor and Cinebench..." -ForegroundColor Yellow
        StartProgram -ProgramName "CPUID.HWMonitor"
        StartProgram -ProgramName "Maxon.CinebenchR23"
    }

}


function rmbb {
    $UserName = whoami
    if ($UserName -eq "shake-mini\shake") {
        Write-Host "Starting BleachBit and RAMMap..." -ForegroundColor Yellow
        Start-Process -FilePath "D:\BleachBit\bleachbit.exe" -Verb RunAs
        Start-Process -FilePath "D:\Utility\Program Folders\Sys Internals\RAMMap64.exe" -Verb RunAs
    }
    else {
        Write-Host "Attempting to Start RAMMap and BleachBit..." -ForegroundColor Yellow
    StartProgram -ProgramName "Microsoft.Sysinternals.RAMMap"
    StartProgram -ProgramName "BleachBit.BleachBit"
    }
}

################### Editing and Reload the Profile ##########
function ep { code $PROFILE }

function epv { nvim $PROFILE }

function reloadprofile {
    & $PROFILE
}
################# Enhanced Listing ############
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }
################ Git Shortcuts ############### 
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

############# System Information ##################
function sysinfo { Get-ComputerInfo }
############# Network Utilities ###################
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

function flushdns {
	Clear-DnsClientCache
	Write-Host "DNS has been flushed" -ForegroundColor Green
}
    
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

################ Clipboard Utilities ##############################
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

function PressEnter {     
    Write-Host " Press Enter to Continue" -ForegroundColor DarkGray
    Read-Host
    return
}

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

# Ensure Terminal-Icons module is installed before importing
function ModInstall {
    if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
        Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
    }
    if (-not (Get-Module -ListAvailable -Name PSFzf)) {
        Install-Module -Name PSFzf -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module -Name Terminal-Icons
    Import-Module -Name PSFzf
    
    Invoke-FuzzyFasd
    Invoke-FuzzyZLocation
    Set-LocationFuzzyEverything
    Invoke-FzfTabCompletion

    $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if (Test-Path($ChocolateyProfile)) {
        Import-Module "$ChocolateyProfile"
    }
}
function PSRLsetup {
    # PowerShell ReadLine 
    Set-PSReadLineOption -Colors @{
        Command = 'DarkYellow'
        Parameter = 'Magenta'
        String = 'Blue'
        Comment = 'DarkGray'
        Keyword = 'DarkMagenta'
        Number = 'DarkBlue'
        Operator = 'DarkRed'
        Variable = 'DarkGreen'
        Type = 'Blue'
        Error = 'Red'
        InlinePrediction = $PSStyle.Foreground.BrightYellow + $PSStyle.Background.BrightBlack
        Selection = $PSStyle.Background.Blue
    }
    
    Set-PSReadLineKeyHandler -Chord 'Ctrl+f' -Function ForwardWord
    Set-PSReadLineKeyHandler -Chord 'Enter' -Function ValidateAndAcceptLine
    Set-PSReadLineOption -EditMode Windows
    Set-PSReadLineOption -BellStyle None
    Set-PSReadLineOption -PredictionSource HistoryAndPlugin
    Set-PSReadLineOption -PredictionViewStyle List
    Set-PSReadLineOption -HistorySearchCursorMovesToEnd:$True
    Set-PSReadLineKeyHandler -Key Tab -ScriptBlock { Invoke-FzfTabCompletion }
    Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
    Set-PSReadLineKeyHandler -Chord "Ctrl+f" -Function ForwardWord
    #####
    $scriptblock = {
        param($wordToComplete, $commandAst, $cursorPosition)
        dotnet complete --position $cursorPosition $commandAst.ToString() |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock
}

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

ModInstall
PSRLsetup
ZoxSetUp
AliasSetup

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

winstall <package> - Searh for and install 'Package' with winget on D: Drive

vscan - Opens Malwarebytesa and runs a Defender Quick Scan, excludes results for UrBackup

home - Changes the current directory to the SHAKE folder.

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

Use 'Show-Help' to display this help message.
"@
}
##################################################################
##################################################################
##################################################################

