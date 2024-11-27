
###################################################################
#######          SHAKE'S PowerShell-7 Profile             #########
###################################################################

function ShakePSMod {
    $moduleName = "ShakePSModule"
    $ShakeGitUrl = "https://raw.githubusercontent.com/SmileyShake/ShakePSModule/main/ShakePSModule.psm1"
    $moduleDestination = "$PSHOME\Modules\$moduleName"
    Write-Host "$moduleName is installing or updating..." -ForegroundColor Yellow
    if (-Not (Test-Path $moduleDestination)) {
        New-Item -ItemType Directory -Path $moduleDestination
    }
    $psm1File = Join-Path $moduleDestination "$moduleName.psm1"
    Invoke-WebRequest -Uri $ShakeGitUrl -OutFile $psm1File
    Write-Host "$moduleName is installed at:" -ForegroundColor Green
    Write-Host "$moduleDestination" -ForegroundColor Cyan
    Import-Module "$moduleDestination"
}

$OmpTheme = "ShakeDarkCL.omp.json" 

ShakePSMod
SetOmpTheme $OmpTheme
PSInit 

##################################################################
##################################################################
##################################################################
