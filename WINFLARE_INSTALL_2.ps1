<#
 Copyright 2017 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
#>

<#
    .SYNOPSIS
        Fully automated installation script for FLARE VM.
        ** Only install on a virtual machine! **

    .DESCRIPTION
        Fully automated installation script for FLARE VM that leverages Chocolatey and Boxstarter.
        This version removes all user interactions, GUI elements, and unnecessary checks for continuous operation.

        To execute this script:
          1) Open PowerShell window as administrator
          2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
          3) Unblock the install script by running "Unblock-File .\install.ps1"
          4) Execute the script by running ".\install.ps1"

    .PARAMETER password
        Current user password to allow reboot resiliency via Boxstarter. Uses default if not provided.

    .PARAMETER customConfig
        Path to a configuration XML file. May be a file path or URL.

    .PARAMETER customLayout
        Path to a taskbar layout XML file. May be a file path or URL.

    .EXAMPLE
        .\install.ps1

        Description
        ---------------------------------------
        Execute the installer to configure FLARE VM in fully automated mode.

    .EXAMPLE
        .\install.ps1 -password Passw0rd!

        Description
        ---------------------------------------
        Execute with custom password for reboots.

    .LINK
        https://github.com/mandiant/flare-vm
        https://github.com/mandiant/VM-Packages
#>

param (
  [string]$password = "FlareVM123!",  # Default password
  [string]$customConfig = $null,
  [string]$customLayout = $null
)

# Force all parameters for full automation
$noPassword = $false
$noWait = $true
$noGui = $true
$noReboots = $false
$noChecks = $true

$ErrorActionPreference = 'Continue'  # Changed to Continue to avoid stopping on non-critical errors
$ProgressPreference = 'SilentlyContinue'

# Function to download files and handle errors consistently
function Save-FileFromUrl {
    param (
        [string]$fileSource,
        [string]$fileDestination,
        [switch]$exitOnError
    )
    Write-Host "[+] Downloading file from '$fileSource'"
    try {
        (New-Object net.webclient).DownloadFile($fileSource,$FileDestination)
        Write-Host "[+] Successfully downloaded file"
    } catch {
        Write-Host "`t[!] Failed to download '$fileSource'"
        Write-Host "`t[!] $_"
        if ($exitOnError) {
            Write-Host "[!] Continuing despite download error..."
        }
    }
}

# Function used for getting configuration files (such as config.xml and LayoutModification.xml)
function Get-ConfigFile {
    param (
        [string]$fileDestination,
        [string]$fileSource
    )
    # Check if the source is an existing file path.
    if (-not (Test-Path $fileSource)) {
        # If the source doesn't exist, assume it's a URL and download the file.
        Save-FileFromUrl -fileSource $fileSource -fileDestination $fileDestination
    } else {
        # If the source exists as a file, move it to the destination.
        Write-Host "[+] Using existing file as configuration file."
        Copy-Item -Path $fileSource -Destination $fileDestination -Force
    }
}

# Set path to user's desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

Write-Host "[+] Starting FLARE VM automated installation..." -ForegroundColor Green
Write-Host "[+] All user interactions have been disabled for continuous operation" -ForegroundColor Cyan

# Minimal checks - only critical ones
Write-Host "[+] Performing minimal critical checks..."

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion -lt [System.Version]"5.0.0") {
    Write-Host "[!] PowerShell version $psVersion is not supported. Minimum version 5.0 required." -ForegroundColor Red
    exit 1
}

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    Write-Host "[!] Script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Set execution policy if needed
try {
    if (-not((Get-ExecutionPolicy).ToString() -eq "Unrestricted")){
        Write-Host "[+] Setting execution policy to Unrestricted..."
        Set-ExecutionPolicy Unrestricted -Force -Scope CurrentUser
    }
} catch {
    Write-Host "[!] Could not set execution policy. Continuing anyway..." -ForegroundColor Yellow
}

# Check for spaces in username
if (${Env:UserName} -match '\s') {
    Write-Host "[!] Username '${Env:UserName}' contains a space and may cause issues" -ForegroundColor Yellow
}

Write-Host "[+] Critical checks completed. Proceeding with installation..."

# Set password to never expire automatically
Write-Host "[+] Setting password to never expire..."
try {
    $UserNoPasswd = Get-CimInstance Win32_UserAccount -Filter "Name='${Env:UserName}'" -ErrorAction SilentlyContinue
    if ($UserNoPasswd) {
        $UserNoPasswd | Set-CimInstance -Property @{ PasswordExpires = $false } -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[!] Could not set password expiry. Continuing..." -ForegroundColor Yellow
}

# Automatically create credentials
Write-Host "[+] Setting up automatic credentials for reboots..."
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:UserName}, $securePassword

# Disable Windows Defender and Tamper Protection silently
Write-Host "[+] Attempting to disable Windows Defender..."
try {
    # Disable real-time monitoring
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    
    # Disable various protection features
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
    
    # Add exclusions for common paths
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "${env:ProgramData}\chocolatey" -ErrorAction SilentlyContinue
    
    Write-Host "[+] Windows Defender settings modified"
} catch {
    Write-Host "[!] Could not modify Windows Defender settings. Continuing..." -ForegroundColor Yellow
}

# Try to disable Tamper Protection via registry
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "[+] Attempted to disable Tamper Protection"
} catch {
    Write-Host "[!] Could not disable Tamper Protection via registry. Continuing..." -ForegroundColor Yellow
}

# Check Boxstarter version
$boxstarterVersionGood = $false
if (${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
    try {
        choco info -l -r "boxstarter" | ForEach-Object { 
            $name, $version = $_ -split '\|' 
            if ($version) {
                $boxstarterVersionGood = [System.Version]$version -ge [System.Version]"3.0.2"
            }
        }
    } catch {
        $boxstarterVersionGood = $false
    }
}

# Install Boxstarter if needed
if (-not $boxstarterVersionGood) {
    Write-Host "[+] Installing Boxstarter..." -ForegroundColor Cyan
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
        Get-Boxstarter -Force
    } catch {
        Write-Host "[!] Error installing Boxstarter, but continuing..." -ForegroundColor Yellow
    }
    Start-Sleep -Milliseconds 500
}

try {
    Import-Module "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\boxstarter.chocolatey.psd1" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Could not import Boxstarter module. Continuing..." -ForegroundColor Yellow
}

# Check Chocolatey version and update if needed
try {
    $version = choco --version
    if ($version) {
        $chocolateyVersionGood = [System.Version]$version -ge [System.Version]"2.0.0"
        if (-not ($chocolateyVersionGood)) { 
            Write-Host "[+] Updating Chocolatey..."
            choco upgrade chocolatey -y
        }
    }
} catch {
    Write-Host "[!] Could not check Chocolatey version. Continuing..." -ForegroundColor Yellow
}

# Disable updates
Write-Host "[+] Disabling Windows updates and store updates..."
try {
    Disable-MicrosoftUpdate -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue -Force | Out-Null
} catch {
    Write-Host "[!] Could not disable all updates. Continuing..." -ForegroundColor Yellow
}

# Set Boxstarter options
try {
    $Boxstarter.RebootOk = $true
    $Boxstarter.NoPassword = $false
    $Boxstarter.AutoLogin = $true
    $Boxstarter.SuppressLogging = $True
    $VerbosePreference = "SilentlyContinue"
    Set-BoxstarterConfig -NugetSources "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2;https://chocolatey.org/api/v2" -ErrorAction SilentlyContinue
    Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Could not set all Boxstarter options. Continuing..." -ForegroundColor Yellow
}

# Set Chocolatey options
Write-Host "[+] Configuring Chocolatey settings..."
try {
    choco sources add -n="vm-packages" -s "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2" --priority 1 -y
    choco feature enable -n allowGlobalConfirmation
    choco feature enable -n allowEmptyChecksums
    $cache = "${Env:LocalAppData}\ChocoCache"
    New-Item -Path $cache -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
    choco config set cacheLocation $cache
} catch {
    Write-Host "[!] Some Chocolatey settings could not be applied. Continuing..." -ForegroundColor Yellow
}

# Set power options to prevent timeouts
Write-Host "[+] Configuring power options..."
try {
    powercfg -change -monitor-timeout-ac 0 | Out-Null
    powercfg -change -monitor-timeout-dc 0 | Out-Null
    powercfg -change -disk-timeout-ac 0 | Out-Null
    powercfg -change -disk-timeout-dc 0 | Out-Null
    powercfg -change -standby-timeout-ac 0 | Out-Null
    powercfg -change -standby-timeout-dc 0 | Out-Null
    powercfg -change -hibernate-timeout-ac 0 | Out-Null
    powercfg -change -hibernate-timeout-dc 0 | Out-Null
} catch {
    Write-Host "[!] Could not set all power options. Continuing..." -ForegroundColor Yellow
}

# Get configuration file
Write-Host "[+] Downloading configuration file..."
$configPath = Join-Path $desktopPath "config.xml"
if ([string]::IsNullOrEmpty($customConfig)) {
    $configSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml'
} else {
    $configSource = $customConfig
}

Get-ConfigFile $configPath $configSource

# Verify config file exists, create a basic one if not
if (-Not (Test-Path $configPath)) {
    Write-Host "[!] Configuration file missing, creating basic config..." -ForegroundColor Yellow
    $basicConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<config>
    <envs>
        <env name="VM_COMMON_DIR" value="%USERPROFILE%\Desktop\VM" />
    </envs>
</config>
"@
    $basicConfig | Out-File -FilePath $configPath -Encoding UTF8
}

# Parse config and set environment variables
Write-Host "[+] Processing configuration..."
try {
    $configXml = [xml](Get-Content $configPath)
    
    foreach ($env in $configXml.config.envs.env) {
        $path = [Environment]::ExpandEnvironmentVariables($($env.value))
        Write-Host "`t[+] Setting %$($env.name)% to: $path" -ForegroundColor Green
        [Environment]::SetEnvironmentVariable("$($env.name)", $path, "Machine")
    }
    [Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
    refreshenv
} catch {
    Write-Host "[!] Error processing config file. Using defaults..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable('VM_COMMON_DIR', "$env:USERPROFILE\Desktop\VM", [EnvironmentVariableTarget]::Machine)
    [Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
}

# Install common module
Write-Host "[+] Installing shared module..."
try {
    choco install common.vm -y --force
    refreshenv
} catch {
    Write-Host "[!] Error installing common.vm. Continuing..." -ForegroundColor Yellow
}

# Save config to common directory
try {
    if (Test-Path ${Env:VM_COMMON_DIR}) {
        $configXml.save((Join-Path ${Env:VM_COMMON_DIR} "config.xml"))
        $configXml.save((Join-Path ${Env:VM_COMMON_DIR} "packages.xml"))
    }
} catch {
    Write-Host "[!] Could not save config to common directory. Continuing..." -ForegroundColor Yellow
}

# Setup custom Start Layout
Write-Host "[+] Setting up Start Layout..."
$layoutPath = Join-Path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" "LayoutModification.xml"
if ([string]::IsNullOrEmpty($customLayout)) {
    $layoutSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/LayoutModification.xml'
} else {
    $layoutSource = $customLayout
}

try {
    Get-ConfigFile $layoutPath $layoutSource
} catch {
    Write-Host "[!] Could not setup Start Layout. Continuing..." -ForegroundColor Yellow
}

# Install debloat package
Write-Host "[+] Installing debloat and performance package..."
try {
    choco install debloat.vm -y --force
} catch {
    Write-Host "[!] Error installing debloat.vm. Continuing..." -ForegroundColor Yellow
}

# Download background images
Write-Host "[+] Setting up FLARE VM branding..."
try {
    if (Test-Path ${Env:VM_COMMON_DIR}) {
        $backgroundImage = "${Env:VM_COMMON_DIR}\background.png"
        Save-FileFromUrl -fileSource 'https://raw.githubusercontent.com/mandiant/flare-vm/main/Images/flarevm-background.png' -fileDestination $backgroundImage
        $lockScreenImage = "${Env:VM_COMMON_DIR}\lockscreen.png"
        Copy-Item $backgroundImage $lockScreenImage -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[!] Could not setup branding images. Continuing..." -ForegroundColor Yellow
}

# Skip all waiting and user interaction
Write-Host "[+] Starting package installation immediately..." -ForegroundColor Green
Write-Host "[!] Installation running in fully automated mode - no user interaction required" -ForegroundColor Cyan

# Begin the package install
Write-Host "[+] Installing FLARE VM packages..." -ForegroundColor Green
$PackageName = "installer.vm"

try {
    Install-BoxstarterPackage -packageName $PackageName -credential $credentials
} catch {
    Write-Host "[!] Error during package installation: $_" -ForegroundColor Red
    Write-Host "[!] You may need to manually restart the installation" -ForegroundColor Yellow
}

Write-Host "[+] FLARE VM installation process completed!" -ForegroundColor Green
Write-Host "[+] Check C:\ProgramData\chocolatey\lib-bad for any failed packages" -ForegroundColor Yellow
