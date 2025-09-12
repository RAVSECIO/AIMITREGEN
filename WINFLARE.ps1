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
        Minimal installation script for FLARE VM.

    .DESCRIPTION
        Simplified installation script for FLARE VM that leverages Chocolatey and Boxstarter.
        Removed GUI components, validation checks, and Windows Defender requirements.
        Script continues gracefully even if some conditions aren't met.

    .PARAMETER password
        Current user password to allow reboot resiliency via Boxstarter.

    .PARAMETER noPassword
        Switch parameter indicating a password is not needed for reboots.

    .PARAMETER customConfig
        Path to a configuration XML file. May be a file path or URL.

    .PARAMETER customLayout
        Path to a taskbar layout XML file. May be a file path or URL.

    .PARAMETER noReboots
        Switch parameter to prevent reboots (not recommended).

    .EXAMPLE
        .\install.ps1 -password Passw0rd! -noPassword

        Description
        ---------------------------------------
        Execute the minimal installer to configure FLARE VM.
#>

param (
  [string]$password = $null,
  [switch]$noPassword,
  [string]$customConfig = $null,
  [string]$customLayout = $null,
  [switch]$noReboots
)

$ErrorActionPreference = 'Continue'  # Changed to Continue for graceful handling
$ProgressPreference = 'SilentlyContinue'

# Function to download files and handle errors gracefully
function Save-FileFromUrl {
    param (
        [string]$fileSource,
        [string]$fileDestination
    )
    Write-Host "[+] Downloading file from '$fileSource'"
    try {
        (New-Object net.webclient).DownloadFile($fileSource,$FileDestination)
        Write-Host "`t[+] Successfully downloaded"
    } catch {
        Write-Host "`t[!] Failed to download '$fileSource' - continuing anyway"
        Write-Host "`t[!] $_"
    }
}

# Function used for getting configuration files
function Get-ConfigFile {
    param (
        [string]$fileDestination,
        [string]$fileSource
    )
    if (-not (Test-Path $fileSource)) {
        Save-FileFromUrl -fileSource $fileSource -fileDestination $fileDestination
    } else {
        Write-Host "[+] Using existing file as configuration file."
        try {
            Copy-Item -Path $fileSource -Destination $fileDestination -Force
        } catch {
            Write-Host "[!] Failed to copy config file - continuing with defaults"
        }
    }
}

# Set path to user's desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

Write-Host "[+] Starting minimal FLARE VM installation"
Write-Host "[+] Validation checks and GUI have been removed for streamlined installation"

# Basic system info
try {
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "[+] PowerShell version: $psVersion"
} catch {
    Write-Host "[!] Could not determine PowerShell version - continuing"
}

try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "[+] Running as Administrator"
    } else {
        Write-Host "[!] Not running as Administrator - some features may not work properly"
    }
} catch {
    Write-Host "[!] Could not verify administrator status - continuing"
}

# Get user credentials for autologin during reboots if needed
if (-not $noPassword.IsPresent -and [string]::IsNullOrEmpty($password)) {
    Write-Host "[+] Password not provided - will attempt installation without credentials"
    $noPassword = $true
}

if (-not $noPassword.IsPresent) {
    try {
        if ([string]::IsNullOrEmpty($password)) {
            Write-Host "[+] Getting user credentials ..."
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            $credentials = Get-Credential ${Env:UserName}
        } else {
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            $credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:UserName}, $securePassword
        }
    } catch {
        Write-Host "[!] Failed to get credentials - switching to no password mode"
        $noPassword = $true
    }
}

# Install Boxstarter if needed
Write-Host "[+] Checking for Boxstarter..."
$boxstarterVersionGood = $false
try {
    if (${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
        $chocoInfo = choco info -l -r "boxstarter" 2>$null
        if ($chocoInfo) {
            $chocoInfo | ForEach-Object { 
                $name, $version = $_ -split '\|'
                if ($name -eq "boxstarter" -and $version) {
                    $boxstarterVersionGood = [System.Version]$version -ge [System.Version]"3.0.2"
                }
            }
        }
    }
} catch {
    Write-Host "[!] Error checking Boxstarter version - will attempt install"
}

if (-not $boxstarterVersionGood) {
    Write-Host "[+] Installing Boxstarter..." -ForegroundColor Cyan
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
        Get-Boxstarter -Force
    } catch {
        Write-Host "[!] Failed to install Boxstarter - continuing anyway"
    }
    Start-Sleep -Milliseconds 500
}

try {
    Import-Module "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\boxstarter.chocolatey.psd1" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Failed to import Boxstarter module - some features may not work"
}

# Check and update Chocolatey if possible
Write-Host "[+] Checking Chocolatey..."
try {
    $version = choco --version 2>$null
    if ($version) {
        Write-Host "[+] Chocolatey version: $version"
        $chocolateyVersionGood = [System.Version]$version -ge [System.Version]"2.0.0"
        if (-not $chocolateyVersionGood) { 
            Write-Host "[+] Updating Chocolatey..."
            choco upgrade chocolatey -y 2>$null
        }
    }
} catch {
    Write-Host "[!] Chocolatey check failed - continuing"
}

# Attempt to disable updates (gracefully)
Write-Host "[+] Attempting to optimize system settings..."
try {
    if (Get-Command Disable-MicrosoftUpdate -ErrorAction SilentlyContinue) {
        Disable-MicrosoftUpdate
    }
} catch {
    Write-Host "[!] Could not disable Microsoft updates - continuing"
}

try {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue -Force | Out-Null
} catch {
    Write-Host "[!] Could not disable Microsoft Store updates - continuing"
}

# Set password to never expire
try {
    Write-Host "[+] Setting password to never expire..."
    $UserNoPasswd = Get-CimInstance Win32_UserAccount -Filter "Name='${Env:UserName}'" -ErrorAction SilentlyContinue
    if ($UserNoPasswd) {
        $UserNoPasswd | Set-CimInstance -Property @{ PasswordExpires = $false } -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[!] Could not set password expiration - continuing"
}

# Set Boxstarter options
try {
    $Boxstarter.RebootOk = (-not $noReboots.IsPresent)
    $Boxstarter.NoPassword = $noPassword.IsPresent
    $Boxstarter.AutoLogin = $true
    $Boxstarter.SuppressLogging = $True
    $VerbosePreference = "SilentlyContinue"
    Set-BoxstarterConfig -NugetSources "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2;https://chocolatey.org/api/v2" -ErrorAction SilentlyContinue
    Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Some Boxstarter configuration failed - continuing"
}

# Set Chocolatey options
Write-Host "[+] Updating Chocolatey settings..."
try {
    choco sources add -n="vm-packages" -s "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2" --priority 1 -y 2>$null
    choco feature enable -n allowGlobalConfirmation 2>$null
    choco feature enable -n allowEmptyChecksums 2>$null
    $cache = "${Env:LocalAppData}\ChocoCache"
    New-Item -Path $cache -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
    choco config set cacheLocation $cache 2>$null
} catch {
    Write-Host "[!] Some Chocolatey configuration failed - continuing"
}

# Set power options to prevent installs from timing out
Write-Host "[+] Optimizing power settings..."
try {
    powercfg -change -monitor-timeout-ac 0 2>$null | Out-Null
    powercfg -change -monitor-timeout-dc 0 2>$null | Out-Null
    powercfg -change -disk-timeout-ac 0 2>$null | Out-Null
    powercfg -change -disk-timeout-dc 0 2>$null | Out-Null
    powercfg -change -standby-timeout-ac 0 2>$null | Out-Null
    powercfg -change -standby-timeout-dc 0 2>$null | Out-Null
    powercfg -change -hibernate-timeout-ac 0 2>$null | Out-Null
    powercfg -change -hibernate-timeout-dc 0 2>$null | Out-Null
} catch {
    Write-Host "[!] Power settings optimization failed - continuing"
}

Write-Host "[+] Checking for configuration file..."
$configPath = Join-Path $desktopPath "config.xml"
if ([string]::IsNullOrEmpty($customConfig)) {
    Write-Host "[+] Using default github configuration file..."
    $configSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml'
} else {
    Write-Host "[+] Using custom configuration file..."
    $configSource = $customConfig
}

Get-ConfigFile $configPath $configSource

# Check the configuration file exists, create minimal one if missing
if (-Not (Test-Path $configPath)) {
    Write-Host "[!] Configuration file missing - creating minimal config"
    $minimalConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<config>
  <envs>
    <env name="VM_COMMON_DIR" value="%USERPROFILE%\Desktop\Tools" />
    <env name="TOOL_LIST_DIR" value="%USERPROFILE%\Desktop\Tools" />
    <env name="RAW_TOOLS_DIR" value="%USERPROFILE%\Desktop\Tools\Raw" />
  </envs>
  <packages>
    <package name="common.vm" />
    <package name="debloat.vm" />
  </packages>
</config>
"@
    try {
        $minimalConfig | Out-File -FilePath $configPath -Encoding utf8
        Write-Host "[+] Created minimal configuration file"
    } catch {
        Write-Host "[!] Failed to create config file - installation may fail"
    }
}

# Get config contents
Start-Sleep 1
try {
    $configXml = [xml](Get-Content $configPath)
    Write-Host "[+] Configuration file loaded successfully"
} catch {
    Write-Host "[!] Failed to parse configuration file - using defaults"
    # Create minimal config object
    $configXml = New-Object System.Xml.XmlDocument
    $configXml.LoadXml($minimalConfig)
}

# Parse config and set initial environment variables
Write-Host "[+] Setting up environment variables..."
try {
    foreach ($env in $configXml.config.envs.env) {
        $path = [Environment]::ExpandEnvironmentVariables($($env.value))
        Write-Host "`t[+] Setting %$($env.name)% to: $path" -ForegroundColor Green
        [Environment]::SetEnvironmentVariable("$($env.name)", $path, "Machine")
    }
    [Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
    if (Get-Command refreshenv -ErrorAction SilentlyContinue) {
        refreshenv
    }
} catch {
    Write-Host "[!] Environment variable setup failed - continuing with defaults"
    # Set basic defaults
    [Environment]::SetEnvironmentVariable("VM_COMMON_DIR", "$env:USERPROFILE\Desktop\Tools", "Machine")
    [Environment]::SetEnvironmentVariable("TOOL_LIST_DIR", "$env:USERPROFILE\Desktop\Tools", "Machine")
    [Environment]::SetEnvironmentVariable("RAW_TOOLS_DIR", "$env:USERPROFILE\Desktop\Tools\Raw", "Machine")
}

# Install the common module
Write-Host "[+] Installing shared module..."
try {
    choco install common.vm -y --force 2>$null
    if (Get-Command refreshenv -ErrorAction SilentlyContinue) {
        refreshenv
    }
} catch {
    Write-Host "[!] Common module installation failed - continuing"
}

# Use single config
try {
    if ($configXml -and ${Env:VM_COMMON_DIR}) {
        $configXml.save((Join-Path ${Env:VM_COMMON_DIR} "config.xml"))
        $configXml.save((Join-Path ${Env:VM_COMMON_DIR} "packages.xml"))
    }
} catch {
    Write-Host "[!] Failed to save config files - continuing"
}

# Custom Start Layout setup
Write-Host "[+] Setting up custom Start Layout..."
try {
    $layoutPath = Join-Path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" "LayoutModification.xml"
    if ([string]::IsNullOrEmpty($customLayout)) {
        $layoutSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/LayoutModification.xml'
    } else {
        $layoutSource = $customLayout
    }
    
    # Create directory if it doesn't exist
    $layoutDir = Split-Path $layoutPath -Parent
    if (!(Test-Path $layoutDir)) {
        New-Item -ItemType Directory -Path $layoutDir -Force | Out-Null
    }
    
    Get-ConfigFile $layoutPath $layoutSource
} catch {
    Write-Host "[!] Start Layout setup failed - continuing"
}

# Log basic system information
Write-Host "[+] Gathering system information..."
try {
    if (${Env:VM_COMMON_DIR} -and (Test-Path "${Env:VM_COMMON_DIR}\vm.common\vm.common.psm1")) {
        Import-Module "${Env:VM_COMMON_DIR}\vm.common\vm.common.psm1" -Force -DisableNameChecking -ErrorAction SilentlyContinue
        if (Get-Command VM-Get-Host-Info -ErrorAction SilentlyContinue) {
            VM-Get-Host-Info
        }
    }
} catch {
    Write-Host "[!] System information gathering failed - continuing"
}

# Install debloat package
Write-Host "[+] Installing debloat and performance package..."
try {
    choco install debloat.vm -y --force 2>$null
} catch {
    Write-Host "[!] Debloat package installation failed - continuing"
}

# Download FLARE VM background image
Write-Host "[+] Setting up FLARE VM branding..."
try {
    if (${Env:VM_COMMON_DIR}) {
        $backgroundImage = "${Env:VM_COMMON_DIR}\background.png"
        Save-FileFromUrl -fileSource 'https://raw.githubusercontent.com/mandiant/flare-vm/main/Images/flarevm-background.png' -fileDestination $backgroundImage
        $lockScreenImage = "${Env:VM_COMMON_DIR}\lockscreen.png"
        Copy-Item $backgroundImage $lockScreenImage -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[!] Branding setup failed - continuing"
}

# Begin the package install
Write-Host "[+] Beginning install of configured packages..." -ForegroundColor Green
Write-Host "[+] This may take a significant amount of time depending on selected packages"

try {
    $PackageName = "installer.vm"
    if ($noPassword.IsPresent) {
        Install-BoxstarterPackage -packageName $PackageName
    } else {
        if ($credentials) {
            Install-BoxstarterPackage -packageName $PackageName -credential $credentials
        } else {
            Install-BoxstarterPackage -packageName $PackageName
        }
    }
    Write-Host "[+] Installation completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "[!] Package installation encountered errors, but may have partially completed"
    Write-Host "[!] Check C:\ProgramData\chocolatey\lib-bad for failed packages"
    Write-Host "[!] You can manually install failed packages with: choco install -y <package_name>"
}

Write-Host "[+] FLARE VM installation process finished"
Write-Host "[+] Please reboot the system to complete the installation"
