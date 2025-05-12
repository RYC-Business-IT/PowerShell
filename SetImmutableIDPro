<#
.SYNOPSIS
    Matches Microsoft Entra ID users with AD users based on UPN, syncs proxyAddresses to AD, and sets the ImmutableId.
.DESCRIPTION
    This script links Microsoft Entra ID users to on-premises AD users by setting the Entra ID ImmutableId to the Base64-encoded AD objectGUID.
    It syncs proxyAddresses from Entra ID to AD before setting ImmutableId, checking for duplicates. For duplicate proxyAddresses, it prompts to remove from conflicting users and add to the target user, with an option for automatic reassignment or reporting only.
    Supports scoping to a single user, AD group members, OU, CSV file, or all AD users. Automatically installs missing modules and extracts tenant ID if not provided. Console output is color-coded for better visibility.
.PARAMETER User
    Specifies a single user to match by UPN (e.g., fsilva@camillus.org).
.PARAMETER Group
    Specifies an AD group whose members will be matched (e.g., SyncUsers).
.PARAMETER OU
    Specifies an AD OU to match users from (e.g., OU=Users,DC=contoso,DC=com).
.PARAMETER CSV
    Specifies a CSV file with a UPN column to match users (e.g., C:\Scripts\Users.csv).
.PARAMETER All
    Matches all AD users in the domain.
.PARAMETER NoProxySync
    Skips syncing proxyAddresses from Entra ID to AD.
.PARAMETER AutoMoveProxyConflicts
    Automatically removes conflicting proxyAddresses from other users and adds them to the target user without prompting.
.PARAMETER DryRun
    If $true, previews changes without applying them. Default: $true.
.PARAMETER LogPath
    Path for the log file. Default: C:\Logs\ImmutableIdMatch_<timestamp>.log.
.PARAMETER ADServer
    AD domain controller (optional, e.g., dc01.contoso.com).
.PARAMETER EntraIDTenantId
    Microsoft Entra ID tenant ID (optional; extracted automatically if not provided).
.EXAMPLE
    .\MatchImmutableId.ps1 -User "fsilva@camillus.org"
    Matches a single user, syncs proxyAddresses (prompting for conflicts), and updates ImmutableId with color-coded output.
.EXAMPLE
    .\MatchImmutableId.ps1 -Group "SyncUsers" -NoProxySync -DryRun $false
    Matches group members, skips proxyAddresses sync, and applies ImmutableId changes.
.EXAMPLE
    .\MatchImmutableId.ps1 -User "fsilva@camillus.org" -AutoMoveProxyConflicts -DryRun $false
    Matches a user, automatically reassigns conflicting proxyAddresses, and applies changes.
#>

[CmdletBinding(DefaultParameterSetName="None")]
param (
    [Parameter(ParameterSetName="User", Mandatory=$true)]
    [string]$User,

    [Parameter(ParameterSetName="Group", Mandatory=$true)]
    [string]$Group,

    [Parameter(ParameterSetName="OU", Mandatory=$true)]
    [string]$OU,

    [Parameter(ParameterSetName="CSV", Mandatory=$true)]
    [string]$CSV,

    [Parameter(ParameterSetName="All", Mandatory=$true)]
    [switch]$All,

    [Parameter()]
    [switch]$NoProxySync,

    [Parameter()]
    [switch]$AutoMoveProxyConflicts,

    [Parameter()]
    [bool]$DryRun = $true,

    [Parameter()]
    [string]$LogPath = "C:\Logs\ImmutableIdMatch_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [Parameter()]
    [string]$ADServer,

    [Parameter()]
    [string]$EntraIDTenantId
)

# Initialize logging with color coding
$null | Out-File -FilePath $LogPath -Force
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info" # Info, Success, Warning, Error, Conflict
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    
    # Color-coded console output
    switch ($Level) {
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Conflict" { Write-Host $logMessage -ForegroundColor Magenta }
        default   { Write-Host $logMessage -ForegroundColor White } # Info
    }
    
    # Plain text to log file
    $logMessage | Out-File -FilePath $LogPath -Append
}

Write-Log "Starting ImmutableId matching script. DryRun: $DryRun, ParameterSet: $($PSCmdlet.ParameterSetName), NoProxySync: $NoProxySync, AutoMoveProxyConflicts: $AutoMoveProxyConflicts"

# Validate parameters
$validParameterSets = "User", "Group", "OU", "CSV", "All"
if ($PSCmdlet.ParameterSetName -eq "None") {
    Write-Log "Error: You must specify one of -User, -Group, -OU, -CSV, or -All." -Level Error
    exit
}

# Check and install required modules
$requiredModules = @(
    @{Name = "ActiveDirectory"; MinVersion = "1.0.1.0"},
    @{Name = "Microsoft.Graph.Users"; MinVersion = "2.0.0"; Dependencies = @("Microsoft.Graph.Core")}
)
foreach ($module in $requiredModules) {
    $installedModule = Get-Module -Name $module.Name -ListAvailable | 
                      Where-Object { [version]$_.Version -ge [version]$module.MinVersion } | 
                      Select-Object -First 1
    if (-not $installedModule) {
        Write-Log "Module $($module.Name) not found. Attempting to install..." -Level Warning
        try {
            # Install dependencies first (if any)
            if ($module.Dependencies) {
                foreach ($dep in $module.Dependencies) {
                    Write-Log "Installing dependency $dep for $($module.Name)..."
                    Install-Module -Name $dep -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Write-Log "Successfully installed $dep." -Level Success
                }
            }
            Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Log "Successfully installed $($module.Name)." -Level Success
        } catch {
            Write-Log "Error installing $($module.Name): $_" -Level Error
            exit
        }
    } else {
        Write-Log "Module $($module.Name) already installed (version $($installedModule.Version))."
    }
}

# Import required modules with retry
$modulesToImport = @("ActiveDirectory", "Microsoft.Graph.Users")
foreach ($module in $modulesToImport) {
    $retryCount = 0
    $maxRetries = 2
    $success = $false
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            Import-Module $module -ErrorAction Stop
            Write-Log "Successfully imported $module." -Level Success
            $success = $true
        } catch {
            $retryCount++
            Write-Log "Error importing $module (attempt $retryCount/$maxRetries): $_" -Level Error
            if ($retryCount -lt $maxRetries) {
                Write-Log "Retrying after refreshing module path..." -Level Warning
                $env:PSModulePath = [System.Environment]::GetEnvironmentVariable("PSModulePath", "User") + ";" + [System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
                Start-Sleep -Seconds 2
            } else {
                Write-Log "Failed to import $module after $maxRetries attempts. Please manually install the module and try again." -Level Error
                exit
            }
        }
    }
}

# Connect to Microsoft Graph
try {
    Connect-MgGraph -Scopes "User.ReadWrite.All" -ErrorAction Stop
    Write-Log "Connected to Microsoft Graph." -Level Success
} catch {
    Write-Log "Error connecting to Microsoft Graph: $_" -Level Error
    exit
}

# Get tenant ID if not provided
if (-not $EntraIDTenantId) {
    try {
        $context = Get-MgContext -ErrorAction Stop
        $EntraIDTenantId = $context.TenantId
        Write-Log "Extracted tenant ID: $EntraIDTenantId" -Level Success
        Write-Log "Warning: Ensure this is the correct tenant ID for your environment." -Level Warning
    } catch {
        Write-Log "Error retrieving tenant ID: $_" -Level Error
        Write-Log "Please provide -EntraIDTenantId explicitly." -Level Error
        exit
    }
} else {
    Write-Log "Using provided tenant ID: $EntraIDTenantId"
}

# Determine default domain controller if ADServer is not specified
$adServerParam = @{}
if ($ADServer) {
    $adServerParam = @{Server = $ADServer}
    Write-Log "Using specified AD server: $ADServer"
} else {
    try {
        $defaultDC = (Get-ADDomainController -Discover).HostName
        Write-Log "Using default domain controller: $defaultDC"
    } catch {
        Write-Log "Error discovering default domain controller: $_" -Level Error
        Write-Log "Please specify -ADServer or ensure AD connectivity." -Level Error
        exit
    }
}

# Define user scope
$adUsers = @()
switch ($PSCmdlet.ParameterSetName) {
    "All" {
        Write-Log "Retrieving all AD users."
        try {
            $adUsers = Get-ADUser -Filter * -Properties userPrincipalName,objectGUID,proxyAddresses @adServerParam -ErrorAction Stop
        } catch {
            Write-Log "Error retrieving AD users: $_" -Level Error
            exit
        }
    }
    "OU" {
        Write-Log "Retrieving AD users from OU: $OU."
        try {
            $adUsers = Get-ADUser -Filter * -SearchBase $OU -Properties userPrincipalName,objectGUID,proxyAddresses @adServerParam -ErrorAction Stop
        } catch {
            Write-Log "Error retrieving AD users from OU ${OU}: $_" -Level Error
            exit
        }
    }
    "CSV" {
        Write-Log "Retrieving AD users from CSV: $CSV."
        try {
            $csvUsers = Import-Csv -Path $CSV
            foreach ($csvUser in $csvUsers) {
                $upn = $csvUser.UPN
                $adUser = Get-ADUser -Filter "userPrincipalName -eq '$upn'" -Properties userPrincipalName,objectGUID,proxyAddresses @adServerParam -ErrorAction Stop
                if ($adUser) { $adUsers += $adUser }
            }
        } catch {
            Write-Log "Error processing CSV users: $_" -Level Error
            exit
        }
    }
    "User" {
        Write-Log "Retrieving AD user with UPN: $User."
        try {
            $adUser = Get-ADUser -Filter "userPrincipalName -eq '$User'" -Properties userPrincipalName,objectGUID,proxyAddresses @adServerParam -ErrorAction Stop
            if ($adUser) {
                $adUsers += $adUser
            } else {
                Write-Log "No AD user found for UPN: $User. Verify the UPN or AD connectivity." -Level Warning
                exit
            }
        } catch {
            Write-Log "Error retrieving AD user with UPN ${User}: $_" -Level Error
            Write-Log "Possible causes: Incorrect UPN, AD server unreachable, or insufficient permissions." -Level Error
            exit
        }
    }
    "Group" {
        Write-Log "Retrieving members of AD group: $Group."
        try {
            $groupObject = Get-ADGroup -Filter "Name -eq '$Group'" @adServerParam -ErrorAction Stop
            if ($groupObject) {
                $adUsers = Get-ADGroupMember -Identity $groupObject -Recursive | 
                           Get-ADUser -Properties userPrincipalName,objectGUID,proxyAddresses @adServerParam -ErrorAction Stop
            } else {
                Write-Log "Group not found: $Group." -Level Warning
                exit
            }
        } catch {
            Write-Log "Error retrieving group members: $_" -Level Error
            exit
        }
    }
}

Write-Log "Found $($adUsers.Count) AD users."

# Get Microsoft Entra ID users
try {
    $entraUsers = Get-MgUser -All -Property UserPrincipalName,Id,ImmutableId,ProxyAddresses -ErrorAction Stop
    Write-Log "Retrieved $($entraUsers.Count) Microsoft Entra ID users." -Level Success
} catch {
    Write-Log "Error retrieving Microsoft Entra ID users: $_" -Level Error
    exit
}

# Match users, sync proxyAddresses, and update ImmutableId
$matchCount = 0
$noMatchCount = 0
$errorCount = 0

foreach ($adUser in $adUsers) {
    $adUPN = $adUser.userPrincipalName
    $adObjectGUID = $adUser.objectGUID
    if (-not $adUPN -or -not $adObjectGUID) {
        Write-Log "Skipping AD user with missing UPN or objectGUID: $($adUser.DistinguishedName)" -Level Warning
        $errorCount++
        continue
    }

    # Find matching Microsoft Entra ID user by UPN
    $entraUser = $entraUsers | Where-Object { $_.UserPrincipalName -eq $adUPN }
    if ($entraUser) {
        Write-Log "Match found for UPN: ${adUPN} (AD GUID: $adObjectGUID, Entra ID: $($entraUser.Id))"

        # Sync proxyAddresses from Entra ID to AD (before ImmutableId)
        if (-not $NoProxySync) {
            $entraProxyAddresses = $entraUser.ProxyAddresses
            if ($entraProxyAddresses) {
                Write-Log "Found $($entraProxyAddresses.Count) proxyAddresses for ${adUPN}: $($entraProxyAddresses -join ', ')"
                $currentADProxyAddresses = $adUser.proxyAddresses | ForEach-Object { $_ }

                foreach ($proxyAddress in $entraProxyAddresses) {
                    # Skip if already in AD for this user
                    if ($currentADProxyAddresses -contains $proxyAddress) {
                        Write-Log "ProxyAddress $proxyAddress already exists for ${adUPN}. Skipping."
                        continue
                    }

                    # Check for duplicates in AD (excluding the target user)
                    try {
                        $conflictingUsers = Get-ADUser -Filter "ProxyAddresses -eq '$proxyAddress'" -Properties userPrincipalName,proxyAddresses @adServerParam -ErrorAction Stop |
                                            Where-Object { $_.DistinguishedName -ne $adUser.DistinguishedName }
                        if ($conflictingUsers) {
                            foreach ($conflictingUser in $conflictingUsers) {
                                Write-Log "Conflict: ProxyAddress $proxyAddress is in use by $($conflictingUser.userPrincipalName) ($($conflictingUser.DistinguishedName))." -Level Conflict
                                if ($DryRun) {
                                    Write-Log "[DryRun] Would prompt to resolve conflict for $proxyAddress." -Level Conflict
                                    $errorCount++
                                    continue
                                }

                                $moveAddress = $AutoMoveProxyConflicts
                                if (-not $AutoMoveProxyConflicts) {
                                    Write-Host "Conflict: ProxyAddress $proxyAddress is in use by $($conflictingUser.userPrincipalName) ($($conflictingUser.DistinguishedName))." -ForegroundColor Magenta
                                    Write-Host "Do you want to remove it from this user and add it to ${adUPN}? (Y/N)" -ForegroundColor Cyan
                                    $response = Read-Host
                                    $moveAddress = $response -eq 'Y' -or $response -eq 'y'
                                }

                                if ($moveAddress) {
                                    # Remove from conflicting user
                                    try {
                                        $conflictingUser.proxyAddresses.Remove($proxyAddress)
                                        Set-ADUser -Identity $conflictingUser -Replace @{proxyAddresses=$conflictingUser.proxyAddresses} @adServerParam -ErrorAction Stop
                                        Write-Log "Successfully removed proxyAddress $proxyAddress from $($conflictingUser.userPrincipalName)." -Level Success
                                    } catch {
                                        Write-Log "Error removing proxyAddress $proxyAddress from $($conflictingUser.userPrincipalName): $_" -Level Error
                                        $errorCount++
                                        continue
                                    }

                                    # Add to target user
                                    try {
                                        Set-ADUser -Identity $adUser -Add @{proxyAddresses=$proxyAddress} @adServerParam -ErrorAction Stop
                                        Write-Log "Successfully added proxyAddress $proxyAddress to ${adUPN}" -Level Success
                                    } catch {
                                        Write-Log "Error adding proxyAddress $proxyAddress to ${adUPN}: $_" -Level Error
                                        $errorCount++
                                        continue
                                    }
                                } else {
                                    Write-Log "Skipping proxyAddress $proxyAddress due to user choice or -AutoMoveProxyConflicts not set." -Level Warning
                                    $errorCount++
                                    continue
                                }
                            }
                        } else {
                            # No conflict, add proxyAddress to target user
                            if ($DryRun) {
                                Write-Log "[DryRun] Would add proxyAddress $proxyAddress to ${adUPN}"
                            } else {
                                try {
                                    Set-ADUser -Identity $adUser -Add @{proxyAddresses=$proxyAddress} @adServerParam -ErrorAction Stop
                                    Write-Log "Successfully added proxyAddress $proxyAddress to ${adUPN}" -Level Success
                                } catch {
                                    Write-Log "Error adding proxyAddress $proxyAddress to ${adUPN}: $_" -Level Error
                                    $errorCount++
                                    continue
                                }
                            }
                        }
                    } catch {
                        Write-Log "Error checking for duplicate proxyAddress ${proxyAddress}: $_" -Level Error
                        $errorCount++
                        continue
                    }
                }
            } else {
                Write-Log "No proxyAddresses found for ${adUPN} in Entra ID." -Level Warning
            }
        } else {
            Write-Log "Skipping proxyAddresses sync for ${adUPN} due to -NoProxySync."
        }

        # Convert objectGUID to Base64 (ImmutableId format)
        $immutableId = [Convert]::ToBase64String($adObjectGUID.ToByteArray())

        # Check if ImmutableId already matches
        if ($entraUser.ImmutableId -eq $immutableId) {
            Write-Log "ImmutableId already matches for ${adUPN}. No update needed." -Level Success
            $matchCount++
            continue
        }

        # Update ImmutableId
        if ($DryRun) {
            Write-Log "[DryRun] Would update ImmutableId for ${adUPN} to $immutableId"
        } else {
            try {
                Update-MgUser -UserId $entraUser.Id -OnPremisesImmutableId $immutableId -ErrorAction Stop
                Write-Log "Successfully updated ImmutableId for ${adUPN} to $immutableId" -Level Success
                $matchCount++
            } catch {
                Write-Log "Error updating ImmutableId for ${adUPN}: $_" -Level Error
                $errorCount++
            }
        }
    } else {
        Write-Log "No Microsoft Entra ID user found for UPN: ${adUPN}" -Level Warning
        $noMatchCount++
    }
}

# Summary
Write-Log "Script completed. Summary:"
Write-Log " - Matched and processed: $matchCount users" -Level Success
Write-Log " - No match found: $noMatchCount users" -Level Warning
Write-Log " - Errors: $errorCount" -Level Error
Write-Log "Log file: $LogPath"

# Disconnect from Microsoft Graph
Disconnect-MgGraph -ErrorAction SilentlyContinue
Write-Log "Disconnected from Microsoft Graph." -Level Success
