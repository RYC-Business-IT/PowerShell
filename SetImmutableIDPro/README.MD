# MatchImmutableId PowerShell Script

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

MatchImmutableId.ps1 is a PowerShell script designed to synchronize Microsoft Entra ID (Azure AD) users with on-premises Active Directory (AD) users by matching on User Principal Name (UPN). It sets the Entra ID ImmutableId to the Base64-encoded AD objectGUID and syncs proxyAddresses from Entra ID to AD, ensuring consistency for hybrid identity environments. The script includes advanced features like duplicate proxyAddresses conflict resolution, color-coded console output, and flexible scoping options.

This script is particularly useful for resolving synchronization errors in Microsoft Entra Cloud Sync, such as AzureDirectoryServiceAttributeValueMustBeUnique, by aligning user attributes and handling conflicts interactively or automatically.

## Features

- UPN-Based Matching: Matches Entra ID and AD users by UPN for accurate identity linking.
- ImmutableId Synchronization: Sets the Entra ID ImmutableId to the AD objectGUID (Base64-encoded).
- ProxyAddresses Sync: Syncs proxyAddresses (including aliases) from Entra ID to AD before setting ImmutableId.
- Duplicate ProxyAddresses Handling:
  - Detects conflicts when a proxyAddresses is used by another AD user.
  - Prompts to remove the address from the conflicting user and add it to the target user (default).
  - Supports automatic conflict resolution with -AutoMoveProxyConflicts.
  - Allows reporting conflicts without changes.
- Color-Coded Output: Enhances console readability:
  - Info: White
  - Success: Green
  - Warning: Yellow
  - Error: Red
  - Conflict: Magenta
  - Prompt: Cyan
- Flexible Scoping: Supports matching for a single user, AD group members, OU, CSV file, or all AD users.
- Dry Run Mode: Previews actions without changes (-DryRun $true).
- Automatic Module Installation: Installs ActiveDirectory, Microsoft.Graph.Users, Microsoft.Graph.Core if missing.
- Tenant ID Extraction: Auto-extracts Entra ID tenant ID, with manual override option.
- Robust Error Handling: Logs detailed errors and continues processing where possible.
- AD Server Flexibility: Uses default domain controller or specified server (-ADServer).

## Prerequisites

- PowerShell: Version 5.1 or later (Windows PowerShell recommended; PowerShell 7 compatible with caveats).
- Operating System: Windows (domain-joined machine preferred for AD access).
- Permissions:
  - Active Directory: Read/write access to userPrincipalName, objectGUID, proxyAddresses (e.g., Domain Admin or delegated permissions).
  - Microsoft Entra ID: User.ReadWrite.All scope for Microsoft Graph (e.g., Global Administrator or User Administrator).
- Network: Access to an AD domain controller and internet for Microsoft Graph and PowerShell Gallery.
- Modules: Auto-installed if missing, but requires PowerShell Gallery access.

## Installation

1. Clone or Download the Repository:
   - Run: git clone https://github.com/RYC-Business-IT/PowerShell.git
   - Navigate: cd PowerShell/MatchImmutableId

2. Set PowerShell Execution Policy:
   - Run: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

3. Verify PowerShell Version:
   - Run: $PSVersionTable.PSVersion

## Usage

Run the script from a PowerShell console as an administrator. Use parameters to control behavior.

### Basic Example
Match a single user and preview changes:
- Run: .\MatchImmutableId.ps1 -User "fsilva@camillus.org" -DryRun $true

### Automatic Conflict Resolution
Move conflicting proxyAddresses automatically:
- Run: .\MatchImmutableId.ps1 -User "fsilva@camillus.org" -AutoMoveProxyConflicts -DryRun $true

### Apply Changes
Apply changes without dry run:
- Run: .\MatchImmutableId.ps1 -User "fsilva@camillus.org" -DryRun $false

### Other Scopes
- Group Members:
  - Run: .\MatchImmutableId.ps1 -Group "SyncUsers" -DryRun $true
- OU:
  - Run: .\MatchImmutableId.ps1 -OU "OU=Users,DC=contoso,DC=com" -DryRun $true
- CSV File (requires UPN column):
  - Run: .\MatchImmutableId.ps1 -CSV "C:\Scripts\Users.csv" -DryRun $true
- All Users:
  - Run: .\MatchImmutableId.ps1 -All -DryRun $true

### Parameters
| Parameter                | Description                                                                 | Required | Default          |
|--------------------------|-----------------------------------------------------------------------------|----------|------------------|
| -User <string>           | UPN of a single user (e.g., fsilva@camillus.org).                          | Yes*     | None             |
| -Group <string>          | AD group name for members (e.g., SyncUsers).                               | Yes*     | None             |
| -OU <string>             | AD OU (e.g., OU=Users,DC=contoso,DC=com).                                 | Yes*     | None             |
| -CSV <string>            | CSV file path with UPN column (e.g., C:\Scripts\Users.csv).                | Yes*     | None             |
| -All                     | Matches all AD users.                                                      | Yes*     | None             |
| -NoProxySync             | Skips proxyAddresses sync.                                                 | No       | False            |
| -AutoMoveProxyConflicts  | Auto-moves conflicting proxyAddresses.                                     | No       | False            |
| -DryRun                  | Previews changes ($true/$false).                                          | No       | $true            |
| -LogPath <string>        | Log file path.                                                            | No       | C:\Logs\ImmutableIdMatch_<timestamp>.log |
| -ADServer <string>       | AD domain controller (e.g., dc01.contoso.com).                            | No       | Default DC       |
| -EntraIDTenantId <string>| Entra ID tenant ID (auto-extracted if omitted).                           | No       | None             |

*One of -User, -Group, -OU, -CSV, or -All is required.

### CSV Format
For -CSV:

UPN
fsilva@camillus.org
jdoe@camillus.org


### Color-Coded Output
Console output uses colors for readability:
- White: General info (e.g., script start, user counts).
- Green: Successes (e.g., module import, proxyAddresses addition).
- Yellow: Warnings (e.g., user not found, no proxyAddresses).
- Red: Errors (e.g., AD query failures, permission issues).
- Magenta: Conflicts (e.g., duplicate proxyAddresses).
- Cyan: Prompts (e.g., conflict resolution Y/N).

Log files are plain text.

## Conflict Resolution
For duplicate proxyAddresses:
- Default (Prompt):
  - Example: Conflict: ProxyAddress smtp:fsilva_alias@camillus.org is in use by jdoe@camillus.org (CN=John Doe,OU=Users,DC=contoso,DC=com). [Magenta]
  - Prompt: Do you want to remove it from this user and add it to fsilva@camillus.org? (Y/N) [Cyan]
  - Y moves the address; other inputs skip it.
- Automatic (-AutoMoveProxyConflicts):
  - Moves the address without prompting.
- Dry Run:
  - Logs conflicts and planned actions.

## Validation
After running the script:
- Check AD proxyAddresses:
  - Run: Get-ADUser -Filter "userPrincipalName -eq 'fsilva@camillus.org'" -Properties proxyAddresses | Select-Object -ExpandProperty proxyAddresses
- Check Conflicting User’s proxyAddresses (if moved):
  - Run: Get-ADUser -Filter "userPrincipalName -eq 'jdoe@camillus.org'" -Properties proxyAddresses | Select-Object -ExpandProperty proxyAddresses
- Verify Entra ID ImmutableId:
  - Run: Connect-MgGraph -Scopes "User.Read.All"
  - Run: Get-MgUser -UserId "fsilva@camillus.org" -Property ImmutableId
  - Run: $adUser = Get-ADUser -Filter "userPrincipalName -eq 'fsilva@camillus.org'" -Properties objectGUID
  - Run: [Convert]::ToBase64String($adUser.objectGUID.ToByteArray())

## Troubleshooting
1. User Not Found:
   - Run: Get-ADUser -Filter "userPrincipalName -eq 'fsilva@camillus.org'"
   - Run: Get-MgUser -Filter "userPrincipalName eq 'fsilva@camillus.org'"

2. AD Connectivity:
   - Run: nltest /dsgetdc:$env:USERDNSDOMAIN
   - Specify -ADServer if needed:
     - Run: .\MatchImmutableId.ps1 -User "fsilva@camillus.org" -ADServer "dc01.camillus.org"

3. Permission Errors:
   - Run: whoami /all
   - Run as administrator:
     - Run: Start-Process powershell -Verb RunAs

4. Module Installation:
   - Run: Test-NetConnection -ComputerName www.powershellgallery.com -Port 443
   - Run: Install-Module -Name ActiveDirectory -Scope CurrentUser
   - Run: Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser

5. Conflicts:
   - Manually resolve:
     - Run: $conflictingUser = Get-ADUser -Filter "userPrincipalName -eq 'jdoe@camillus.org'" -Properties proxyAddresses
     - Run: $conflictingUser.proxyAddresses.Remove("smtp:fsilva_alias@camillus.org")
     - Run: Set-ADUser -Identity $conflictingUser -Replace @{proxyAddresses=$conflictingUser.proxyAddresses}

6. Logs:
   - Check C:\Logs\ImmutableIdMatch_*.log for details. Share logs for support.

## Contributing
1. Fork the repository.
2. Create a feature branch:
   - Run: git checkout -b feature/YourFeature
3. Commit changes:
   - Run: git commit -m "Add YourFeature"
4. Push to the branch:
   - Run: git push origin feature/YourFeature
5. Open a pull request on [https://github.com/RYC-Business-IT/PowerShell](https://github.com/RYC-Business-IT/PowerShell).

Update this README for new features.

## License
MIT License. See [LICENSE](LICENSE).

## Acknowledgments
- Built for RYC Business IT to streamline hybrid identity management.
- Inspired by Microsoft Entra Cloud Sync and PowerShell community resources.

## Contact
Open issues at [https://github.com/RYC-Business-IT/PowerShell/issues](https://github.com/RYC-Business-IT/PowerShell/issues).
