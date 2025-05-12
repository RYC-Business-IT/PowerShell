# MatchImmutableId PowerShell Script

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

`MatchImmutableId.ps1` is a PowerShell script designed to synchronize Microsoft Entra ID (Azure AD) users with on-premises Active Directory (AD) users by matching on User Principal Name (UPN). It sets the Entra ID `ImmutableId` to the Base64-encoded AD `objectGUID` and syncs `proxyAddresses` from Entra ID to AD, ensuring consistency for hybrid identity environments. The script includes advanced features like duplicate `proxyAddresses` conflict resolution, color-coded console output, and flexible scoping options.

This script is particularly useful for resolving synchronization errors in Microsoft Entra Cloud Sync, such as `AzureDirectoryServiceAttributeValueMustBeUnique`, by aligning user attributes and handling conflicts interactively or automatically.

## Features

- **UPN-Based Matching**: Matches Entra ID and AD users by UPN for accurate identity linking.
- **ImmutableId Synchronization**: Sets the Entra ID `ImmutableId` to the AD `objectGUID` (Base64-encoded).
- **ProxyAddresses Sync**: Syncs `proxyAddresses` (including aliases) from Entra ID to AD before setting `ImmutableId`.
- **Duplicate ProxyAddresses Handling**:
  - Detects conflicts when a `proxyAddresses` is used by another AD user.
  - Prompts to remove the address from the conflicting user and add it to the target user (default).
  - Supports automatic conflict resolution with `-AutoMoveProxyConflicts`.
  - Allows reporting conflicts without changes.
- **Color-Coded Output**: Enhances console readability:
  - Info: White
  - Success: Green
  - Warning: Yellow
  - Error: Red
  - Conflict: Magenta
  - Prompt: Cyan
- **Flexible Scoping**: Supports matching for a single user, AD group members, OU, CSV file, or all AD users.
- **Dry Run Mode**: Previews actions without changes (`-DryRun $true`).
- **Automatic Module Installation**: Installs `ActiveDirectory`, `Microsoft.Graph.Users`, `Microsoft.Graph.Core` if missing.
- **Tenant ID Extraction**: Auto-extracts Entra ID tenant ID, with manual override option.
- **Robust Error Handling**: Logs detailed errors and continues processing where possible.
- **AD Server Flexibility**: Uses default domain controller or specified server (`-ADServer`).

## Prerequisites

- **PowerShell**: Version 5.1 or later (Windows PowerShell recommended; PowerShell 7 compatible with caveats).
- **Operating System**: Windows (domain-joined machine preferred for AD access).
- **Permissions**:
  - **Active Directory**: Read/write access to `userPrincipalName`, `objectGUID`, `proxyAddresses` (e.g., Domain Admin or delegated permissions).
  - **Microsoft Entra ID**: `User.ReadWrite.All` scope for Microsoft Graph (e.g., Global Administrator or User Administrator).
- **Network**: Access to an AD domain controller and internet for Microsoft Graph and PowerShell Gallery.
- **Modules**: Auto-installed if missing, but requires PowerShell Gallery access.

## Installation

### Local Setup
1. **Clone or Download the Repository**:
   ```bash
   git clone https://github.com/RYC-Business-IT/PowerShell.git
   cd PowerShell/MatchImmutableId
