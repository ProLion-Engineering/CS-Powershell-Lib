# CS-WFS

Two scripts aimed at extending CryptoSpike's functionality to Windows File Server.
    FSRM-CS-Blocklist.ps1   : Leverages Microsft's File Server Ressource Manager file filters to extend blocklist functionality to Windows
    block-wfs.ps1           : Blocks user access to smb file share on local server based on blocked users in CryptoSpike Application.

# block-wfs.ps1

    .DESCRIPTION
    Blocks user access to smb file share on local server based on blocked users in CryptoSpike Application.
    Should be ran on a schedule in order to update blocked users on the local SMB shares. Administrative shares are not modified.
    Use of the $Sync parameter will remove all explicit blocks on protected shares not linked to a blocked user in CryptoSpike.
    CryptoSpike 3.0.17P1 or newer required. Requires Powershell 7.

    .EXAMPLE
    PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" 
    Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.

    .EXAMPLE
    PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" -sync
    Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.
    Will also remove Unblocked users from the server.

    .USAGE
    The script should be ran frequently (every couple of minutes) using the windows task scheduler. In order to make changes, the task must be executed with admin privilege

    .PARAMETER ip
    Specifies the ip of the CryptoSpike Leader Machine

    .PARAMETER username
    Specifies the username used to query the CryptoSpike Leader Machine. The user must be able to read blocked users.

    .PARAMETER password
    Specifies the password used to query the CryptoSpike Leader Machine

    .PARAMETER sync
    Use script in sync mode, will remove block permissions no longer needed.

    .INPUTS
    None. You cannot pipe objects to block-wfs.ps1.

    .OUTPUTS
    None.

# FSRM-CS-Blocklist.ps1

    .SYNOPSIS
    Leverages windows server ressource manager and it's file filter feature. Imports and updates the filter depending on the blocklist defined on CryptoSpike
    Requires Powershell 7.

    .DESCRIPTION
    Leverages windows server ressource manager and it's file filter feature. Imports and updates the filter depending on the blocklist defined on CryptoSpike.
    Should be ran on a schedule in order to update file filters when the blocklist is updated on CryptoSpike.
    The file filter will be set in active mode.
    CryptoSpike 3.0.17P1 or newer required. Requires Powershell 7.

    .PARAMETER ip
    Specifies the ip of the CryptoSpike Leader Machine

    .PARAMETER username
    Specifies the username used to query the CryptoSpike Leader Machine. The user must be able to read blocked users.

    .PARAMETER password
    Specifies the password used to query the CryptoSpike Leader Machine

    .PARAMETER ProtectAllShares
    Will list all shares on the server and derive the paths to protect from them.

    .PARAMETER DirToProtectList
    Only used if Protectallshares is not. Defines the directories to protect

    .INPUTS
    None. You cannot pipe objects to FSRM-CS-Blocklist.ps1.

    .OUTPUTS
    None.

    .EXAMPLE
    PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" 
    Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.

    .EXAMPLE
    PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" -sync
    Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.
    Will also remove Unblocked users from the server.