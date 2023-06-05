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
