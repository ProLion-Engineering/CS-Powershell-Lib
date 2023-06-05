param (
    [string]$ip,
    [string]$username,
    $password,
    [switch]$sync

)
    <#
        .SYNOPSIS
        Blocks user access to smb file share on local server based on blocked users in CryptoSpike Application. CryptoSpike 3.0.17P1 or newer required.
        Requires Powershell 7.

        .DESCRIPTION
        Blocks user access to smb file share on local server based on blocked users in CryptoSpike Application.
        Should be ran on a schedule in order to update blocked users on the local SMB shares. Administrative shares are not modified.
        Use of the $Sync parameter will remove all explicit blocks on protected shares not linked to a blocked user in CryptoSpike.
        CryptoSpike 3.0.17P1 or newer required. Requires Powershell 7.

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

        .EXAMPLE
        PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" 
        Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.

        .EXAMPLE
        PS> .\block-wfs.ps1 -ip 1.1.1.1 -username "readonly" -password "string" -sync
        Will query CryptoSpike for all Windows blocked users and block them on the local Windows File Server.
        Will also remove Unblocked users from the server.
        
        .LINK
        Online version: https://github.com/ProLion-Engineering/CS-Powershell-Lib/tree/main/CS-WFS

    #>

#Requires -PSEdition Core
#Requires -Version 7.0
#Requires -RunAsAdministrator

###############
#  Functions  #
###############

function get-CSapitoken {

    param(
    $ip,
    $username,
    $password
    )

    $Body = @{
        username = $username
        password = $password
    }

    $JsonBody = $Body | ConvertTo-Json

    $response = Invoke-WebRequest -Uri https://$ip/api/v1/Server/auth/login -Method Post -Body $JsonBody -ContentType application/json -SkipCertificateCheck

    #$token = $raw.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | where-object { $_ -like "Set-Cookie:*"}
    #$token = $token.replace('Set-Cookie: auth-refresh-token=Bearer%20','').split(';')[0]


    return $response

}

function get-CSblockedusers {

    param(
        $ip,
        $header
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri "https://$ip/api/v1/audit/users?blocked=true"

    return $response

}

###############
# Processing  #
###############

#Get token
$TokenResponse = get-CSapitoken -username $username -password $password -ip $ip
$header = @{"authorization" = $TokenResponse.content.split(',')[0].replace('{"token":','').replace('"','') }

#Get Blocked users from CS
$BlockedUsers = (get-CSblockedusers -ip $ip -header $header).content | ConvertFrom-Json

$localshares  = get-smbshare | Where-Object {$_.Special -ne $True}

#In sync mode remove all deny not matching a blocked user otherwise only add

foreach ($share in $localshares) {

    if ($sync) {

        $DenyPermissions = Get-SmbShareAccess -name $share.Name | Where-Object { $_.AccessControlType -eq '1'}

        foreach ($Deny in $DenyPermissions) {

            $username = $Deny.AccountName.split('\')[1]

            if ($username -notin $BlockedUsers.items.username) {

                Unblock-SmbShareAccess -name $share.name -AccountName $Deny.AccountName -Force

            }

        }


    }
 
    foreach ($user in ($BlockedUsers.items | Where-Object {$_.userIdType -eq "WINDOWS"})) {

        if ($user.resolvedState -ne "RESOLVED" ) {

            
            $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$($user.userId)")
            try {
                $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            }
            catch{
                #Principal can not be translated
                Write-Warning -Message "could not resolve $($user.userid)"
                continue
            }
            Block-SmbShareAccess -name $share.name -AccountName $objUser.value -Force | Out-Null

        }
        else {
            Block-SmbShareAccess -name $share.name -AccountName $user.userprincipalname -Force | Out-Null
        }
    }
    

}