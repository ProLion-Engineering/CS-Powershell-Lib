param (
    [string]$ip,
    [string]$username,
    $password,
    [switch]$sync

)
#CS minimum version 3.0.17P2
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

                Unblock-SmbShareAccess -name $share.name -AccountName $username -Force

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