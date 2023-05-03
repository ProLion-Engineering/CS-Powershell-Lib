param (
    $ip,
    $username,
    $password,
    $xlsxfile

)

#Prereq

#check if we have module and install if not

try {
    Import-Module ImportExcel
}
catch{
    Install-Module ImportExcel -ErrorAction SilentlyContinue
    Import-Module ImportExcel -ErrorAction SilentlyContinue
}
finally {
    if ( $null -eq (Get-Command -Module importExcel)) {
        Write-Warning -Message 'this script requires importexcel module and it could not be installed'
        pause
        exit
    }
}

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

function get-CSclusters {

    param(
        $ip,
        $header
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/clusters

    return $response
}

function get-CSSvms {

    param(
        $ip,
        $header,
        $clusterId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/clusters/$clusterId/servers

    return $response
    
}

function get-CSSVMstatus {

    param(
        $ip,
        $header,
        $serverId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/subscription/assignments/servers/$serverId/status?refresh=false

    return $response
    
}

function get-CSSVMShares {

    param(
        $ip,
        $header,
        $serverId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/servers/$serverId/shares

    return $response


}

function get-CSSVMPolicies {

    param(
        $ip,
        $header,
        $serverId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/fileevent/$serverId/policies

    return $response

}

function get-CSSVMVolumes {

    param(
        $ip,
        $header,
        $serverId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/servers/$serverId/volumes

    return $response

}

function get-CSVolShares {

    param(
        $ip,
        $header,
        $VolumeId
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/cluster/volumes/$VolumeId/shares

    return $response


}

###############
# Processing  #
###############

#Get token
$TokenResponse = get-CSapitoken -username $username -password $password -ip $ip
$header = @{"authorization" = $TokenResponse.content.split(',')[0].replace('{"token":','').replace('"','') }

#Build Data Model

$clusters = (get-CSclusters -ip $ip -header $header).content | ConvertFrom-Json

[int]$c = 0
foreach ($cluster in $clusters) {

    Add-Member -MemberType NoteProperty -InputObject $clusters[$c] -Name Svms -Value ((get-CSSvms -ip $ip -header $header -clusterId $cluster.id).content | ConvertFrom-Json)

    [int]$s = 0

    foreach ($svm in $clusters[$c].Svms) {
        
        Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s] -Name Status -Value ((get-CSSVMstatus -ip $ip -header $header -serverId $svm.id).content | ConvertFrom-Json) -Force
        Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s] -Name Policies -Value ((get-CSSVMPolicies -ip $ip -header $header -serverId $svm.id).content | ConvertFrom-Json)
        Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s] -Name Volumes -Value ((get-CSSVMVolumes -ip $ip -header $header -serverId $svm.id).content | ConvertFrom-Json)

        [int]$v = 0

        foreach ($volume in $clusters[$c].Svms[$s].Volumes) {
            
            Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s].Volumes[$v] -Name SVM -Value $clusters[$c].Svms[$s].name #If only I had a Partent property I would not have to do this!
            Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s].Volumes[$v] -Name Shares -Value ((get-CSVolShares -ip $ip -header $header -VolumeId $volume.id).content | ConvertFrom-Json)
            
            [int]$sa = 0
            
            foreach ($Share in $clusters[$c].Svms[$s].Volumes[$v].shares) {

                Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s].Volumes[$v].shares[$sa] -Name SVM -Value $clusters[$c].Svms[$s].name #If only I had a Partent property I would not have to do this!
                Add-Member -MemberType NoteProperty -InputObject $clusters[$c].Svms[$s].Volumes[$v].shares[$sa] -Name Volume -Value $clusters[$c].Svms[$s].Volumes[$v].name #If only I had a Partent property I would not have to do this!
            
                $sa++
            }
            $v++
        }
        $s++
    }
    $c++
}


#Export


$clusters | Select-Object -Property id, 
    name,
    @{ Name = 'HostName'; Expression = {$_.connection.host}},
    status,
    @{ Name = 'sslEnabled'; Expression = {$_.connection.sslEnabled}},
    @{ Name = 'username'; Expression = {$_.connection.username}} | 
     Export-Excel -AutoSize -StartRow 2 -TableName "Clusters" -Path $xlsxfile -WorksheetName "Clusters" 

$clusters.svms | Select-Object -Property id,`
    name,
    @{ Name = 'status'; Expression = {$_.status.healthyStatus}},
    @{ Name = 'engineType'; Expression = {$_.status.engineType}},
    @{ Name = 'Cluster'; Expression = {$_.cluster.name}} |
     Export-Excel -AutoSize -StartRow 2 -TableName "SVMS" -Path $xlsxfile -WorksheetName "SVMS" 

$clusters.svms.volumes | Select-Object -Property id,
    name,
    managed,
    volumetype,
    SVM |
    Export-Excel -AutoSize -StartRow 2 -TableName "Volumes" -Path $xlsxfile -WorksheetName "Volumes"

$clusters.svms.volumes.shares | Select-Object -Property id,
    name,
    path,
    managed,
    SVM,
    Volume |
    Export-Excel -AutoSize -StartRow 2 -TableName "Shares" -Path $xlsxfile -WorksheetName "Shares"

