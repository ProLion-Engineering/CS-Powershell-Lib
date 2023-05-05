param (
    $ip,
    $username,
    $password,
    [switch]$ProtectAllShares,
    [string[]]$DirToProtectList

)
    <#
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
        
        .LINK
        Online version: https://github.com/ProLion-Engineering/CS-Powershell-Lib/tree/main/CS-WFS

    #>

#Requires -PSEdition Core
#Requires -Version 7.0
#Requires -RunAsAdministrator
###############
# Static vars #
###############

$FSRM_FilesGroupName = "CryptoSpike"
$FSRM_FilesTemplateName = "Cryptospike-Template"
[array]$FSRMapiJsonExt = $null

###############
#  Functions  #
###############

function get-apitoken {

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

function get-blocklists {

    param(
    $ip,
    $header
    )

    $response = Invoke-WebRequest -ContentType application/json -SkipCertificateCheck -Headers $header -SkipHeaderValidation -Uri https://$ip/api/v1/server/config/apps/file-event/blocklist

    return $response

}

function update-blocklist {
    param(
    $FSRM_FilesGroupName,
    $FSRMapiJsonExt
    )

    if(Get-FsrmFileGroup -Name $FSRM_FilesGroupName -ErrorAction SilentlyContinue){

        #File group exists, Get current list
        [boolean]$FSRMExtListUpdate = $false
        $FSRMProdExt = (Get-FsrmFileGroup -Name $FSRM_FilesGroupName).IncludePattern

        #Compare
        $FSRMProdAdd = (Compare-Object -DifferenceObject $FSRMapiJsonExt -ReferenceObject $FSRMProdExt -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
        $FSRMProdDel = (Compare-Object -DifferenceObject $FSRMapiJsonExt -ReferenceObject $FSRMProdExt -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "<="}).InputObject

        #set ADD variable if Needed
        if (($FSRMProdAdd.Count -gt 0) -or ($FSRMProdDel.Count -gt 0)) {
            $FSRMExtListUpdate = $true
            $FSRMExtList = $FSRMapiJsonExt
        }else{
            $FSRMExtListUpdate = $false
        }
        if($FSRMExtListUpdate -eq $true){

            # Overwite list if needed
            Try{
                Set-FsrmFileGroup -Name $FSRM_FilesGroupName -IncludePattern $FSRMExtList -ErrorAction Stop        
            }Catch{
                Write-Error $_
                exit  
            }
        }
    }else{
        #Create group
        Try{
            New-FsrmFileGroup -Name $FSRM_FilesGroupName -IncludePattern $FSRMapiJsonExt -ErrorAction Stop
        
        }Catch{
            Write-Error $_
            exit 
        }
    }
}

function new-template {

    param(

        $FSRM_FilesTemplateName,
        $FSRM_FilesGroupName 

    )


    $FSRM_NotifEvent = New-FsrmAction -Type Event -EventType Warning `
                                        -Body "User [Source Io Owner] tried to save file [Source File Path] in [File Screen Path] on server [Server]. This pattern is included in  [Violated File Group] blocklist, it is not allowed on the server." -RunLimitInterval 30

    $FSRM_NotifEmail = New-FsrmAction -Type Email -MailTo "[Admin Email]" -Subject "Ransmoware alert !" `
                                        -Body "User [Source Io Owner] tried to save file [Source File Path] in [File Screen Path] on server [Server]. This pattern is included in  [Violated File Group] blocklist, it is not allowed on the server." -RunLimitInterval 30 


    if(Get-FsrmFileScreenTemplate -Name $FSRM_FilesTemplateName -ErrorAction SilentlyContinue){

        # Associate group to template
        if($FSRM_FilesGroupName -notin (Get-FsrmFileScreenTemplate -Name $FSRM_FilesTemplateName).IncludeGroup){
            Set-FsrmFileScreenTemplate -Name $FSRM_FilesTemplateName -IncludeGroup $FSRM_FilesGroupName
        }

    }else{

        Try{
            New-FsrmFileScreenTemplate -Name $FSRM_FilesTemplateName -Active:$True -IncludeGroup "$FSRM_FilesGroupName" -Notification $FSRM_NotifEvent,$FSRM_NotifEmail
        
        }Catch{
            write-error " $($_.Exception.Message))"   
        }
    }


}

function protect-folders {

    param(
        $DirToProtectList,
        $FSRM_FilesGroupName,
        $FSRM_FilesTemplateName
    )

    $FSRM_FileScreenProd = Get-FsrmFileScreen

    Foreach($DirToProtect in $DirToProtectList){

        if(Test-Path $DirToProtect -ErrorAction SilentlyContinue){

            # Check if 
            if($DirToProtect -in $FSRM_FileScreenProd.Path){
            
                # If the filter is already associated to file group -> OK else add
                if((Get-FsrmFileScreen -Path $DirToProtect).IncludeGroup -contains $FSRM_FilesGroupName){

                #No Change

                }else{
                    $FSRM_FilesGroupToInclude = (Get-FsrmFileScreen -Path $DirToProtect).IncludeGroup + $FSRM_FilesGroupName

                    Try{
                        Set-FsrmFileScreen -Path $DirToProtect -IncludeGroup $FSRM_FilesGroupToInclude -ErrorAction Stop

                    }Catch{
                        Write-error "Could not update FileScreen" $_
                        pause   
                        continue                   
                    }
                }

            }else{

                Try{
                    New-FsrmFileScreen -Path $DirToProtect -IncludeGroup $FSRM_FilesGroupName -Template $FSRM_FilesTemplateName -Active:$true

                }Catch{
                        Write-error "Could not update FileScreen" $_
                        pause   
                        continue
                }
            }

        }else{
            write-error -Message "$DirToProtect is not a valid path"  
        }

        Clear-Variable DirToProtect,FSRM_FilesGroupToInclude -ErrorAction SilentlyContinue
    }
    
}
###############
#  Body       #
###############

#Check if fsrm is installed and deploy if needed

if((Get-WindowsFeature -Name "FS-Resource-Manager").InstallState -eq "Available"){
    Try{
        
        Install-WindowsFeature –Name FS-Resource-Manager –IncludeManagementTools -ErrorAction Stop
        Write-Host "FSRM : OK - Installed by script" -ForegroundColor Green
    }Catch{

        Write-Host "FSRM : ERROR could not install ($($_.Exception.Message))." -ForegroundColor Red
        pause
        exit
    }
}elseif((Get-WindowsFeature -Name "FS-Resource-Manager").InstallState -eq "Installed"){

    Write-Host "FSRM : OK - Already installed" -ForegroundColor Green
}


$TokenResponse = get-apitoken -username $username -password $password -ip $ip
$header = @{"authorization" = $TokenResponse.content.split(',')[0].replace('{"token":','').replace('"','') }

$Blocklistresponse =  get-blocklists -header $header -ip $ip
$Blocklists = $Blocklistresponse | ConvertFrom-Json

foreach ( $Blocklist in $Blocklists.items) {

    foreach ($instance in $Blocklist.instances) { 
        foreach ($item in $instance.content.blocklistEntries) {
            if (( $item.name -notin $FSRMapiJsonExt) -and ($item.enabled -eq $true) -and ($item.exclusionRule -eq "") -and ($item.acknowledged -eq "True")) {
                #remove invalid characters
                $cleanitem = $item.name.Trim('/','\',':','"','|','<','>')
                $FSRMapiJsonExt = $FSRMapiJsonExt + $cleanitem
            }
        }
    }
}

#Update list of extensions to block - Add from all blocklists on CS
update-blocklist -FSRM_FilesGroupName $FSRM_FilesGroupName -FSRMapiJsonExt $FSRMapiJsonExt

# Select Folders to Protect
if($ProtectAllShares -eq $true){

    # Find all shared local paths
    $DirToProtectList = Get-CimInstance Win32_Share | Select-Object Name,Path,Type | Where-Object { ($_.Type -match  '0|2147483648') -and ($_.Path -notin $FSRM_DirToExclude) } | Select-Object -ExpandProperty Path | Select-Object -Unique 

}else{
    $DirToProtectList = $FSRM_DirToProtect
}

new-template -FSRM_FilesTemplateName $FSRM_FilesTemplateName -FSRM_FilesGroupName $FSRM_FilesGroupName
protect-folders -DirToProtectList $DirToProtectList -FSRM_FilesGroupName $FSRM_FilesGroupName -FSRM_FilesTemplateName $FSRM_FilesTemplateName



