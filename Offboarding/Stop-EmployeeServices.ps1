function Stop-EmployeeServices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateScript({ Get-ADUser $_ })][string]$Identity,
        [Parameter(Mandatory)][string]$FileServerName,
        [Parameter(Mandatory)][string]$AdminShareName,
        [Parameter(Mandatory)][string]$EntraConnectServerName  
        
    )
    process {   

        # 1. Identify the account of the user
        $User = Get-ADUser -Identity $Identity

        # 2. Remove membership from all AD Groups except from 'Domain Users'
        Get-ADPrincipalGroupMembership -Identity $User.SamAccountName | Where-Object {$_.Name -ne 'Domain Users'} |
            ForEach-Object { 
                Remove-ADPrincipalGroupMembership -MemberOf $_.Name -Identity $User.SamAccountName -Confirm:$false
                Write-Output "User: '$($User.SamAccountName)' has been removed from group '$($_.Name)'." 
            }

        # 3. Remove all permissions for the user from all folders in the path
        Get-DgAclPerUser -Path "\\$FileServerName\$AdminShareName" -Identity $User.SamAccountName | Set-DgAclv2 -Remove                
        
        # 4. Stop sharing User's SmbFolder
        Remove-DgSmbShare -Name $User.SamAccountName -ComputerName $FileServerName -Verbose
        Pause

        # 5. Move SmbFolder to Archive         
        $Path = "\\$FileServerName\$AdminShareName\$($User.SamAccountName)"
        $Destination = "\\$FileServerName\e$\"
        Move-DgFolder -Path $Path -Destination $Destination -Verbose
        Pause

        # Sync Entra Connect
        Start-DgADSyncSyncCycle -ComputerName $EntraConnectServerName | Out-Null

        # Connect to Entra
        Connect-Entra
 
        # 6. Check and remove the user from all Entra groups
        Get-EntraUserMembership -UserId $User.UserPrincipalName | 
        ForEach-Object { Remove-DgEntraGroupMember -UserPrincipalName $User.UserPrincipalName -GroupName $_.displayName }

        # Connect to Exchange Online
        # Get-DgConnectionInformation is already called in the function

        # 7. Check and remove User's email address from email distribution group
        $DGroups = Get-DgDistributionGroup -Member $User.UserPrincipalName | Select-Object -ExpandProperty DisplayName
        if ($DGroups.Count -ge 1) {
            $DGroups | ForEach-Object { Remove-DistributionGroupMember -Identity $_ -Member $User.UserPrincipalName }
        }
        Pause
        

        # 8. Remove the user from all transport rules where the user is Bcc'd
        $associatedTRules = Get-TransportRule | Where-Object { $_.BlindCopyTo -match $User.UserPrincipalName }
        $associatedTRules | ForEach-Object { Set-DgTransportRuleBcc -Identity $_.Identity -BlindCopyTo $User.UserPrincipalName -Remove -Verbose }
        Pause

        # 9. Check and remove any mailbox permissions
        Remove-DgMailboxPermissionv2 -User $User.UserPrincipalName        
        Pause

        # 10. Convert mailbox to shared
        $IfSharedMailbox = Get-EXOMailbox -Identity $User.UserPrincipalName | Select-Object -ExpandProperty RecipientTypeDetails
        if (-not($IfSharedMailbox -eq 'SharedMailbox')) {
            Set-Mailbox -Identity $User.UserPrincipalName -Type Shared
            Write-Output "UserMailbox: '$($User.UserPrincipalName)' has been converted to "'SharedMailbox'"."
        }

        # Need to run Start-ADSyncSyncCycle delta
        Start-DgADSyncSyncCycle -ComputerName $EntraConnectServerName | Out-Null
        Start-Sleep 2         
        
        # Need to close ExchangeOnline and AzureAD sessions
        Disconnect-ExchangeOnline
        # Disconnect-AzureAD

    }
}

# Remaining manual steps:
#1. Remove the user's MS365 license
#2. Move the user's AD account to the 'Disabled' OU and disable the account
#3. Remove the user's biometric access from the system
#4. Delete the user's CUCM device and extension
#5. Delete the user's CUCM account and Cisco Unity voicemail account
#6. Retrieve the user's IT equipment and accessories based on the IT custody form

