#Requires -version 7.0
# Requires -Modules ActiveDirectory, Microsoft.Graph, Microsoft.Graph.Users, ExchangeOnlineManagement, Microsoft.Entra


function Get-DgEmployeeServices {
    <#
    .SYNOPSIS
        Collects all IT relevant details about an IT user corresponding to the IT assets and access provided.
    .DESCRIPTION
        Collects all IT relevant details about an IT user corresponding to the IT assets and access provided.
    .EXAMPLE
        Get-DgEmployeeServices -User userid -ComputerName fileservername -PathForAllShares '\\filesrvername\d$'
        This will show all the employee details in the console.
    .EXAMPLE
        $user = Get-DgEmployeeServices -User userid -ComputerName fileservername -PathForAllShares '\\filesrvername\d$'
        This will put all employee details in a variable. You can then expand each property, for example, "$user.Group".
    #>
        [CmdletBinding()]
        param (
            # SamAccountName or UPN
            [Parameter(Mandatory)][string]$User,
            [Parameter(Mandatory)][string]$FileServerName,
            [Parameter(Mandatory)][string]$AdminShareName
    
        ) 
        process {
            # Check details of new user        
            $ADUser = Get-ADUser $User -Properties *
            $Ht = @{}         
            $Ht = [ordered]@{
                GivenName = $ADUser.GivenName
                Initials = $ADUser.Initials
                Surname = $ADUser.Surname
                Title = $ADUser.Title
                Department = $ADUser.Department 
                OfficePhone = $ADUser.OfficePhone            
                UserPrincipalName = $ADUser.UserPrincipalName
                SamAccountName = $ADUser.SamAccountName
                Company = $ADUser.Company
                Office = $ADUser.Office
            } 
            # Show membership to AD Groups
            Get-ADPrincipalGroupMembership -Identity $ADUser.SamAccountName | ForEach-Object {$Ht.ADGroups += @($_.Name)}
            
            # Show access to any Smb Folder in fileserver        
            Get-DgAclPerUser -Path "\\$FileServerName\$AdminShareName" -Identity $ADUser.SamAccountName | ForEach-Object {$Ht.SmbShareAccess += @($_.FolderName)}
    
            # Check if there's a shared User Folder
            $SharePath = "\\$FileServerName\$($ADUser.SamAccountName)"
            if (Test-Path -Path $SharePath) {
                $Ht.UserFolderShare += $SharePath
            } 
    
            # Show ntfs permissions for the user's SmbFolder
            $AclPath = "\\$FileServerName\$($ADUser.SamAccountName)"
            if (Test-Path -Path $AclPath) {
                $SmbFolderAcl = (Get-Acl -Path $AclPath).Access
                foreach ($SmbACE in $SmbFolderAcl) {
                    if ($SmbACE.IdentityReference -like "*$($ADUser.SamAccountName)*") {
                        $Ht.UserFolderPermissions += @($SmbACE.FileSystemRights)
                    }
                }
            }        
    
            # Check if MS365 license is assigned
            # Get-DgAzureADUserLicenseDetail -ObjectId $ADUser.UserPrincipalName
            Get-DgMgContext
            Get-MgUserLicenseDetail -UserId $ADUser.UserPrincipalName | 
            ForEach-Object { $Ht.MS365License += @($_.SkuPartNumber) } 
    
            # Check membership to distribution groups
            Get-DgDistributionGroup -Member $ADUser.SamAccountName | 
            ForEach-Object { $Ht.Group += @($_.DisplayName)} 
            
            # Check entra group memberships
            Get-EntraUserMembership -UserId $ADUser.UserPrincipalName | ForEach-Object { $Ht.EntraGroup += @($_.displayName) }
            
            # Check for any mailbox permissions        
            $Full = Get-DgEXOMailboxPermission -User $ADUser.UserPrincipalName
            if (-not($null -eq $Full)) {
                foreach ($Perm in $Full) {
                    if ($Perm.AccessRights -like 'FullAccess') {
                        $Ht.FullAccess += @($Perm.Identity)
                    }
                }
            }
            $SendAs = Get-DgEXORecipientPermission -Trustee $ADUser.UserPrincipalName
            if (-not($null -eq $SendAs)) {
                foreach ($Perm in $SendAs) {
                    $Ht.SendAs += @($Perm.Identity)
                }
            }
            $SendOnBehalf = Get-DgSendOnBehalfPermission -User $ADUser.UserPrincipalName
            if (-not($null -eq $SendOnBehalf)) {
                foreach ($Perm in $SendOnBehalf) {
                    $Ht.SendOnBehalf += @($Perm.Identity)
                }
            }
            $Calendar = Get-DgCalendarPermission -User $ADUser.UserPrincipalName
            if (-not($null -eq $Calendar)) {
                foreach ($Perm in $Calendar) {
                    $Ht.Calendar += @($Perm.Identity)
                }
            }
            # Check if included in BlindCopyTo of any transport rule
            Get-TransportRule | Where-Object { $_.BlindCopyTo -match $ADUser.UserPrincipalName } | ForEach-Object {$Ht.TransportRulesBlindCopyTo += @($_)}
            
            # Check if included in SentTo property of any transport rule
            $SentTo = Get-DgTransportRuleSentTo -EmailAddress $ADUser.UserPrincipalName 
            if (!$null -eq $SentTo) {
                foreach ($S in $SentTo) {
                    $Ht.TransportRuleSentTo += @($SentTo)
                }            
            }
            $Ht
            # $Ht.GetEnumerator().ForEach({ "$($_.Name)=$($_.Value)" })
    
        }
    }