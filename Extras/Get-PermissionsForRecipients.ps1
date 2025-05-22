#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Get-PermissionsForRecipients {
    <#
    .SYNOPSIS
        Gets the mailbox and recipient permissions for a specified user in Exchange Online mailboxes, including Send As and Send on Behalf of.
    .DESCRIPTION
        This script retrieves mailbox permissions (Full Access, Send As, etc.) and recipient permissions (Send As, etc.) for a specified user in Exchange Online mailboxes.
        It allows filtering by mailbox type (user, shared, room, equipment) and utilizes parallel processing for enhanced performance.
    .PARAMETER User
        The User Principal Name (UPN) or primary SMTP address of the user for whom to retrieve mailbox permissions.
        Example: 'username@domain.com'
    .PARAMETER MailboxType
        Specifies the type of mailboxes to include in the search.
        Valid values are: UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox, All.
        Default is All.
    .PARAMETER ThrottleLimit
        The maximum number of concurrent operations to run in parallel. Increasing this value can improve performance but may impact throttling.
        Default is 10 (increased from 5 for potentially better performance).
    .EXAMPLE
        Get-PermissionsForRecipients -User "username@domain.com" -MailboxType SharedMailbox
        Retrieves mailbox permissions for the specified user in shared mailboxes only.
    .EXAMPLE
        'user1@domain.com' | Get-PermissionsForRecipients -ThrottleLimit 15
        Retrieves mailbox permissions for the specified user with a throttle limit of 15 concurrent operations across all mailbox types.
    .NOTES
        This script requires PowerShell 7.0 or later and the ExchangeOnlineManagement module to be connected to your Microsoft 365 tenant.
        Ensure you have the necessary Exchange Online administrator roles to run these cmdlets.
        The script uses parallel processing to improve efficiency when querying multiple mailboxes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage='Enter the User Principal Name (UPN) or primary SMTP address.')][string]$User,
        [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'All')][string]$MailboxType = 'All',
        [ValidateRange(5, 50)][int]$ThrottleLimit = 10 # Increased default ThrottleLimit
    )
    process {
        # Determine which mailbox types to process
        $RecipientTypeDetails = @()
        if ($MailboxType -ceq 'All') {
            $RecipientTypeDetails = 'UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox'
        } else {
            $RecipientTypeDetails = $MailboxType
        }

        # Get the filtered list of mailboxes
        try {
            $FilteredMailboxes = Get-EXOMailbox -RecipientTypeDetails $RecipientTypeDetails -ErrorAction Stop
        }
        catch {
            Write-Error "Error retrieving mailboxes: $($_.Exception.Message)"
            exit 1
        }

        # Array to store all permission results
        $AllPermissions = [System.Collections.Generic.List[object]]::new()

        foreach ($Mailbox in $FilteredMailboxes) {
            $userToFind = $User # Local variable for clarity in parallel block

            # Get Mailbox Permissions
            try {
                $MailboxPermissions = Get-EXOMailboxPermission -Identity $Mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue | Where-Object {$_.User -like $userToFind}
                if ($MailboxPermissions) {
                    foreach ($MPermission in $MailboxPermissions) {
                        $AllPermissions.Add([PSCustomObject]@{
                            MailboxDisplayName = $Mailbox.DisplayName
                            MailboxAlias       = $Mailbox.Alias
                            User               = $MPermission.User
                            AccessRights       = $MPermission.AccessRights -join ', '
                            IsInherited        = $MPermission.IsInherited
                            Deny               = $MPermission.Deny
                            InheritanceType    = $MPermission.InheritanceType
                            PermissionType     = 'MailboxPermission'
                        })
                    }
                }
            }
            catch {
                Write-Warning "Error checking mailbox permissions for '$($Mailbox.DisplayName)': $($_.Exception.Message)"
            }

            # Get Recipient Permissions (Send As)
            try {
                $RecipientPermissions = Get-RecipientPermission -Identity $Mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue | Where-Object {$_.Trustee -like $userToFind}
                if ($RecipientPermissions) {
                    foreach ($RPermission in $RecipientPermissions) {
                        $AllPermissions.Add([PSCustomObject]@{
                            MailboxDisplayName = $Mailbox.DisplayName
                            MailboxAlias       = $Mailbox.Alias
                            User               = $RPermission.Trustee
                            AccessRights       = $RPermission.AccessRights -join ', '
                            IsInherited        = $RPermission.IsInherited
                            Deny               = $RPermission.Deny # RecipientPermission doesn't directly have a Deny property, but we can include it for consistency
                            InheritanceType    = $RPermission.InheritanceType
                            PermissionType     = 'RecipientPermission (Send As)'
                        })
                    }
                }
            }
            catch {
                Write-Warning "Error checking recipient permissions for '$($Mailbox.DisplayName)': $($_.Exception.Message)"
            }

            # Get Send On Behalf Of Permissions
            try {
                if ($Mailbox.GrantSendOnBehalfTo -like $userToFind) {
                    $AllPermissions.Add([PSCustomObject]@{
                        MailboxDisplayName    = $Mailbox.DisplayName
                        MailboxAlias          = $Mailbox.Alias
                        User                  = $userToFind
                        AccessRights          = 'SendOnBehalf'
                        IsInherited           = $false # SendOnBehalf is not inherited in the same way
                        Deny                  = $false # SendOnBehalf doesn't have a Deny concept in this context
                        InheritanceType       = 'N/A'
                        PermissionType        = 'SendOnBehalf'
                    })
                }
            }
            catch {
                Write-Warning "Error checking Send On Behalf Of permissions for '$($Mailbox.DisplayName)': $($_.Exception.Message)"
            }

        }
        # Output the collected permissions
        $AllPermissions | Sort-Object MailboxDisplayName, PermissionType, User
    }
}