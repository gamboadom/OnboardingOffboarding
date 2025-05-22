#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

#region Remove-DgMailboxPermission
# function Remove-DgMailboxPermission {
#     <#
#     .SYNOPSIS
#         Gets the mailbox permissions for a specified user in Exchange Online mailboxes.
#     .DESCRIPTION
#         This script retrieves mailbox permissions for a specified user in Exchange Online mailboxes.
#     .PARAMETER User
#         The user for whom to retrieve mailbox permissions.
#         The user should be in the format 'username@domain.com'.
#     .PARAMETER ThrottleLimit
#         The maximum number of concurrent operations to run in parallel. Default is 5.
#     .EXAMPLE
#         Remove-DgMailboxPermission -User "username@domain.com"
#         Retrieves mailbox permissions for the specified user.
#     .EXAMPLE
#         'user1@domain.com' | Remove-DgMailboxPermission -ThrottleLimit 10
#         Retrieves mailbox permissions for the specified user with a throttle limit of 10 concurrent operations.
#     .NOTES
#         This script requires PowerShell 7.0 or later and the ExchangeOnlineManagement module.
#         Ensure that you have the necessary permissions to run this script and access mailbox permissions.
#         The script uses parallel processing to improve performance when retrieving mailbox permissions.
#     #>
#     [CmdletBinding()]
#     param (
#         [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][ValidateScript ({ Get-EXOMailbox -Identity $_ })][string]$User,
#         [Parameter()][ValidateRange(2,20)][int]$ThrottleLimit = 5
#     )
    
#     begin {
#         Get-ConnectionInformation | Out-Null
#     }
    
#     process {

#         # Get the mailbox permissions for the specified user
#         Get-DgEXOMailboxPermission -User $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
#             # Remove the mailbox permissions for the specified user
#             Remove-EXOMailboxPermission -Identity $_.Identity -User $using:User -Confirm:$false
#             Write-Output "Removed mailbox permission for user '$($using:User)' from mailbox '$($_.Identity)'."
#         }

#         # Get the 'SendAs' permissions for the specified user
#         Get-DgEXORecipientPermission -Trustee $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
#             # Remove the 'SendAs' permissions for the specified user
#             Remove-EXORecipientPermission -Identity $_.Identity -Trustee $using:User -Confirm:$false
#             Write-Output "Removed 'SendAs' permission for user '$($using:User)' from mailbox '$($_.Identity)'."
#         }
        
#         # Get the 'SendOnBehalf' permissions for the specified user
#         Get-DgSendOnBehalfPermission -User $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
#             # Remove the 'SendOnBehalf' permissions for the specified user
#             Set-Mailbox -Identity $_.Identity -GrantSendOnBehalfTo @{Remove=$using:User}
#             Write-Output "Removed 'SendOnBehalf' permission for user '$($using:User)' from mailbox '$($_.Identity)'."
#         }
        
#     }
# }
#endregion Remove-DgMailboxPermission

function Remove-DgMailboxPermission {
    <#
    .SYNOPSIS
        Gets the mailbox permissions for a specified user in Exchange Online mailboxes.
    .DESCRIPTION
        This script retrieves mailbox permissions for a specified user in Exchange Online mailboxes.
    .PARAMETER User
        The user for whom to retrieve mailbox permissions.
        The user should be in the format 'username@domain.com'.
    .PARAMETER ThrottleLimit
        The maximum number of concurrent operations to run in parallel. Default is 5.
    .EXAMPLE
        Remove-DgMailboxPermission -User "username@domain.com"
        Retrieves mailbox permissions for the specified user.
    .EXAMPLE
        'user1@domain.com' | Remove-DgMailboxPermission -ThrottleLimit 10
        Retrieves mailbox permissions for the specified user with a throttle limit of 10 concurrent operations.
    .NOTES
        This script requires PowerShell 7.0 or later and the ExchangeOnlineManagement module.
        Ensure that you have the necessary permissions to run this script and access mailbox permissions.
        The script uses parallel processing to improve performance when retrieving mailbox permissions.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][ValidateScript ({ Get-EXOMailbox -Identity $_ })][string]$User,
        [Parameter()][ValidateRange(2,20)][int]$ThrottleLimit = 5
    )
    
    begin {
        Get-ConnectionInformation | Out-Null
    }
    
    process {
        # Get all mailboxes
        $allMailboxes = Get-EXOMailbox -ResultSize unlimited -Properties GrantSendOnBehalfTo

        # Get the mailbox permissions for the specified user
        $fullAccess = $allMailboxes | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            Get-EXOMailboxPermission -Identity $_.PrimarySmtpAddress | Where-Object { $_.User -match $using:User }
        }

        Get-DgEXOMailboxPermission -User $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Remove the mailbox permissions for the specified user
            Remove-EXOMailboxPermission -Identity $_.Identity -User $using:User -Confirm:$false
            Write-Output "Removed mailbox permission for user '$($using:User)' from mailbox '$($_.Identity)'."
        }

        # Get the 'SendAs' permissions for the specified user
        Get-DgEXORecipientPermission -Trustee $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Remove the 'SendAs' permissions for the specified user
            Remove-EXORecipientPermission -Identity $_.Identity -Trustee $using:User -Confirm:$false
            Write-Output "Removed 'SendAs' permission for user '$($using:User)' from mailbox '$($_.Identity)'."
        }
        
        # Get the 'SendOnBehalf' permissions for the specified user
        Get-DgSendOnBehalfPermission -User $User | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Remove the 'SendOnBehalf' permissions for the specified user
            Set-Mailbox -Identity $_.Identity -GrantSendOnBehalfTo @{Remove=$using:User}
            Write-Output "Removed 'SendOnBehalf' permission for user '$($using:User)' from mailbox '$($_.Identity)'."
        }
        
    }
}