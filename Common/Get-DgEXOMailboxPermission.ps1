#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Get-DgEXOMailboxPermission {
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
        Get-DgEXOMailboxPermission -User "username@domain.com"
        Retrieves mailbox permissions for the specified user.
    .EXAMPLE
        'user1@domain.com' | Get-DgEXOMailboxPermission -ThrottleLimit 10
        Retrieves mailbox permissions for the specified user with a throttle limit of 10 concurrent operations.
    .NOTES
        This script requires PowerShell 7.0 or later and the ExchangeOnlineManagement module.
        Ensure that you have the necessary permissions to run this script and access mailbox permissions.
        The script uses parallel processing to improve performance when retrieving mailbox permissions.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][string]$User,
        [Parameter()][ValidateRange(2,20)][int]$ThrottleLimit = 5
    )
    
    begin {
        Get-DgConnectionInformation | Out-Null
    }
    
    process {
        try {
            # Get all mailboxes and filter by the specified user
            # Using -Parallel to process mailboxes concurrently for better performance.
            # Note: -Parallel requires PowerShell 7.0 or later and the script must be run in a compatible environment.
            # Using -ThrottleLimit to limit the number of concurrent operations.
            # Note: -ThrottleLimit requires PowerShell 7.0 or later.
            Get-EXOMailbox -ResultSize unlimited | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                Get-EXOMailboxPermission -Identity $_.PrimarySmtpAddress | Where-Object { $_.User -match $using:User }
            }    
        }
        catch {
            Write-Error "Error retrieving mailbox permissions: $($_.Exception.Message)"
        }
        
    }
}