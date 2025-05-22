function Get-DgEXORecipientPermission {
    <#
    .SYNOPSIS
        Gets the 'SendAs' permissions for a specified user in Exchange Online mailboxes.
    .DESCRIPTION
        This script retrieves 'SendAs' permissions for a specified user in Exchange Online mailboxes.
    .PARAMETER Trustee
        The user for whom to retrieve 'SendAs' permissions.
        The user should be in the format 'UPN' or 'SamAccountName'.
    .PARAMETER ThrottleLimit
        The maximum number of concurrent operations to run in parallel. Default is 5.
    .EXAMPLE
        Get-DgEXORecipientPermission -Trustee username@domain.com.
        Retrieves 'SendAs' permissions for the specified user.
    .EXAMPLE
        'user1@example.com' | Get-DgEXORecipientPermission -ThrottleLimit 10
        Retrieves 'SendAs' permissions for the specified user with a throttle limit of 10 concurrent operations.
    #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)][ValidateScript({Get-EXOMailbox -Identity $_})][string]$Trustee,
            [Parameter()][ValidateRange(2,20)][int]$ThrottleLimit = 5
        )    
        begin {
            Get-DgConnectionInformation | Out-Null
        }    
        process {
            # Get all mailboxes and filter by the specified user
            # Using -Parallel to process mailboxes concurrently for better performance.
            # Note: -Parallel requires PowerShell 7.0 or later and the script must be run in a compatible environment.
            # Using -ThrottleLimit to limit the number of concurrent operations.
            Get-EXOMailbox -ResultSize unlimited | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                Get-EXORecipientPermission -Identity $_.Identity -Trustee $using:Trustee 
            } 
        } #process        
    } #function


