#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Get-DgSendOnBehalfPermission {
    <#
    .SYNOPSIS
        Gets the 'SendOnBehalf' permissions for a specified user in Exchange Online mailboxes.
    .DESCRIPTION
        This script retrieves 'SendOnBehalf' permissions for a specified user in Exchange Online mailboxes.
    .PARAMETER User
        The user for whom to retrieve 'SendOnBehalf' permissions.
        The user could be in the format 'username@domain.com' the SamAccountName.
    .PARAMETER ThrottleLimit
        The maximum number of concurrent operations to run in parallel. Default is 5.
    .EXAMPLE
        Get-DgSendOnBehalfPermission -User "username@domain.com"
        Retrieves 'SendOnBehalf' permissions for the specified user.
    .EXAMPLE
        'user1@domain.com' | Get-DgSendOnBehalfPermission
        Retrieves 'SendOnBehalf' permissions for the specified user with a throttle limit of 10 concurrent operations.
    .NOTES
        This script requires PowerShell 7.0 or later and the ExchangeOnlineManagement module.
        Ensure that you have the necessary permissions to run this script and access 'SendOnBehalf' permissions.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)][ValidateScript ({ Get-EXOMailbox -Identity $_ })][string]$User
    )
    
    begin {
        Get-ConnectionInformation | Out-Null
    }
    
    process {
        try {
            # Get the display name of the user
            $UserDisplayName = Get-EXOMailbox -Identity $User | Select-Object -ExpandProperty DisplayName
            # Get GrantSendOnBehalfTo permissions for the specified user
            Get-EXOMailbox -Properties GrantSendOnBehalfTo | Where-Object { $_.GrantSendOnBehalfTo -match $UserDisplayName }
        }
        catch {
            Write-Error "Error retrieving 'SendOnBehalf' permissions: $($_.Exception.Message)"
        }          
    }
}