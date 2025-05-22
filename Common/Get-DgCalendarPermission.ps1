#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement
function Get-DgCalendarPermission {
    <#
    .SYNOPSIS
    Retrieves calendar permissions for a specified user in Exchange Online mailboxes.
    .DESCRIPTION
    This script retrieves calendar permissions for a specified user in Exchange Online mailboxes.
    It allows filtering by mailbox type (user or shared) and supports parallel processing for improved performance.
    .PARAMETER User
    The user for whom to retrieve calendar permissions.
    .PARAMETER UserMailboxOnly
        If specified, only user mailboxes will be processed. The default will search from all mailboxes.
    .PARAMETER SharedMailboxOnly
        If specified, only shared mailboxes will be processed. The default will search from all mailboxes.
    .PARAMETER ThrottleLimit
    The maximum number of concurrent operations to run in parallel. Default is 5.
    .EXAMPLE
    Get-DgCalendarPermission -User "user1@domain.com" -SharedMailboxOnly
    Retrieves calendar permissions for the specified user in shared mailboxes only.
    .EXAMPLE
    Get-DgCalendarPermission -User "user2@domain.com" -ThrottleLimit 10
    Retrieves calendar permissions for the specified user in all mailboxes with a throttle limit of 10 concurrent operations.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$User,
        [switch]$UserMailboxOnly,
        [switch]$SharedMailboxOnly,
        [ValidateRange(2,25)][int]$ThrottleLimit = 5
    )
    begin {
        # Ensure we have an active Exchange Online connection
        Get-DgConnectionInformation
    }
    process {
        if ($UserMailboxOnly) {
            $RecipientTypeDetails = 'UserMailbox'
        } elseif ($SharedMailboxOnly) {
            $RecipientTypeDetails = 'SharedMailbox'
        } else {
            $RecipientTypeDetails = @(
                'UserMailbox',
                'SharedMailbox',
                'RoomMailbox',
                'EquipmentMailbox'
            )
        }

        # Verify if the user exists in the Exchange Online environment.
        try {
            $UserToFind = Get-EXOMailbox -Identity $User -ErrorAction Stop
        }
        catch {
            Write-Error "User '$User' not found in Exchange Online: $($_.Exception.Message)"
            exit 1
        }

        # Get-EXOMailbox is a cmdlet that retrieves mailbox information from Exchange Online.
        $FilteredMailboxes = Get-EXOMailbox -RecipientTypeDetails $RecipientTypeDetails

        # Using -Parallel to process mailboxes concurrently for better performance.
        # Note: -Parallel requires PowerShell 7.0 or later and the script must be run in a compatible environment.
        $FilteredMailboxes | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Using $using: to access variables from the parent scope in the parallel block.
            # Note: Ensure that the script is run in a context that supports parallel execution (e.g., PowerShell 7.0+).

            # Assign each object to a $Mailbox variable for clarity.
            # The $_ variable represents the current object in the pipeline.
            $Mailbox = $_
            try {
                # Get-EXOMailboxFolderPermission retrieves the permissions for the specified mailbox folder.
                # The -Identity parameter specifies the mailbox and folder to check permissions for to which the $User will be checked against.
                $Permissions = Get-EXOMailboxFolderPermission -Identity "$($Mailbox.UserPrincipalName):\Calendar" | Where-Object {$_.User -like "*$($using:UserToFind.UserPrincipalName)*"}

                # Check if the permissions are not null or empty before processing.
                if ($Permissions) {
                    foreach ($Permission in $Permissions) {
                        [PSCustomObject][ordered]@{
                            Identity         = "$($Mailbox.UserPrincipalName):\Calendar"
                            FolderName       = $Permission.FolderName
                            User             = $Permission.User
                            AccessRights     = $Permission.AccessRights
                            SharingPermissionFlags = if ($Permission.PSObject -and $Permission.PSObject.Properties.Match('SharingPermissionFlags')) { $Permission.SharingPermissionFlags } else { $null }
                        }
                    }
                }            
            }
            catch {
                Write-Warning "Error retrieving mailbox: $($Mailbox.UserPrincipalName). Error: $_"
            }            
        }

        # if ($Results) {
        #     # Output the results to the console or pipeline.
        #     $Results
        # }
        # else {
        #     Write-Warning "No calendar permissions found in any '$($RecipientTypeDetails -join ", ")' for user: $User"
        # }
    }
}