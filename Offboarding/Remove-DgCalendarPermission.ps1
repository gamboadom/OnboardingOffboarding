#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Remove-DgCalendarPermission {
    <#
    .SYNOPSIS
    Removes calendar permissions for a specified user from target mailboxes in Exchange Online.
    .DESCRIPTION
    This script removes calendar permissions for a specified user from the Calendar folder of target mailboxes in Exchange Online.
    It allows specifying the user whose permissions should be removed and supports processing target mailboxes via pipeline input or by specifying the -Identity parameter directly.
    It also supports filtering by mailbox type (user or shared) for the target mailboxes and parallel processing for improved performance.
    .PARAMETER Identity
    The UPN or primary SMTP address of the mailbox(es) from which the calendar permission will be removed.
    Accepts pipeline input.
    .PARAMETER User
    The UPN or primary SMTP address of the user whose calendar permission will be revoked.
    .EXAMPLE
    Remove-DgCalendarPermission -Identity "mailbox1@domain.com" -User "user1@domain.com"
    Removes all calendar permissions for user1@domain.com from the calendar of mailbox1@domain.com.
    .EXAMPLE
    Get-EXOMailbox -RecipientTypeDetails SharedMailbox | Remove-DgCalendarPermission -User "exemployee@domain.com" -ThrottleLimit 10
    Removes all calendar permissions for exemployee@domain.com from the calendars of all shared mailboxes.
    .EXAMPLE
    "mailbox2@domain.com", "mailbox3@domain.com" | Remove-DgCalendarPermission -User "guest@domain.com"
    Removes calendar permissions for guest@domain.com from mailbox2@domain.com and mailbox3@domain.com.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)][string[]]$Identity,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)][Alias('UserToRemove')][string]$User
    )
    begin {
        # Ensure we have an active Exchange Online connection
        Get-DgConnectionInformation
    }
    process {
        # Check if the Identity exists in the Exchange Online environment.
        foreach ($Id in $Identity) {
            try {
                $MailboxUPN = $Id.Split(':')[0]
                $TargetMailboxId = Get-EXOMailbox -Identity $MailboxUPN -ErrorAction Stop
                if ($TargetMailboxId) {
                    try {
                        # Remove the calendar permission
                        Remove-MailboxFolderPermission -Identity "$($TargetMailboxId.UserPrincipalName):\Calendar" -User $User -Confirm:$false -ErrorAction Stop
                        Write-Host "Successfully removed calendar permissions for '$User' from '$($TargetMailboxId.UserPrincipalName):\Calendar'"
                    }
                    catch {
                        Write-Warning "Failed to remove calendar permissions for '$User' from '$($TargetMailboxId.UserPrincipalName):\Calendar'. Error:  $($_.Exception.Message)"
                    }                    
                }
            }
            catch {
                Write-Warning "Target mailbox '$($TargetMailboxId.UserPrincipalName)' not found."
                continue
            }
        }
    }
}