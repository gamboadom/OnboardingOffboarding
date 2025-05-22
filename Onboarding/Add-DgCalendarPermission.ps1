#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Add-DgCalendarPermission {
    <#
    .SYNOPSIS
    Adds calendar permissions for a specified user to target mailboxes in Exchange Online.
    .DESCRIPTION
    This script adds calendar permissions for a specified user to the Calendar folder of target mailboxes in Exchange Online.
    It allows specifying the permission level and supports filtering by mailbox type (user or shared) and parallel processing for improved performance.
    .PARAMETER TargetMailbox
    The UPN or primary SMTP address of the mailbox to which the calendar permission will be added.
    .PARAMETER UserToAdd
    The UPN or primary SMTP address of the user to whom the calendar permission will be granted.
    .PARAMETER AccessRights
    The calendar permission level to grant to the UserToAdd. Valid values include:
    None, FreeBusyTimeOnly, FreeBusyTimeAndSubjectAndLocation, Reviewer, Contributor, Editor, Delegate, Owner.
    .EXAMPLE
    Add-DgCalendarPermission -TargetMailbox "sharedmailbox1@domain.com" -UserToAdd "user1@domain.com" -AccessRights Reviewer
    Adds Reviewer permission for user1@domain.com to the calendar of sharedmailbox1@domain.com.
    .EXAMPLE
    Get-EXOMailbox -Identity shared1@domain.com | Add-DgCalendarPermission -UserToAdd "delegateuser@domain.com" -AccessRights Editor 
    Adds Editor permission for delegateuser@domain.com to the calendars of all user mailboxes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Identity')][string]$TargetMailbox,
        [Parameter(Mandatory=$true)][string]$UserToAdd,
        [Parameter(Mandatory=$true)][ValidateSet('None', 'FreeBusyTimeOnly', 'FreeBusyTimeAndSubjectAndLocation', 'Reviewer', 'Contributor', 'Editor', 'Delegate', 'Owner')][string]$AccessRights
    )
    begin {
        # Ensure we have an active Exchange Online connection
        Get-DgConnectionInformation
    }
    process {
        # Get the target mailbox
        try {
            # Check if the mailbox exists in the Exchange Online environment.
            $TargetMailboxId = $TargetMailbox.Split(':')[0]
            $TargetM = Get-EXOMailbox -Identity $TargetMailboxId -ErrorAction Stop
            if ($TargetM) {              
                try {
                    # Check if the user exists in the Exchange Online environment.                
                    $UserToAddInTargetM = Get-EXOMailbox -Identity $UserToAdd -ErrorAction Stop
                    if ($UserToAddInTargetM) {
                        # Check if the user already has permissions on the target mailbox calendar                    
                        $ExistingPermissions = Get-EXOMailboxFolderPermission -Identity "$($TargetM.UserPrincipalName):\Calendar" | Where-Object {$_.User -like "*$($UserToAddInTargetM.UserPrincipalName)*"}
                        
                        if (-not $ExistingPermissions) {
                            try {
                                # Add the calendar permission
                                Add-MailboxFolderPermission -Identity "$($TargetM.UserPrincipalName):\Calendar" -User $($UserToAddInTargetM.UserPrincipalName) -AccessRights $AccessRights -ErrorAction Stop | Out-Null # Suppress output
                                # Check if the permission was added successfully
                                Write-Host "Successfully added '$AccessRights' permission to '$($TargetM.UserPrincipalName):\Calendar' for user:'$($UserToAddInTargetM.UserPrincipalName)'"
                            } catch {
                                Write-Warning "Failed to add calendar permission to '$($TargetM.UserPrincipalName):\Calendar' for user:'$($UserToAddInTargetM.UserPrincipalName)'. Error: $($_.Exception.Message)"
                            }
                        } else {
                            Write-Warning "Existing permissions found on '$($TargetM.UserPrincipalName):\Calendar' for user:'$($UserToAddInTargetM.UserPrincipalName)'. No changes made."
                        }
                    } else {
                        Write-Warning "User '$($UserToAddInTargetM.UserPrincipalName)' not found in target mailbox '$($TargetM.UserPrincipalName)'. Existing."
                        exit
                    }                
                } catch {
                    Write-Warning "User '$UserToAdd' not found."
                    exit
                }
            }
        } catch {
            Write-Warning "Target mailbox '$($TargetMailboxId)' not found."
            exit
        }        
    }
}