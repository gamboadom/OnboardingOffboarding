<#
.SYNOPSIS
Removes FullAccess, SendAs, and SendOnBehalf permissions granted to a specified user
from Exchange Online mailboxes and recipients.

.DESCRIPTION
This function connects to Exchange Online (using Get-DgConnectionInfo, assumed
to handle the connection) and then finds and removes FullAccess, SendAs, and
SendOnBehalf permissions that have been explicitly granted to the user specified
by the -User parameter on other mailboxes or recipients.

It supports the standard PowerShell -Confirm and -WhatIf parameters.

.PARAMETER User
The Email Address or User Principal Name (UPN) of the user whose permissions
should be removed. This parameter is mandatory.

.INPUTS
None.

.OUTPUTS
None. The function performs actions (removes permissions) and provides output
via Write-Host, Write-Warning, and Write-Error.

.NOTES
Requires the Exchange Online PowerShell module (EXO V2 or later) to be installed
and connected. The function assumes that 'Get-DgConnectionInfo' handles the
connection setup.

FullAccess permissions that are inherited (e.g., via security groups) are
typically not removed by Remove-MailboxPermission and are excluded by default.

SendOnBehalf permissions are removed by modifying the GrantSendOnBehalfTo property
of the target mailbox.

.EXAMPLE
Remove-DgMailboxPermissionv2 -User "user@example.com"

Description:
Finds and prompts to remove FullAccess, SendAs, and SendOnBehalf permissions
granted to user@example.com.

.EXAMPLE
Remove-DgMailboxPermissionv2 -User "user@example.com" -Confirm:$false

Description:
Finds and removes FullAccess, SendAs, and SendOnBehalf permissions granted
to user@example.com without prompting for confirmation for each removal.

.EXAMPLE
Remove-DgMailboxPermissionv2 -User "user@example.com" -WhatIf

Description:
Shows what permissions would be removed for user@example.com without actually
performing the removal.
#>
function Remove-DgMailboxPermissionv2 {
    [CmdletBinding(SupportsShouldProcess)] # Add SupportsShouldProcess and Verbose
    param (
        # Email ID or UPN of the user whose permissions are to be removed
        [Parameter(Mandatory)][ValidateScript({ Get-EXORecipient -Identity $_ })][string]$User
    )

    begin {
        # Ensure connection is established - assuming Get-DgConnectionInfo does this
        Write-Verbose "Ensuring connection to Exchange Online..."
        try {
            Get-DgConnectionInformation | Out-Null # This should check if the connection is valid
        }
        catch {
            Write-Error "Failed to establish connection to Exchange Online. Original error: $($_.Exception.Message)"
            # Exit the function if connection fails
            return
        }

        # Get the target user's object once
        Write-Verbose "Retrieving user object for '$User'..."
        try {
            # Use Get-EXORecipient as it's more flexible for user/group/mail contact
            $TargetUser = Get-EXORecipient -Identity $User -ErrorAction Stop
            $TargetUserIdentity = $TargetUser.Identity # Use Identity for cmdlets
            $TargetUserDisplayName = $TargetUser.DisplayName # Use DisplayName for messages
            # DistinguishedName is needed for the SendOnBehalf filter
            $TargetUserDistinguishedName = $TargetUser.DistinguishedName
            Write-Verbose "Target User Identity: $($TargetUserIdentity)"
            Write-Verbose "Target User Display Name: $($TargetUserDisplayName)"
            Write-Verbose "Target User Distinguished Name: $($TargetUserDistinguishedName)"

        }
        catch {
            Write-Error "Could not find user '$User'. Please verify the email address or UPN. Original error: $($_.Exception.Message)"
            # Exit the function if user is not found
            return
        }
    }

    process {
        Write-Host "`nSearching for permissions granted to '$TargetUserDisplayName' ($TargetUserIdentity)..."

        # --- Find FullAccess Permissions ---
        Write-Verbose "Searching for FullAccess permissions..."
        $FullAccessPermissionsFound = @() # Array to store found permissions
        try {
            # Get all mailboxes and iterate to check permissions on each
            Write-Verbose "Getting all mailboxes to check FullAccess permissions..."
            $AllMailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop

            Write-Verbose "Checking permissions on $($AllMailboxes.Count) mailboxes..."
            foreach ($Mailbox in $AllMailboxes) {
                try {
                    # Get permissions for the current mailbox and filter for the target user
                    $PermissionsOnMailbox = Get-EXOMailboxPermission -Identity $Mailbox.Identity -ErrorAction SilentlyContinue |
                                            Where-Object { ($_.User -eq $TargetUserIdentity) -and ($_.AccessRights -match 'FullAccess') -and (-not $_.IsInherited) }

                    if ($PermissionsOnMailbox) {
                        $FullAccessPermissionsFound += $PermissionsOnMailbox
                        Write-Verbose "Found FullAccess permission for '$TargetUserDisplayName' on mailbox '$($Mailbox.Identity)'."
                    }
                }
                catch {
                    Write-Warning "Could not retrieve permissions for mailbox '$($Mailbox.Identity)'. Skipping this mailbox. Original error: $($_.Exception.Message)"
                }
            }

            if ($FullAccessPermissionsFound.Count -gt 0) {
                Write-Host "Found $($FullAccessPermissionsFound.Count) mailbox(es) with explicit FullAccess permission granted to '$TargetUserDisplayName'."
                foreach ($Perm in $FullAccessPermissionsFound) {
                    $TargetMailboxIdentity = $Perm.Identity
                    # Use ShouldProcess for standard confirmation/whatif support
                    if ($PSCmdlet.ShouldProcess("Remove FullAccess permission for '$TargetUserDisplayName' from mailbox '$TargetMailboxIdentity'", "Removing FullAccess Permission")) {
                        try {
                            Remove-MailboxPermission -Identity $TargetMailboxIdentity -User $TargetUserIdentity -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
                            Write-Host "Successfully removed FullAccess permission for '$TargetUserDisplayName' from '$TargetMailboxIdentity'." -ForegroundColor Green
                        }
                        catch {
                            Write-Error "Failed to remove FullAccess permission for '$TargetUserDisplayName' from '$TargetMailboxIdentity'. Original error: $($_.Exception.Message)"
                        }
                    }
                }
            } else {
                Write-Host "No explicit FullAccess permissions found for '$TargetUserDisplayName'." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "An error occurred while searching for FullAccess permissions. Original error: $($_.Exception.Message)"
        }


        # --- Find SendAs Permissions ---
        Write-Verbose "Searching for SendAs permissions..."
         $SendAsPermissionsFound = @() # Array to store found permissions
        try {
            # Get all recipients and iterate to check permissions on each
            Write-Verbose "Getting all recipients to check SendAs permissions..."
            # Get-EXORecipient includes mailboxes, mail users, mail contacts, etc.
            $AllRecipients = Get-EXORecipient -ResultSize Unlimited -ErrorAction Stop

            Write-Verbose "Checking permissions on $($AllRecipients.Count) recipients..."
            foreach ($Recipient in $AllRecipients) {
                 try {
                    # Get permissions for the current recipient and filter for the target user
                    $PermissionsOnRecipient = Get-EXORecipientPermission -Identity $Recipient.Identity -ErrorAction SilentlyContinue |
                                              Where-Object { ($_.Trustee -eq $TargetUserIdentity) -and ($_.AccessRights -eq 'SendAs') }

                    if ($PermissionsOnRecipient) {
                         $SendAsPermissionsFound += $PermissionsOnRecipient
                         Write-Verbose "Found SendAs permission for '$TargetUserDisplayName' on recipient '$($Recipient.Identity)'."
                    }
                 }
                 catch {
                     Write-Warning "Could not retrieve permissions for recipient '$($Recipient.Identity)'. Skipping this recipient. Original error: $($_.Exception.Message)"
                 }
            }

            if ($SendAsPermissionsFound.Count -gt 0) {
                Write-Host "Found $($SendAsPermissionsFound.Count) recipient(s) with SendAs permission granted to '$TargetUserDisplayName'."
                foreach ($Perm in $SendAsPermissionsFound) {
                    $TargetRecipientIdentity = $Perm.Identity
                     # Use ShouldProcess for standard confirmation/whatif support
                    if ($PSCmdlet.ShouldProcess("Remove SendAs permission for '$TargetUserDisplayName' from recipient '$TargetRecipientIdentity'", "Removing SendAs Permission")) {
                        try {
                            Remove-RecipientPermission -Identity $TargetRecipientIdentity -Trustee $TargetUserIdentity -AccessRights SendAs -Confirm:$false -ErrorAction Stop
                            Write-Host "Successfully removed SendAs permission for '$TargetUserDisplayName' from '$TargetRecipientIdentity'." -ForegroundColor Green
                        }
                        catch {
                            Write-Error "Failed to remove SendAs permission for '$TargetUserDisplayName' from '$TargetRecipientIdentity'. Original error: $($_.Exception.Message)"
                        }
                    }
                }
            } else {
                Write-Host "No SendAs permissions found for '$TargetUserDisplayName'." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "An error occurred while searching for SendAs permissions. Original error: $($_.Exception.Message)"
        }


        # --- Find SendOnBehalf Permissions ---
        Write-Verbose "Searching for SendOnBehalf permissions..."
        try {
            # Find mailboxes where the TargetUser is listed in GrantSendOnBehalfTo
            # Using a filter is more efficient than getting all mailboxes and iterating
            # Need the TargetUser's DistinguishedName for the filter
            if ($null -ne $TargetUserDistinguishedName) {
                 Write-Verbose "Searching for mailboxes with GrantSendOnBehalfTo set to '$TargetUserDistinguishedName'..."
                 $SendOnBehalfMailboxes = Get-EXOMailbox -Filter "GrantSendOnBehalfTo -eq '$TargetUserDistinguishedName'" -ResultSize Unlimited -ErrorAction Stop |
                                          Select-Object -Property Identity, GrantSendOnBehalfTo # Select relevant properties

                if ($SendOnBehalfMailboxes.Count -gt 0) {
                    Write-Host "Found $($SendOnBehalfMailboxes.Count) mailbox(es) with SendOnBehalf permission granted to '$TargetUserDisplayName'."
                    foreach ($Mailbox in $SendOnBehalfMailboxes) {
                        $TargetMailboxIdentity = $Mailbox.Identity
                        # Use ShouldProcess for standard confirmation/whatif support
                        if ($PSCmdlet.ShouldProcess("Remove SendOnBehalf permission for '$TargetUserDisplayName' from mailbox '$TargetMailboxIdentity'", "Removing SendOnBehalf Permission")) {
                            try {
                                # Use the Remove method for the multi-valued GrantSendOnBehalfTo property
                                Set-Mailbox -Identity $TargetMailboxIdentity -GrantSendOnBehalfTo @{Remove=$TargetUserIdentity} -ErrorAction Stop
                                Write-Host "Successfully removed SendOnBehalf permission for '$TargetUserDisplayName' from '$TargetMailboxIdentity'." -ForegroundColor Green
                            }
                            catch {
                                Write-Error "Failed to remove SendOnBehalf permission for '$TargetUserDisplayName' from '$TargetMailboxIdentity'. Original error: $($_.Exception.Message)"
                            }
                        }
                    }
                } else {
                    Write-Host "No SendOnBehalf permissions found for '$TargetUserDisplayName'." -ForegroundColor Yellow
                }
            } else {
                 Write-Warning "Could not retrieve DistinguishedName for user '$TargetUserIdentity'. Skipping SendOnBehalf permission search."
            }
        }
        catch {
            Write-Error "An error occurred while searching for SendOnBehalf permissions. Original error: $($_.Exception.Message)"
        }

        Write-Host "`nPermission search and removal process completed for '$TargetUserDisplayName'."
    }

    # end {
    #     # Optional: Add cleanup code here if needed
    # }
}
