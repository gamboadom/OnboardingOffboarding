#Requires -Version 7.0
#Requires -Module ExchangeOnlineManagement

function Add-DgMailboxRecipientPermission {
    <#
    .SYNOPSIS
        Grants mailbox permissions to a specified user for Exchange Online mailboxes.
    .DESCRIPTION
        This function grants mailbox permissions to a specified user for Exchange Online mailboxes.
        It supports setting various access rights and allows you to specify the type of mailboxes
        (user, shared, room, equipment) to which the permissions are applied.  It incorporates
        error handling and parameter validation.
    .PARAMETER User
        The user to whom the mailbox permissions will be granted.  Specify the user in
        the format 'username@domain.com'.  This parameter is mandatory.
    .PARAMETER Identity
        Specifies the identity of the mailbox where permissions are being added.
        You can use the mailbox's email address, alias, or display name.  This parameter is mandatory.
    .PARAMETER AccessRights
        Specifies the access rights to grant to the user.  This is a mandatory parameter.
        Valid values are:
        - FullAccess
        - SendAs
        - SendOnBehalf
        - ExternalAccount
        You can provide multiple access rights separated by commas (e.g., "FullAccess,SendAs").
    .PARAMETER SharedMailboxOnly
        If specified, the permissions will only be applied to shared mailboxes.
    .PARAMETER ThrottleLimit
        The maximum number of concurrent operations to run in parallel. Default is 5.
    .PARAMETER Deny
        Specifies whether the permissions should be allowed or denied.
        $true = Deny, $false = Allow (default).
    .PARAMETER InheritanceType
        Specifies how permissions are inherited.  Valid values are:
        None, All, User, or Descendents. Default is All.
    .EXAMPLE
        Add-DgMailboxRecipientPermission -User "user1@domain.com" -Identity "sales@domain.com" -AccessRights "FullAccess,SendAs"
        Grants Full Access and Send As permissions to user1 for the sales shared mailbox.
    .EXAMPLE
        Add-DgMailboxRecipientPermission -User "user2@domain.com" -Identity "Room101" -AccessRights "FullAccess" -SharedMailboxOnly:$false -Deny:$true
        Denies Full Access permission for user2 to the Room101 resource mailbox.
    .NOTES
        This function requires PowerShell 7.0 or later and the ExchangeOnlineManagement module.
        Ensure that you have the necessary permissions to run this function and modify mailbox permissions.
        The function uses parallel processing to improve performance when setting mailbox permissions.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, HelpMessage = 'Enter the User in the format username@domain.com.')][string]$User,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Specify the identity of the mailbox (e.g., email address, alias, or display name).')][string]$Identity,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = 'Specify the access rights (e.g., FullAccess, SendAs).  Comma-separated for multiple.')][ValidateSet("FullAccess", "SendAs", "SendOnBehalf", "ExternalAccount")][string[]]$AccessRights,
        [switch]$SharedMailboxOnly,
        [ValidateRange(5, 50)][int]$ThrottleLimit = 5,
        [switch]$Deny,
        [ValidateSet("None", "All", "User", "Descendents")][string]$InheritanceType = "All"
    )

    process {

        # Resolve the Mailbox Identity to ensure we have the correct object.
        try {
            $Mailbox = Get-EXOMailbox -Identity $Identity
        } catch {
            Write-Warning "Failed to retrieve mailbox with identity '$Identity'.  Skipping."
            return  # Exit the process block for this iteration
        }

        # TODO: Add-MailboxPermission logic here
        # The only valid value for AccessRights are FullAccess, ChangeOwner, ExternalAccount, DeleteItem, ReadPermission, and ChangePermission.

        # Construct the parameters for Add-MailboxPermission
        $permissionParams = @{
            Identity        = $Mailbox.PrimarySmtpAddress # Use PrimarySmtpAddress for consistency
            User            = $User
            AccessRights    = $AccessRights
            Deny            = $Deny
            InheritanceType = $InheritanceType
        }

        # Check if the user wants to confirm the action
        $ConfirmationMessage = "Granting $($AccessRights -join ', ') permissions for user '$User' on mailbox '$($Mailbox.DisplayName)'. Deny is set to '$Deny'. Inheritance Type is '$InheritanceType'"
        if ($PSCmdlet.ShouldProcess($Mailbox.DisplayName, $ConfirmationMessage)) {
            try {
                # Execute the Add-MailboxPermission cmdlet
                Add-MailboxPermission @permissionParams

                Write-Verbose "Successfully granted $($AccessRights -join ', ') permissions for user '$User' on mailbox '$($Mailbox.DisplayName)'."
            } catch {
                Write-Warning "Failed to grant permissions for user '$User' on mailbox '$($Mailbox.DisplayName)': $_"
                # Optionally, write more detailed error information:
                # Write-Verbose "Detailed error: $($_.Exception.InnerException.Message)"
            }
        }

        # TODO: Add-RecipientPermission logic here
        # The only valid value for AccessRights is SendAs for this cmdlet.
        # Construct the parameters for Add-RecipientPermission
        
        # TODO: GrantSendOnBehalf logic here
        # Set-Mailbox -identity $Mailbox.PrimarySmtpAddress -GrantSendOnBehalfTo $User -Confirm:$false
    }
        
}
# End of function Add-DgMailboxRecipientPermission

# Grant Full Access and Send As permissions to user1 for the sales shared mailbox:
# Add-DgMailboxRecipientPermission -User "user1@domain.com" -Identity "sales@domain.com" -AccessRights "FullAccess","SendAs"

# # Deny Full Access permission for user2 to Room101:
# Add-DgMailboxRecipientPermission -User "user2@domain.com" -Identity "Room101" -AccessRights "FullAccess" -Deny:$true

# # Use WhatIf to preview the changes
# Add-DgMailboxRecipientPermission -User "user1@domain.com" -Identity "sales@domain.com" -AccessRights "FullAccess","SendAs" -WhatIf