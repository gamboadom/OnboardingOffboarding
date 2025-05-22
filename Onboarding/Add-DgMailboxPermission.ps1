function Add-DgMailboxPermission {
    [CmdletBinding()]
    param (
        # UserPrincipalName or Email address of Shared Mailbox
        [Parameter(Mandatory)][ValidateScript({ Get-EXOMailbox $_ })][string]$Identity,
        # UPN or Email address of a delegate
        [Parameter(Mandatory)][ValidateScript({ Get-EXOMailbox $_ })][string]$User
    )
    begin {
        Get-DgConnectionInformation | Out-Null
    }
    process {
        $ToAdd = Read-Host "`nWhat permission would you like to assign?`n[1] FullAccess, [2] SendAs, [3] SendOnBehalf (default is `"FullAccess`")"
        switch ($ToAdd) {
            1 {Add-MailboxPermission -Identity $Identity -User $User -AccessRights FullAccess | Out-Null;
                Write-Verbose "Done adding 'FullAccess' permission to User '$User' on mailbox '$Identity'."            
            }
            2 {Add-RecipientPermission -Identity $Identity -Trustee $User -AccessRights SendAs -Confirm:$false | Out-Null;
                Write-Verbose "Done adding 'SendAs' permission to User '$User' on mailbox '$Identity'."            
            }
            3 {Set-Mailbox -Identity $Identity -GrantSendOnBehalfTo $User -Confirm:$false | Out-Null;
                Write-Verbose "Done adding 'SendOnBehalf' permission to User '$User' on mailbox '$Identity'." 
            }
            Default { Add-MailboxPermission -Identity $Identity -User $User -AccessRights FullAccess | Out-Null;
                Write-Verbose "Done adding 'FullAccess' permission to User '$User' on mailbox '$Identity'."  
            }
        }
    }     
}
