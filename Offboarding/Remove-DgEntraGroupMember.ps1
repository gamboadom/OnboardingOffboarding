function Remove-DgEntraGroupMember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateScript({ Get-EntraUser -UserId $_ })][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$GroupName
    )
    process {
        # Get the user's object ID
        $user = Get-EntraUser -UserId $UserPrincipalName

        # Get the group's object ID
        $group = Get-EntraGroup -Filter "startswith(DisplayName,'$GroupName')"
        if (-not $group) {
            # If the group is not found, display an error message and exit the function
            Write-Error "Group '$GroupName' not found."
            return
        } elseif ($group.Count -gt 1) {
            # If multiple groups are found, display an error message and exit the function
            Write-Warning "Multiple groups found with the name '$GroupName'. Please specify a more specific group name."
            return
        }else {
            if ($group.OnPremisesSyncEnabled -eq $true) {
                # If the group is synced from on-premises Active Directory, display a warning message and exit the function
                Write-Warning "The group '$GroupName' is synced from on-premises Active Directory. You cannot remove users from this group directly in Microsoft Entra."
                return               
            } elseif ($group.GroupTypes -contains "DynamicMembership") {
                # If the group is a dynamic group, display a warning message and exit the function
                Write-Warning "The group '$GroupName' is a dynamic group. You cannot remove users from this group directly in Microsoft Entra."
                return
            } else {
                try {
                    # Remove the user from a group                    # 
                    Remove-EntraGroupMember -GroupId $group.ObjectId -MemberId $user.ObjectId
                }
                catch {
                    Write-Error "Failed to remove user '$UserPrincipalName' from group '$GroupName'. Error: $_.Exception.Message"
                }
            }

            try {
                # Remove the user from a group                    # 
                Remove-EntraGroupMember -GroupId $group.ObjectId -MemberId $user.ObjectId
            }
            catch {
                Write-Error "Failed to remove user '$UserPrincipalName' to group '$GroupName'. Error: $_.Exception.Message"
            }
        }           
    }
}