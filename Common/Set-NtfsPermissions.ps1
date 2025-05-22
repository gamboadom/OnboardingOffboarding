function Set-NtfsPermissions { # Function name changed here
    <#
    .SYNOPSIS
        Adds or removes ACLs for a specified path with improved validation, safety, and identity resolution.
    .DESCRIPTION
        This function adds or removes Access Control List (ACL) entries for a given path (file or directory).
        You can specify the identity, rights, inheritance, propagation, and type of access rule to add or remove.

        It includes:
        - Mandatory selection of either -Add or -Remove.
        - Robust identity resolution for local or domain accounts, including auto-completion for SamAccountNames
          found in existing ACLs if direct resolution fails. It correctly translates SecurityIdentifiers to NTAccounts
          for proper SamAccountName extraction, with enhanced error handling for translation failures.
        - A warning and confirmation prompt if modifying ACLs on a folder larger than 1GB.
        - Precise removal of access rules by matching all specified parameters, now more robust against identity string variations.
    .PARAMETER Path
        The path to the file or directory where the ACL will be modified.
        This parameter accepts pipeline input (e.g., from Get-ChildItem).
    .PARAMETER Identity
        The user or group identity to whom the access rule applies (e.g., "Domain\User", "Everyone", "BUILTIN\Administrators").
        If a simple SamAccountName (e.g., "johndoe") is provided and cannot be directly resolved to a fully qualified
        domain name, the function will attempt to find a matching SamAccountName within the existing ACL entries on
        the target path and use its fully qualified identity. This now correctly handles the translation from SecurityIdentifier
        to NTAccount.
        This parameter accepts pipeline input by property name.
    .PARAMETER Rights
        The file system rights to grant or deny (e.g., "FullControl", "Modify", "ReadAndExecute", "ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadPermissions", "WriteAttributes", "ReadAttributes", "Delete", "DeleteSubdirectoriesAndFiles", "ChangePermissions", "TakeOwnership").
        Valid values are defined by the System.Security.AccessControl.FileSystemRights enumeration.
        Defaults to "FullControl" if not specified.
    .PARAMETER Inheritance
        Specifies how the access rule is inherited by child objects (e.g., "ContainerInherit, ObjectInherit", "None").
        Valid values are defined by the System.Security.AccessControl.InheritanceFlags enumeration.
        Defaults to "ContainerInherit, ObjectInherit" (applies to folders and files within).
    .PARAMETER Propagation
        Specifies how inheritance is propagated to child objects (e.g., "None", "InheritOnly").
        Valid values are defined by the System.Security.AccessControl.PropagationFlags enumeration.
        Defaults to "None".
    .PARAMETER Type
        Specifies whether the access rule is for allowing or denying access (e.g., "Allow", "Deny").
        Valid values are defined by the System.Security.AccessControl.AccessControlType enumeration.
        Defaults to "Allow".
    .PARAMETER Add
        Switch parameter. If specified, the function will add the access rule.
        This parameter is mandatory when using the 'AddRule' parameter set.
    .PARAMETER Remove
        Switch parameter. If specified, the function will remove the access rule.
        Note: For successful removal, you must provide the exact same parameters (Identity, Rights, Inheritance, Propagation, Type)
        that were used when the rule was originally added. This function now uses a more robust matching
        logic to find and remove the specific rule.
        This parameter is mandatory when using the 'RemoveRule' parameter set.
    .EXAMPLE
        # Add an allow rule for a domain group with Modify permissions on a folder, inheriting to children
        Set-NtfsPermissions -Path "\\fileserver\Share1\Folder" -Identity "YOURDOMAIN\DomainUsers" -Rights "Modify" `
            -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Add

    .EXAMPLE
        # Add an allow rule using just a SamAccountName, which will be resolved from existing ACLs if present
        # Assuming 'johndoe' is already present in some ACL entry on 'C:\Temp\MyFolder' as 'YOURDOMAIN\johndoe'
        Set-NtfsPermissions -Path "C:\Temp\MyFolder" -Identity "johndoe" -Rights "ReadAndExecute" -Add

    .EXAMPLE
        # Remove the previously added allow rule (all parameters must match exactly)
        Set-NtfsPermissions -Path "\\fileserver\Share1\Folder" -Identity "YOURDOMAIN\DomainUsers" -Rights "Modify" `
            -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Remove

    .EXAMPLE
        # Remove an ACL rule using just a SamAccountName, which will be resolved from existing ACLs
        # This will now correctly find and remove ALKHAIRDUBAI\mawad if 'mawad' is passed as Identity
        Set-NtfsPermissions -Path "\\filesrv\DGamboa" -Identity "mawad" -Rights "FullControl" -Remove

    .EXAMPLE
        # Add FullControl to a local user on a file
        Set-NtfsPermissions -Path "C:\Temp\MyFile.txt" -Identity "LocalUser" -Rights "FullControl" `
            -Inheritance "None" -Propagation "None" -Type "Allow" -Add

    .EXAMPLE
        # Remove permissions for a user from bulk folders (requires all ACL parameters to be known for removal)
        # Note: This example assumes Get-DgAclPerUser provides enough context to reconstruct the exact rule for removal.
        # If not, you might need to manually specify -Rights, -Inheritance, -Propagation, -Type.
        # The pipeline only provides -Path and -Identity here.
        Get-ChildItem -Path "C:\Share\Users" -Directory | ForEach-Object {
            Set-NtfsPermissions -Path $_.FullName -Identity "SomeUser" -Rights "ReadAndExecute" `
                -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Remove
        }
    #>
    [CmdletBinding(DefaultParameterSetName='AddRule', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [ValidateScript({ Test-Path -Path $_ -ErrorAction SilentlyContinue })] # Use SilentlyContinue to allow Get-Acl to throw specific errors
        [string]$Path,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=1)]
        [Alias('IdentityReference')]
        [string]$Identity,

        [Parameter()]
        [ValidateSet("FullControl", "Modify", "ReadAndExecute", "ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadPermissions", "WriteAttributes", "ReadAttributes", "Delete", "DeleteSubdirectoriesAndFiles", "ChangePermissions", "TakeOwnership")]
        [System.Security.AccessControl.FileSystemRights]$Rights = "FullControl", # Directly use enum type

        [Parameter()]
        [ValidateSet("None", "ContainerInherit", "ObjectInherit", "ContainerInherit, ObjectInherit", "ObjectInherit, ContainerInherit")]
        [System.Security.AccessControl.InheritanceFlags]$Inheritance = "ContainerInherit, ObjectInherit", # Directly use enum type

        [Parameter()]
        [ValidateSet("None", "InheritOnly", "NoPropagateInherit", "InheritOnly, NoPropagateInherit", "NoPropagateInherit, InheritOnly")]
        [System.Security.AccessControl.PropagationFlags]$Propagation = "None", # Directly use enum type

        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [System.Security.AccessControl.AccessControlType]$Type = "Allow", # Directly use enum type

        [Parameter(ParameterSetName='AddRule', Mandatory=$true)]
        [Switch]$Add,

        [Parameter(ParameterSetName='RemoveRule', Mandatory=$true)]
        [Switch]$Remove
    )

    BEGIN {
        # Define a constant for the 1GB threshold in bytes
        $OneGBInBytes = 1GB
    }

    PROCESS {
        $resolvedIdentity = $null
        $identityProvided = $Identity # Store the original input
        $isBareSamAccountNameInput = ($identityProvided -notlike "*\*")
        $forceAclLookup = $false

        # Attempt direct resolution first
        try {
            $directResolvedNtAccount = New-Object System.Security.Principal.NTAccount($identityProvided)
            Write-Verbose "Attempted direct resolution for '$identityProvided': '$($directResolvedNtAccount.Value)'."

            # If the direct resolution gives us a fully qualified name (contains a backslash), use it.
            # Also use it if it's a well-known SID like 'Everyone' or 'System' (which won't have a backslash, but are distinct).
            # If it's a bare SamAccountName *and* the input was also a bare SamAccountName,
            # we need to force ACL lookup to get the full domain name.
            if ($directResolvedNtAccount.Value -like "*\*") { # It's already fully qualified (e.g., DOMAIN\User)
                $resolvedIdentity = $directResolvedNtAccount
            } elseif ($isBareSamAccountNameInput) {
                # Direct resolution resulted in a bare SamAccountName (e.g., 'MAWad' resolved to 'MAWad')
                # and the input was also bare. This is the scenario where we need to check ACLs
                # to get the full domain name.
                Write-Verbose "Direct resolution for '$identityProvided' resulted in a bare name. Forcing ACL lookup to find fully qualified identity."
                $forceAclLookup = $true
            } else {
                # This case implies direct resolution produced a bare name, but the input was fully qualified.
                # This is unexpected if the input was valid. Treat as needing ACL lookup.
                Write-Verbose "Direct resolution for '$identityProvided' produced a bare name, but input was not bare. Forcing ACL lookup."
                $forceAclLookup = $true
            }
        }
        catch {
            # Direct resolution failed completely (e.g., invalid name, no network)
            Write-Verbose "Direct resolution for '$identityProvided' failed: $($_.Exception.Message). Forcing ACL lookup."
            $forceAclLookup = $true
        }

        # Perform ACL lookup if forced, or if direct resolution didn't yield a valid resolvedIdentity yet
        if ($forceAclLookup -or (-not $resolvedIdentity)) {
            Write-Verbose "Performing ACL lookup to resolve identity for '$identityProvided' on '$Path'."
            try {
                $Acl = Get-Acl -Path $Path -ErrorAction Stop # Ensure we get the ACL or error out

                $translationFailedForSomeAces = $false # Flag to track if any translations failed

                # Filter for access rules where the IdentityReference's translated NTAccount value matches the input
                # This will match SamAccountNames for domain accounts, local accounts, and well-known SIDs
                $matchingAces = $Acl.Access | Where-Object {
                    try {
                        # Translate the SecurityIdentifier to an NTAccount
                        $ntAccount = $_.IdentityReference.Translate([System.Security.Principal.NTAccount])
                        $ntAccountValue = $ntAccount.Value # e.g., "DOMAIN\johndoe", "BUILTIN\Administrators", "MACHINENAME\LocalUser"

                        if ($isBareSamAccountNameInput) {
                            # If bare SamAccountName provided as input, compare against the last part (SamAccountName)
                            $samAccountNameFromAcl = $ntAccountValue.Split('\')[-1]
                            $samAccountNameFromAcl -eq $identityProvided # PowerShell's -eq is case-insensitive by default
                        } else {
                            # If fully qualified identity provided as input, compare directly
                            $ntAccountValue -eq $identityProvided
                        }
                    }
                    catch {
                        # Handle cases where translation might fail for some reason (e.g., orphaned SIDs)
                        Write-Verbose "Could not translate IdentityReference '$($_.IdentityReference.Value)' for comparison: $($_.Exception.Message)"
                        $translationFailedForSomeAces = $true # Set flag if translation fails
                        $false # Do not include this ACE in matches
                    }
                }

                if ($matchingAces.Count -eq 1) {
                    $resolvedIdentity = $matchingAces[0].IdentityReference.Translate([System.Security.Principal.NTAccount])
                    Write-Verbose "Successfully resolved '$identityProvided' to '$($resolvedIdentity.Value)' from existing ACL on '$Path'."
                }
                elseif ($matchingAces.Count -gt 1) {
                    Write-Error "Multiple ACL entries found for SamAccountName '$identityProvided' on '$Path'. Please provide a more specific Identity (e.g., 'Domain\User') to avoid ambiguity."
                    return # Exit the function for this path
                }
                else {
                    # No match found in existing ACLs by SamAccountName, and direct resolution also failed.
                    if ($translationFailedForSomeAces) {
                        Write-Error "Identity '$identityProvided' could not be resolved directly. While attempting to match against existing ACLs on '$Path', some identity translations failed. This may indicate orphaned SIDs or network/permission issues preventing resolution. Please ensure the identity is valid and resolvable, or provide a fully qualified name (e.g., 'Domain\User')."
                    } else {
                        Write-Error "Identity '$identityProvided' could not be resolved as a valid user/group, nor found as a unique SamAccountName in the existing ACLs on '$Path'. Please check the identity."
                    }
                    return # Exit the function for this path
                }
            }
            catch {
                Write-Error "Error accessing ACL on '$Path' to resolve Identity '$identityProvided': $($_.Exception.Message)"
                return # Exit the function for this path
            }
        }

        # If after all attempts, resolvedIdentity is still null, something went wrong
        if (-not $resolvedIdentity) {
            Write-Error "An unexpected error occurred while resolving Identity '$identityProvided' for path '$Path'. No action taken."
            return
        }

        # Check folder size if it's a directory and warn if large
        $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
        if ($item -and $item.PSIsContainer) { # Check if it's a directory
            try {
                $folderSize = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                if ($folderSize -gt $OneGBInBytes) {
                    $confirmMessage = "The folder '$Path' is approximately {0:N2} GB. Modifying ACLs on large folders can take time and impact performance. Do you want to proceed?" -f ($folderSize / 1GB)
                    if (-not $PSCmdlet.ShouldContinue("Warning: Large Folder Detected", $confirmMessage)) {
                        Write-Warning "ACL modification on '$Path' cancelled by user due to large folder size."
                        return # Skip processing for this path
                    }
                }
            }
            catch {
                Write-Warning "Could not determine size of '$Path'. Proceeding with ACL modification. Error: $($_.Exception.Message)"
            }
        }

        # Use ShouldProcess for safety with -WhatIf and -Confirm
        $action = if ($PSBoundParameters.ContainsKey('Add')) { "adding" } else { "removing" }
        $target = "ACL for '$resolvedIdentity' with rights '$Rights' ($Type) on '$Path'"

        if ($PSCmdlet.ShouldProcess($target, "Are you sure you want to proceed with $action $target?")) {
            try {
                # Get the current ACL of the specified path (re-get in case it was obtained in the catch block)
                $Acl = Get-Acl -Path $Path

                if ($PSBoundParameters.ContainsKey('Add')) {
                    # Create a new FileSystemAccessRule object using the resolved identity
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
                        $resolvedIdentity,
                        $Rights,
                        $Inheritance,
                        $Propagation,
                        $Type
                    )
                    # Add the new access rule to the ACL
                    $Acl.AddAccessRule($Ace)
                    Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop # Use -ErrorAction Stop for better error propagation
                    Write-Output "Successfully added ACL for '$Identity' on '$Path' with '$Rights' rights, and type '$Type'."
                }
                elseif ($PSBoundParameters.ContainsKey('Remove')) {
                    # Find the specific access rule to remove by matching all its components
                    $foundRuleToRemove = $null
                    foreach ($rule in $Acl.Access) {
                        try {
                            $ruleNtAccount = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount])
                            # Compare resolved identity (case-insensitive) and other rule properties
                            if (($ruleNtAccount.Value -eq $resolvedIdentity.Value) -and `
                                ($rule.FileSystemRights -eq $Rights) -and `
                                ($rule.InheritanceFlags -eq $Inheritance) -and `
                                ($rule.PropagationFlags -eq $Propagation) -and `
                                ($rule.AccessControlType -eq $Type)) {

                                $foundRuleToRemove = $rule
                                break # Found the rule, exit loop
                            }
                        }
                        catch {
                            Write-Verbose "Skipping rule with SID '$($rule.IdentityReference.Value)' during removal search due to translation error: $($_.Exception.Message)"
                        }
                    }

                    if ($foundRuleToRemove) {
                        # Use RemoveAccessRule with the actual rule object found
                        # This is more robust than RemoveAccessRuleSpecific for identity string variations
                        $Acl.RemoveAccessRule($foundRuleToRemove)
                        Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
                        Write-Output "Successfully removed ACL for '$($foundRuleToRemove.IdentityReference.Value)' on '$Path' with '$Rights' rights, and type '$Type'."
                    } else {
                        Write-Warning "Could not find an exact matching ACL rule for '$Identity' (resolved to '$($resolvedIdentity.Value)') on '$Path' with '$Rights' rights, and type '$Type'. No rule was removed."
                    }
                }
            }
            catch {
                Write-Error "Error modifying ACL on '$Path': $($_.Exception.Message)"
            }
        }
    }
}
