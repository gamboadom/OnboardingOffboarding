function Set-DgNtfsPermissionsRemotely {
    <#
    .SYNOPSIS
        Adds or removes ACLs for a specified path on local or remote computers.
    .DESCRIPTION
        This function adds or removes Access Control List (ACL) entries for a given path (file or directory)
        on one or more specified computers. You can specify the identity, rights, inheritance, propagation,
        and type of access rule to add or remove.

        It includes:
        - Mandatory selection of either -Add or -Remove.
        - Robust identity resolution for local or domain accounts. If a bare SamAccountName is provided,
          it first attempts direct resolution. If that results in another bare name, it will then try
          to prepend the current domain's NetBIOS name (if applicable) to get a fully qualified identity.
          A lookup in existing ACLs is also performed as a fallback or for disambiguation.
        - A warning and confirmation prompt if modifying ACLs on a folder larger than 1GB.
        - Precise removal of access rules by matching all specified parameters, now more robust against identity string variations.
        - Remote execution capability via the -ComputerName parameter.
    .PARAMETER Path
        The path to the file or directory where the ACL will be modified.
        This path must be accessible from the target -ComputerName.
        This parameter accepts pipeline input (e.g., from Get-ChildItem).
    .PARAMETER Identity
        The user or group identity to whom the access rule applies (e.g., "Domain\User", "Everyone", "BUILTIN\Administrators").
        If a simple SamAccountName (e.g., "johndoe") is provided, the function attempts to resolve it.
        If direct resolution results in a bare name, it will then attempt to find a matching fully qualified name
        using the domain's NetBIOS name or within existing ACL entries on the target path. If not found, it proceeds
        with the bare name if it's a valid local identity.
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
    .PARAMETER ComputerName
        Specifies the name of the computer(s) on which to run the ACL modification.
        If not specified, the function will run on the local computer.
        Requires PowerShell Remoting to be enabled on the target computer(s).
    .EXAMPLE
        # Add an allow rule for a new domain group with Modify permissions on a folder on a remote server
        Set-DgNtfsPermissionsRemotely -ComputerName "FileServer01" -Path "D:\Share1\NewFolder" -Identity "YOURDOMAIN\NewGroup" -Rights "Modify" `
            -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Add

    .EXAMPLE
        # Add an allow rule for a new local user on a remote server (e.g., a service account)
        Set-DgNtfsPermissionsRemotely -ComputerName "FileServer01" -Path "C:\ProgramData\App" -Identity "LocalServiceUser" -Rights "ReadAndExecute" -Add

    .EXAMPLE
        # Remove an ACL rule using just a SamAccountName on a remote server, which will be resolved from existing ACLs
        Set-DgNtfsPermissionsRemotely -ComputerName "FileServer01" -Path "\\filesrv\DGamboa" -Identity "mawad" -Rights "FullControl" -Remove

    .EXAMPLE
        # Add FullControl to a local user on a file on the local computer
        Set-DgNtfsPermissionsRemotely -Path "C:\Temp\MyFile.txt" -Identity "LocalUser" -Rights "FullControl" `
            -Inheritance "None" -Propagation "None" -Type "Allow" -Add
    #>
    [CmdletBinding(DefaultParameterSetName='AddRule', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [string]$Path,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=1)]
        [Alias('IdentityReference')]
        [string]$Identity,

        [Parameter()]
        [ValidateSet("FullControl", "Modify", "ReadAndExecute", "ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadPermissions", "WriteAttributes", "ReadAttributes", "Delete", "DeleteSubdirectoriesAndFiles", "ChangePermissions", "TakeOwnership")]
        [System.Security.AccessControl.FileSystemRights]$Rights = "FullControl",

        [Parameter()]
        [ValidateSet("None", "ContainerInherit", "ObjectInherit", "ContainerInherit, ObjectInherit", "ObjectInherit, ContainerInherit")]
        [System.Security.AccessControl.InheritanceFlags]$Inheritance = "ContainerInherit, ObjectInherit",

        [Parameter()]
        [ValidateSet("None", "InheritOnly", "NoPropagateInherit", "InheritOnly, NoPropagateInherit", "NoPropagateInherit, InheritOnly")]
        [System.Security.AccessControl.PropagationFlags]$Propagation = "None",

        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [System.Security.AccessControl.AccessControlType]$Type = "Allow",

        [Parameter(ParameterSetName='AddRule', Mandatory=$true)]
        [Switch]$Add,

        [Parameter(ParameterSetName='RemoveRule', Mandatory=$true)]
        [Switch]$Remove,

        [Parameter()]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    BEGIN {
        $OneGBInBytes = 1GB
    }

    PROCESS {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Processing path '$Path' on computer '$computer'."

            try {
                $scriptBlock = {
                    param (
                        $remotePath,
                        $remoteIdentityProvided,
                        $remoteIsBareSamAccountNameInput,
                        $remoteRights,
                        $remoteInheritance,
                        $remotePropagation,
                        $remoteType,
                        $remoteAddSwitch,
                        $remoteRemoveSwitch,
                        $remoteOneGBInBytes
                    )

                    # --- Identity Resolution on Remote Computer (Revised for Add/Remove) ---
                    $resolvedIdentity = $null
                    $tempResolvedNtAccount = $null # To hold result of first direct resolution attempt
                    $foundFullyQualifiedInAcl = $false # Flag if a fully qualified name was found in ACLs

                    # Attempt 1: Try to resolve the identity directly. This must succeed for the identity to be valid.
                    try {
                        $tempResolvedNtAccount = New-Object System.Security.Principal.NTAccount($remoteIdentityProvided)
                        Write-Verbose "Direct resolution for '$remoteIdentityProvided' on '$env:COMPUTERNAME' yielded: '$($tempResolvedNtAccount.Value)'."

                        # If it's already fully qualified (contains a backslash) or a known bare name (like System, Everyone)
                        if ($tempResolvedNtAccount.Value -like "*\*" -or $tempResolvedNtAccount.Value -eq $remoteIdentityProvided) {
                            $resolvedIdentity = $tempResolvedNtAccount
                        }
                    }
                    catch {
                        Write-Verbose "Direct resolution for '$remoteIdentityProvided' failed entirely on '$env:COMPUTERNAME': $($_.Exception.Message)."
                    }

                    # Attempt 2: If input was a bare SamAccountName AND direct resolution didn't get a fully qualified name,
                    # try to get the fully qualified name by prepending domain NetBIOS name.
                    if ($remoteIsBareSamAccountNameInput -and (-not ($resolvedIdentity -and $resolvedIdentity.Value -like "*\*"))) {
                        Write-Verbose "Input '$remoteIdentityProvided' is bare, and direct resolution did not yield fully qualified name. Attempting domain-prefixed resolution."
                        try {
                            # Check if ActiveDirectory module is available to use Get-ADDomain
                            if (Get-Module -ListAvailable ActiveDirectory) {
                                $domainNetBiosName = (Get-ADDomain -ErrorAction SilentlyContinue).NetBiosName
                                if ($domainNetBiosName) {
                                    $domainPrefixedIdentity = "$domainNetBiosName\$remoteIdentityProvided"
                                    Write-Verbose "Attempting resolution with domain prefix: '$domainPrefixedIdentity'."
                                    $domainResolvedNtAccount = New-Object System.Security.Principal.NTAccount($domainPrefixedIdentity)
                                    $resolvedIdentity = $domainResolvedNtAccount # This is the preferred fully qualified identity
                                    Write-Verbose "Successfully resolved bare '$remoteIdentityProvided' to fully qualified '$($resolvedIdentity.Value)' using domain prefix."
                                } else {
                                    Write-Verbose "Machine is not domain-joined or cannot retrieve domain NetBIOS name. Skipping domain-prefixed resolution."
                                }
                            } else {
                                Write-Verbose "ActiveDirectory module not available on '$env:COMPUTERNAME'. Skipping domain-prefixed resolution."
                            }
                        }
                        catch {
                            Write-Verbose "Domain-prefixed resolution for '$remoteIdentityProvided' failed on '$env:COMPUTERNAME': $($_.Exception.Message)."
                            # If this fails, $resolvedIdentity might still be $null or the bare name from initial attempt.
                        }
                    }

                    # Attempt 3: If still not fully qualified (or if domain lookup failed), check existing ACLs.
                    # This is useful for removal or if the domain lookup was skipped/failed.
                    if ($remoteIsBareSamAccountNameInput -and (-not ($resolvedIdentity -and $resolvedIdentity.Value -like "*\*"))) {
                        Write-Verbose "Attempting ACL lookup for full identity for bare '$remoteIdentityProvided'."
                        try {
                            $Acl = Get-Acl -Path $remotePath -ErrorAction SilentlyContinue

                            if ($Acl) {
                                $translationFailedForSomeAces = $false
                                $matchingAces = $Acl.Access | Where-Object {
                                    try {
                                        $ntAccount = $_.IdentityReference.Translate([System.Security.Principal.NTAccount])
                                        $ntAccountValue = $ntAccount.Value
                                        $samAccountNameFromAcl = $ntAccountValue.Split('\')[-1]
                                        $samAccountNameFromAcl -eq $remoteIdentityProvided
                                    }
                                    catch {
                                        Write-Verbose "Could not translate IdentityReference '$($_.IdentityReference.Value)' for comparison on '$env:COMPUTERNAME': $($_.Exception.Message)"
                                        $translationFailedForSomeAces = $true
                                        $false
                                    }
                                }

                                if ($matchingAces.Count -eq 1) {
                                    $resolvedIdentity = $matchingAces[0].IdentityReference.Translate([System.Security.Principal.NTAccount])
                                    $foundFullyQualifiedInAcl = $true
                                    Write-Verbose "Successfully resolved bare '$remoteIdentityProvided' to fully qualified '$($resolvedIdentity.Value)' from existing ACL on '$remotePath' on '$env:COMPUTERNAME'."
                                }
                                elseif ($matchingAces.Count -gt 1) {
                                    throw "Multiple ACL entries found for SamAccountName '$remoteIdentityProvided' on '$remotePath' on '$env:COMPUTERNAME'. Please provide a more specific Identity (e.g., 'Domain\User') to avoid ambiguity."
                                }
                            } else {
                                Write-Verbose "Could not retrieve ACL for '$remotePath' to find full identity for '$remoteIdentityProvided'. Relying on other resolution methods."
                            }
                        }
                        catch {
                            Write-Warning "Error during ACL lookup for identity resolution for '$remoteIdentityProvided' on '$remotePath' on '$env:COMPUTERNAME': $($_.Exception.Message). Relying on other resolution methods."
                        }
                    }

                    # Final Identity Assignment and Validation
                    # If after all attempts, $resolvedIdentity is still null, or it's a bare name and we're adding,
                    # use the initial direct resolution result if it was valid.
                    if (-not $resolvedIdentity) {
                        if ($tempResolvedNtAccount) {
                            $resolvedIdentity = $tempResolvedNtAccount # Use the bare name if direct resolution worked
                            Write-Verbose "Proceeding with bare resolved identity '$($resolvedIdentity.Value)' as fully qualified could not be determined."
                        } else {
                            throw "Identity '$remoteIdentityProvided' could not be resolved to a valid user or group on '$env:COMPUTERNAME'. Please check the identity and ensure it exists and is resolvable."
                        }
                    }


                    # --- Folder Size Check on Remote Computer ---
                    $item = Get-Item -Path $remotePath -ErrorAction SilentlyContinue
                    if ($item -and $item.PSIsContainer) {
                        try {
                            $folderSize = (Get-ChildItem -Path $remotePath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                            if ($folderSize -gt $remoteOneGBInBytes) {
                                Write-Warning "The folder '$remotePath' on '$env:COMPUTERNAME' is approximately {0:N2} GB. Modifying ACLs on large folders can take time and impact performance." -f ($folderSize / 1GB)
                            }
                        }
                        catch {
                            Write-Warning "Could not determine size of '$remotePath' on '$env:COMPUTERNAME'. Proceeding with ACL modification. Error: $($_.Exception.Message)"
                        }
                    }

                    # --- ACL Modification on Remote Computer ---
                    $Acl = Get-Acl -Path $remotePath -ErrorAction Stop

                    if ($remoteAddSwitch) {
                        $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
                            $resolvedIdentity, # Use the now correctly resolved identity
                            $remoteRights,
                            $remoteInheritance,
                            $remotePropagation,
                            $remoteType
                        )
                        $Acl.AddAccessRule($Ace)
                        Set-Acl -Path $remotePath -AclObject $Acl -ErrorAction Stop
                        Write-Output "Successfully added ACL for '$remoteIdentityProvided' (resolved to '$($resolvedIdentity.Value)') on '$remotePath' on '$env:COMPUTERNAME' with '$remoteRights' rights, and type '$remoteType'."
                    }
                    elseif ($remoteRemoveSwitch) {
                        $foundRuleToRemove = $null
                        foreach ($rule in $Acl.Access) {
                            try {
                                $ruleNtAccount = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount])
                                if (($ruleNtAccount.Value -eq $resolvedIdentity.Value) -and `
                                    ($rule.FileSystemRights -eq $remoteRights) -and `
                                    ($rule.InheritanceFlags -eq $remoteInheritance) -and `
                                    ($rule.PropagationFlags -eq $remotePropagation) -and `
                                    ($rule.AccessControlType -eq $remoteType)) {

                                    $foundRuleToRemove = $rule
                                    break
                                }
                            }
                            catch {
                                Write-Verbose "Skipping rule with SID '$($rule.IdentityReference.Value)' during removal search on '$env:COMPUTERNAME' due to translation error: $($_.Exception.Message)"
                            }
                        }

                        if ($foundRuleToRemove) {
                            $Acl.RemoveAccessRule($foundRuleToRemove)
                            Set-Acl -Path $remotePath -AclObject $Acl -ErrorAction Stop
                            Write-Output "Successfully removed ACL for '$remoteIdentityProvided' (resolved to '$($resolvedIdentity.Value)') on '$remotePath' on '$env:COMPUTERNAME' with '$remoteRights' rights, and type '$remoteType'."
                        } else {
                            Write-Warning "Could not find an exact matching ACL rule for '$remoteIdentityProvided' (resolved to '$($resolvedIdentity.Value)') on '$remotePath' on '$env:COMPUTERNAME' with '$remoteRights' rights, and type '$remoteType'. No rule was removed."
                        }
                    }
                } # End of remote script block

                # Invoke the script block on the remote computer
                Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList @(
                    $Path,
                    $Identity,
                    $isBareSamAccountNameInput,
                    $Rights,
                    $Inheritance,
                    $Propagation,
                    $Type,
                    $PSBoundParameters.ContainsKey('Add'),
                    $PSBoundParameters.ContainsKey('Remove'),
                    $OneGBInBytes
                ) -ErrorAction Stop | Out-Host # Pipe output to host for visibility
            }
            catch {
                Write-Error "Error processing '$Path' on computer '$computer': $($_.Exception.Message)"
            }
        }
    }
}
