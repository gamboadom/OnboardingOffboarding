function Remove-DgNtfsPermissionsRemotely {
    <#
    .SYNOPSIS
        Removes ACL permissions for directories based on provided permission objects or parameters.
    .DESCRIPTION
        This script removes Access Control List (ACL) permissions for directories. It can accept
        permission objects from Get-DgNtfsPermissionsRemotely or work with direct parameters.
        Supports both local and remote execution with comprehensive error handling.
    .PARAMETER PermissionObjects
        Array of permission objects (typically from Get-DgNtfsPermissionsRemotely output).
        Each object should contain Path, IdentityReference, FileSystemRights, and AccessControlType properties.
    .PARAMETER ParentPath
        The path to the directory where ACL permissions will be removed (alternative to PermissionObjects).
    .PARAMETER Identity
        The user identity for whom to remove permissions (alternative to PermissionObjects).
    .PARAMETER FileSystemRights
        Specific rights to remove. If not specified, removes all permissions for the identity.
    .PARAMETER AccessControlType
        Type of access control (Allow/Deny). Defaults to 'Allow'.
    .PARAMETER ComputerName
        The remote computer name. If not specified, runs locally.
    .PARAMETER WhatIf
        Shows what would be removed without actually making changes.
    .PARAMETER Force
        Bypasses confirmation prompts.
    .EXAMPLE
        # Remove permissions using objects from Get-DgNtfsPermissionsRemotely
        $permissions = Get-DgNtfsPermissionsRemotely -ParentPath "\\fileserver\Share1" -Identity "domain\user"
        Remove-DgNtfsPermissionsRemotely -PermissionObjects $permissions
    .EXAMPLE
        # Remove permissions directly by path and identity
        Remove-DgNtfsPermissionsRemotely -ParentPath "C:\Data" -Identity "domain\user" -ComputerName "Server01"
    .EXAMPLE
        # Remove specific permissions with WhatIf
        Remove-DgNtfsPermissionsRemotely -ParentPath "C:\Data" -Identity "domain\user" -FileSystemRights "ReadAndExecute" -WhatIf
    #>

    [CmdletBinding(DefaultParameterSetName='ByObjects', SupportsShouldProcess, ConfirmImpact='High')]
    param (
        [Parameter(ParameterSetName='ByObjects', Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject[]]$PermissionObjects,
        
        [Parameter(ParameterSetName='ByPath', Mandatory=$true)]
        [string]$ParentPath,
        
        [Parameter(ParameterSetName='ByPath', Mandatory=$true)]
        [Alias('IdentityReference')]
        [string]$Identity,
        
        [Parameter(ParameterSetName='ByPath')]
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,
        
        [Parameter(ParameterSetName='ByPath')]
        [System.Security.AccessControl.AccessControlType]$AccessControlType = 'Allow',
        
        [Parameter()]
        [string]$ComputerName,
        
        [Parameter()]
        [switch]$Force
    )
    
    begin {
        # Initialize an array to hold all permission objects when pipeline input is used
        $allPermissions = @()
    }
    
    process {
        # Collect permission objects from pipeline if in 'ByObjects' parameter set
        if ($PSCmdlet.ParameterSetName -eq 'ByObjects') {
            $allPermissions += $PermissionObjects
        }
    }
    
    end {
        # Define the script block to be executed locally or remotely
        $scriptBlock = {
            param(
                [PSCustomObject[]]$remotePermissions,
                [string]$remotePath,
                [string]$remoteIdentity,
                [string]$remoteRights,
                [string]$remoteAccessType,
                [bool]$isDirectMode,
                [bool]$forceRemoval # This parameter is passed for consistency, but ShouldProcess handles confirmation
            )
            
            try {
                $results = @() # Array to store results of each removal operation
                
                if ($isDirectMode) {
                    # Direct mode: scan path and remove permissions based on provided parameters
                    Write-Verbose "Direct mode: Scanning path '$remotePath' for identity '$remoteIdentity' on $($env:COMPUTERNAME)"
                    
                    # Validate if the parent path exists
                    if (-not (Test-Path -Path $remotePath)) {
                        throw "Path '$remotePath' does not exist or is not accessible."
                    }
                    
                    # Get all directories within the parent path
                    $AllFolders = Get-ChildItem -Path $remotePath -Directory -ErrorAction SilentlyContinue
                    
                    if (-not $AllFolders) {
                        Write-Warning "No directories found in path '$remotePath'."
                        return $results # Return empty results if no folders are found
                    }
                    
                    # Process each folder to remove matching ACEs
                    foreach ($folder in $AllFolders) {
                        try {
                            Write-Verbose "Processing folder: $($folder.FullName)"
                            $acl = Get-Acl -Path $folder.PSPath -ErrorAction Stop
                            $modified = $false # Flag to track if ACL was modified
                            
                            # Find all ACEs that match the identity
                            $acesToRemove = $acl.Access | Where-Object { 
                                $_.IdentityReference -like "*$remoteIdentity*" 
                            }
                            
                            # Further filter by FileSystemRights if specified
                            if ($remoteRights -and $remoteRights -ne '') {
                                $rightsEnum = [System.Security.AccessControl.FileSystemRights]$remoteRights
                                $acesToRemove = $acesToRemove | Where-Object {
                                    # Use -band to check if the ACE's rights include the specified rights
                                    ($_.FileSystemRights -band $rightsEnum) -eq $rightsEnum
                                }
                            }
                            
                            # Further filter by AccessControlType if specified
                            if ($remoteAccessType -and $remoteAccessType -ne '') {
                                $accessTypeEnum = [System.Security.AccessControl.AccessControlType]$remoteAccessType
                                $acesToRemove = $acesToRemove | Where-Object {
                                    $_.AccessControlType -eq $accessTypeEnum
                                }
                            }
                            
                            # Iterate through the filtered ACEs and attempt to remove each one
                            foreach ($ace in $acesToRemove) {
                                Write-Verbose "Attempting to remove ACE: Identity='$(($ace.IdentityReference).Value)', Rights='$($ace.FileSystemRights)', Type='$($ace.AccessControlType)' from '$($folder.FullName)'"
                                try {
                                    $acl.RemoveAccessRule($ace) | Out-Null
                                    $modified = $true
                                    
                                    # Log successful removal
                                    $results += [PSCustomObject][ordered]@{
                                        ComputerName = $env:COMPUTERNAME
                                        FolderName = $folder.Name
                                        Path = $folder.FullName
                                        IdentityReference = $ace.IdentityReference.Value
                                        FileSystemRights = $ace.FileSystemRights.ToString()
                                        AccessControlType = $ace.AccessControlType.ToString()
                                        Action = "Removed"
                                        Success = $true
                                        Error = $null
                                    }
                                }
                                catch {
                                    # Log failed removal of a specific ACE
                                    $results += [PSCustomObject][ordered]@{
                                        ComputerName = $env:COMPUTERNAME
                                        FolderName = $folder.Name
                                        Path = $folder.FullName
                                        IdentityReference = $ace.IdentityReference.Value
                                        FileSystemRights = $ace.FileSystemRights.ToString()
                                        AccessControlType = $ace.AccessControlType.ToString()
                                        Action = "Failed to Remove"
                                        Success = $false
                                        Error = $_.Exception.Message
                                    }
                                    Write-Warning "Failed to remove ACE '$($ace.IdentityReference.Value)' from '$($folder.FullName)': $($_.Exception.Message)"
                                }
                            }
                            
                            # Apply changes to the ACL if any rules were removed
                            if ($modified) {
                                Write-Verbose "Applying modified ACL to '$($folder.FullName)'"
                                Set-Acl -Path $folder.PSPath -AclObject $acl -ErrorAction Stop
                            } else {
                                Write-Verbose "No matching ACEs found or removed for '$($folder.FullName)' with specified criteria."
                            }
                        }
                        catch {
                            Write-Warning "Error processing folder '$($folder.FullName)': $($_.Exception.Message)"
                            $results += [PSCustomObject][ordered]@{
                                ComputerName = $env:COMPUTERNAME
                                FolderName = $folder.Name
                                Path = $folder.FullName
                                IdentityReference = $remoteIdentity
                                FileSystemRights = $remoteRights
                                AccessControlType = $remoteAccessType
                                Action = "Failed to Process Folder"
                                Success = $false
                                Error = $_.Exception.Message
                            }
                        }
                    }
                }
                else {
                    # Object mode: use provided permission objects for removal
                    Write-Verbose "Object mode: Processing $($remotePermissions.Count) permission objects on $($env:COMPUTERNAME)"
                    
                    # Group permissions by path for efficient processing
                    $groupedByPath = $remotePermissions | Group-Object -Property Path
                    
                    foreach ($pathGroup in $groupedByPath) {
                        $folderPath = $pathGroup.Name
                        Write-Verbose "Processing path group: '$folderPath'"
                        
                        try {
                            # Validate if the path exists before attempting to get ACL
                            if (-not (Test-Path -Path $folderPath)) {
                                Write-Warning "Path '$folderPath' no longer exists, skipping."
                                $results += [PSCustomObject][ordered]@{
                                    ComputerName = $env:COMPUTERNAME
                                    FolderName = (Split-Path $folderPath -Leaf)
                                    Path = $folderPath
                                    IdentityReference = "N/A"
                                    FileSystemRights = "N/A"
                                    AccessControlType = "N/A"
                                    Action = "Skipped (Path Not Found)"
                                    Success = $false
                                    Error = "Path does not exist"
                                }
                                continue
                            }
                            
                            $acl = Get-Acl -Path $folderPath -ErrorAction Stop
                            $modified = $false # Flag to track if ACL was modified
                            
                            # Iterate through each permission object provided
                            foreach ($permObj in $pathGroup.Group) {
                                Write-Verbose "Looking for ACE: Identity='$(($permObj.IdentityReference).Value)', Rights='$($permObj.FileSystemRights)', Type='$($permObj.AccessControlType)', Inherited='$($permObj.IsInherited)' on '$folderPath'"
                                
                                # For debugging, list all ACEs on the current folder
                                Write-Verbose "Current ACL entries for '$folderPath':"
                                $acl.Access | ForEach-Object {
                                    Write-Verbose "  - Identity: $($_.IdentityReference.Value), Rights: $($_.FileSystemRights), Type: $($_.AccessControlType), Inherited: $($_.IsInherited)"
                                }

                                try {
                                    # Find all matching ACEs based on exact properties from the permission object
                                    # IMPORTANT: Use .Value for IdentityReference comparison for robustness
                                    $matchingAces = $acl.Access | Where-Object {
                                        ($_.IdentityReference.Value -eq $permObj.IdentityReference.Value) -and
                                        ($_.FileSystemRights -eq $permObj.FileSystemRights) -and
                                        ($_.AccessControlType -eq $permObj.AccessControlType) -and
                                        ($_.IsInherited -eq $permObj.IsInherited)
                                    }
                                    
                                    if ($matchingAces.Count -gt 0) {
                                        # Iterate through each found matching ACE and remove it
                                        foreach ($ace in $matchingAces) {
                                            Write-Verbose "Found and attempting to remove matching ACE: Identity='$(($ace.IdentityReference).Value)', Rights='$($ace.FileSystemRights)', Type='$($ace.AccessControlType)'"
                                            $acl.RemoveAccessRule($ace) | Out-Null
                                            $modified = $true
                                            
                                            # Log successful removal
                                            $results += [PSCustomObject][ordered]@{
                                                ComputerName = $env:COMPUTERNAME
                                                FolderName = Split-Path $folderPath -Leaf
                                                Path = $folderPath
                                                IdentityReference = $ace.IdentityReference.Value
                                                FileSystemRights = $ace.FileSystemRights.ToString()
                                                AccessControlType = $ace.AccessControlType.ToString()
                                                Action = "Removed"
                                                Success = $true
                                                Error = $null
                                            }
                                        }
                                    }
                                    else {
                                        # Log if no matching ACE was found for the given permission object
                                        Write-Verbose "No matching ACE found for: Identity='$(($permObj.IdentityReference).Value)', Rights='$($permObj.FileSystemRights)', Type='$($permObj.AccessControlType)' on '$folderPath'"
                                        $results += [PSCustomObject][ordered]@{
                                            ComputerName = $env:COMPUTERNAME
                                            FolderName = Split-Path $folderPath -Leaf
                                            Path = $folderPath
                                            IdentityReference = $permObj.IdentityReference.Value
                                            FileSystemRights = $permObj.FileSystemRights.ToString()
                                            AccessControlType = $permObj.AccessControlType.ToString()
                                            Action = "Not Found"
                                            Success = $false
                                            Error = "Matching ACE not found for specified properties"
                                        }
                                    }
                                }
                                catch {
                                    # Log failure to remove a specific ACE from the permission object
                                    $results += [PSCustomObject][ordered]@{
                                        ComputerName = $env:COMPUTERNAME
                                        FolderName = Split-Path $folderPath -Leaf
                                        Path = $folderPath
                                        IdentityReference = $permObj.IdentityReference.Value
                                        FileSystemRights = $permObj.FileSystemRights.ToString()
                                        AccessControlType = $permObj.AccessControlType.ToString()
                                        Action = "Failed to Remove"
                                        Success = $false
                                        Error = $_.Exception.Message
                                    }
                                    Write-Warning "Failed to process permission object for '$folderPath': $($_.Exception.Message)"
                                }
                            }
                            
                            # Apply changes to the ACL if any rules were removed
                            if ($modified) {
                                Write-Verbose "Applying modified ACL to '$folderPath'"
                                Set-Acl -Path $folderPath -AclObject $acl -ErrorAction Stop
                            } else {
                                Write-Verbose "No changes applied to ACL for '$folderPath'."
                            }
                        }
                        catch {
                            Write-Warning "Error accessing or modifying ACL for '$folderPath': $($_.Exception.Message)"
                            $results += [PSCustomObject][ordered]@{
                                ComputerName = $env:COMPUTERNAME
                                FolderName = (Split-Path $folderPath -Leaf)
                                Path = $folderPath
                                IdentityReference = "N/A"
                                FileSystemRights = "N/A"
                                AccessControlType = "N/A"
                                Action = "Failed to Process Path"
                                Success = $false
                                Error = $_.Exception.Message
                            }
                        }
                    }
                }
                
                return $results # Return the collected results
            }
            catch {
                # Catch any unhandled errors within the script block
                Write-Error "Error during permission removal on $($env:COMPUTERNAME): $($_.Exception.Message)"
                throw # Re-throw to propagate the error
            }
        }
        
        # Prepare parameters for the script block based on the chosen parameter set
        if ($PSCmdlet.ParameterSetName -eq 'ByObjects') {
            $isDirectMode = $false
            $permissionsToProcess = $allPermissions
            $pathParam = $null
            $identityParam = $null
            $rightsParam = $null
            $accessTypeParam = $null
        }
        else { # ByPath parameter set
            $isDirectMode = $true
            $permissionsToProcess = @() # Not used in direct mode, but passed for consistency
            $pathParam = $ParentPath
            $identityParam = $Identity
            $rightsParam = if ($FileSystemRights) { $FileSystemRights.ToString() } else { $null }
            $accessTypeParam = $AccessControlType.ToString()
        }
        
        # Confirmation prompt logic, respecting WhatIf and Force
        if (-not $Force -and -not $WhatIfPreference) {
            if ($isDirectMode) {
                $confirmMessage = "Remove ACL permissions for identity '$Identity' from path '$ParentPath'"
            }
            else {
                $confirmMessage = "Remove $($permissionsToProcess.Count) ACL permission(s)"
            }
            
            if ($ComputerName) {
                $confirmMessage += " on computer '$ComputerName'"
            }
            
            if (-not $PSCmdlet.ShouldProcess($confirmMessage, "Remove ACL Permissions")) {
                return # User cancelled the operation
            }
        }
        
        # Execute the script block remotely or locally
        if ($ComputerName) {
            try {
                Write-Verbose "Executing on remote computer: $ComputerName"
                
                # Test connection to the remote computer
                if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
                    throw "Cannot reach computer '$ComputerName'."
                }
                
                # Invoke the script block on the remote computer
                $results = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $permissionsToProcess, $pathParam, $identityParam, $rightsParam, $accessTypeParam, $isDirectMode, $Force -ErrorAction Stop
                
                return $results
            }
            catch {
                Write-Error "Failed to execute on '$ComputerName': $($_.Exception.Message)"
                throw # Re-throw to propagate the error
            }
        }
        else {
            # Execute the script block locally
            Write-Verbose "Executing locally on $env:COMPUTERNAME"
            
            try {
                # Use the call operator '&' to run the script block locally with arguments
                $results = & $scriptBlock -remotePermissions $permissionsToProcess -remotePath $pathParam -remoteIdentity $identityParam -remoteRights $rightsParam -remoteAccessType $accessTypeParam -isDirectMode $isDirectMode -forceRemoval $Force
                return $results
            }
            catch {
                Write-Error "Local execution failed: $($_.Exception.Message)"
                throw # Re-throw to propagate the error
            }
        }
    }
}
