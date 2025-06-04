function Get-DgNtfsPermissionsRemotely {
    <#
    .SYNOPSIS
        Retrieves ACLs for directories in a specified path for a given user.
    .DESCRIPTION
        This script retrieves Access Control Lists (ACLs) for directories in a specified path for a given user.
        It allows filtering by user identity and supports parallel processing for improved performance.
    .PARAMETER ParentPath
        The path to the directory where ACLs will be retrieved.
    .PARAMETER Identity
        The user identity for whom to retrieve ACLs.
    .PARAMETER ComputerName
        The remote computer name. If not specified, runs locally.
    .EXAMPLE
        Get-DgNtfsPermissionsRemotely -ParentPath "\\fileserver\Share1" -Identity username
    .EXAMPLE
        Get-DgNtfsPermissionsRemotely -ParentPath "C:\Data" -Identity "domain\user" -ComputerName "Server01"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ParentPath,
        
        [Parameter(Mandatory=$true)]
        [Alias('IdentityReference')]
        [string]$Identity,
        
        [Parameter()]
        [string]$ComputerName
    )
    
    process {
        $scriptBlock = {
            param(
                [string]$remotePath, 
                [string]$remoteIdentityProvided
            )
            
            try {
                Write-Verbose "Scanning path: $remotePath for identity: $remoteIdentityProvided"
                
                # Validate path exists on target machine
                if (-not (Test-Path -Path $remotePath)) {
                    throw "Path '$remotePath' does not exist or is not accessible"
                }
                
                # Get all directories in the specified path
                $AllFolders = Get-ChildItem -Path $remotePath -Directory -ErrorAction SilentlyContinue
                
                if (-not $AllFolders) {
                    Write-Warning "No directories found in path '$remotePath'"
                    return
                }
                
                Write-Verbose "Found $($AllFolders.Count) directories to process"
                
                # Process each folder
                $results = foreach ($eachFolder in $AllFolders) {
                    try {
                        # Get ACL for the current folder
                        $acl = Get-Acl -Path $eachFolder.PSPath -ErrorAction Stop
                        
                        # Filter ACL entries for the specified identity
                        $aclPerUser = $acl.Access | Where-Object { 
                            $_.IdentityReference -like "*$remoteIdentityProvided*" 
                        }
                        
                        if ($aclPerUser) {
                            # Handle multiple ACEs for the same user
                            foreach ($ace in $aclPerUser) {
                                [PSCustomObject][ordered]@{
                                    ComputerName = $env:COMPUTERNAME
                                    FolderName = $eachFolder.Name
                                    Path = $eachFolder.FullName
                                    FileSystemRights = $ace.FileSystemRights
                                    AccessControlType = $ace.AccessControlType
                                    IdentityReference = $ace.IdentityReference
                                    IsInherited = $ace.IsInherited
                                    InheritanceFlags = $ace.InheritanceFlags
                                    PropagationFlags = $ace.PropagationFlags
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Error accessing ACL for '$($eachFolder.FullName)': $($_.Exception.Message)"
                    }
                }
                
                return $results
            }
            catch {
                Write-Error "Error processing path '$remotePath': $($_.Exception.Message)"
                throw
            }
        }
        
        # Execute remotely or locally
        if ($ComputerName) {
            try {
                Write-Verbose "Executing on remote computer: $ComputerName"
                
                # Validate remote connectivity first
                if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
                    throw "Cannot reach computer '$ComputerName'"
                }
                
                # Execute on remote computer
                $results = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $ParentPath, $Identity -ErrorAction Stop
                
                # Return results (don't pipe to Out-Host)
                return $results
            }
            catch {
                Write-Error "Failed to execute on '$ComputerName': $($_.Exception.Message)"
                throw
            }
        } 
        else {
            Write-Verbose "Executing locally on $env:COMPUTERNAME"
            
            # Execute locally
            try {
                $results = & $scriptBlock -remotePath $ParentPath -remoteIdentityProvided $Identity
                return $results
            }
            catch {
                Write-Error "Local execution failed: $($_.Exception.Message)"
                throw
            }
        }
    }
}