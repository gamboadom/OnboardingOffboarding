function Get-DgAclPerUser {
    <#
    .SYNOPSIS
        Retrieves ACLs for directories in a specified path for a given user.
    .DESCRIPTION
        This script retrieves Access Control Lists (ACLs) for directories in a specified path for a given user.
        It allows filtering by user identity and supports parallel processing for improved performance.
    .PARAMETER Path
        The path to the directory where ACLs will be retrieved.
    .PARAMETER Identity
        The user identity for whom to retrieve ACLs.
    .EXAMPLE
        Get-DgAclPerUser -Path "\\fileserver\Share1" -Identity username
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -Path $_ })][string]$Path,
        [Parameter(Mandatory=$true)][Alias('IdentityReference')][ValidateScript({ Get-ADUser $_ })][string]$Identity,
        [ValidateRange(2,25)][int]$ThrottleLimit = 5
    )
    process {
        try {
            # Get-ChildItem is used to retrieve the list of directories in the specified path.
            # The -Directory parameter ensures that only directories are returned.
            $AllFolders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue

            # Get all subdirectories recursively
            # Foreach-Object -Parallel is used to process each folder in parallel
            # This is useful for large directory structures to speed up the process.
            $AllFolders | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                # $eachFolder is the current folder being processed in the parallel loop.
                # $using:Identity is used to pass the Identity parameter from the parent scope to the child scope.
                $eachFolder = $_
                try {
                    # Get-Acl retrieves the Access Control List (ACL) for the current folder.
                    # The ACL is filtered to include only entries that match the specified user identity.                    
                    $aclPerUser = (Get-Acl -Path $eachFolder.PSPath).Access | Where-Object {$_.IdentityReference -match $using:Identity}
                    if ($aclPerUser) {
                        [PSCustomObject][ordered]@{
                            FolderName = $eachFolder.Name
                            Path = $eachFolder.FullName
                            FileSystemRights = $aclPerUser.FileSystemRights
                            AccessControlType = $aclPerUser.AccessControlType
                            IdentityReference = $aclPerUser.IdentityReference
                            IsInherited = $aclPerUser.IsInherited
                            InheritanceFlags = $aclPerUser.InheritanceFlags
                            PropagationFlags = $aclPerUser.PropagationFlags
                        }
                    }
                }
                catch {
                    Write-Warning "Error accessing ACL for '$($eachFolder.FullName)': $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Error "Error getting subdirectories for '$Path': $($_.Exception.Message)"
        }
    }            
}