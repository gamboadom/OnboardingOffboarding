function Get-DgAclv2 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -Path $_ })][string]$Path
    )
    process {
        try {
            (Get-Acl -Path $Path).Access
        }
        catch {
            Write-Error "Error retrieving ACL for '$Path': $($_.Exception.Message)"
        }        
    }
}