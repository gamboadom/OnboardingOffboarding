function Get-DgMgContext {
    [CmdletBinding()]
    param (
        [switch]$Force
    )
    process {
        $MgContext = Get-MgContext 
        # $isConnected = $true

        if (-not $MgContext -or $Force) {
            if ($Force -and $MgContext) {
                Write-Warning "Forcing a new Microsoft Graph connection."
                Disconnect-MgGraph
            } else {
                Write-Warning "No active Microsoft Graph connection found. Connecting now."
            }
            try {
                Connect-MgGraph -Scopes User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All -NoWelcome -ErrorAction Stop
                $MgContext = Get-MgContext
                if (-not $MgContext) {
                    # $isConnected = $false
                    Write-Error "Failed to establish Microsoft Graph connection."
                }
            }
            catch {
                # $isConnected = $false
                Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
                exit 1
            }
        }
        # return $isConnected
    }
}