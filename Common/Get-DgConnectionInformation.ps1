function Get-DgConnectionInformation {
    [CmdletBinding()]
    param (
        [switch]$Force
    )
    process {
        $exchangeOnlineConnection = Get-ConnectionInformation | Where-Object {$_.Name -like "ExchangeOnline_*" -and $_.State -eq "Connected"}
        # $isConnected = $true

        if (-not $exchangeOnlineConnection -or $Force) {
            if ($Force -and $exchangeOnlineConnection) {
                Write-Warning "Forcing a new Exchange Online connection."
                Disconnect-ExchangeOnline -ConnectionId $exchangeOnlineConnection.ConnectionId -Confirm:$false
            } else {
                Write-Warning "No active Exchange Online connection found. Connecting now."
            }
            try {
                Connect-ExchangeOnline -ErrorAction Stop
                $exchangeOnlineConnection = Get-ConnectionInformation | Where-Object {$_.Name -like "ExchangeOnline_*" -and $_.State -eq "Connected"}
                if (-not $exchangeOnlineConnection) {
                    # $isConnected = $false
                    Write-Error "Failed to establish Exchange Online connection."
                }
            }
            catch {
                # $isConnected = $false
                Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
                exit 1
            }
        }
        # return $isConnected
    }
}