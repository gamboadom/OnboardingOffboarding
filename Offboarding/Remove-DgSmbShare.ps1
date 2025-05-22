function Remove-DgSmbShare {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ShareName,
        [Parameter()][ValidateNotNullOrEmpty()][string]$ComputerName = $env:COMPUTERNAME,
        [Parameter()][Switch]$Force
    )
    process {
        try {
            Write-Verbose "Attempting to remove SMB share '$ShareName' on computer '$ComputerName'."
            $CimSession = if ($ComputerName -ne $env:COMPUTERNAME) {
                Write-Verbose "Creating CIM session to '$ComputerName'."
                New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            } else {
                $null # No need for a CIM session for the local computer
            }

            # Check if the share exists using Get-SmbShare, which is more direct
            $ExistingShare = Get-SmbShare -Name $ShareName -CimSession $CimSession -ErrorAction SilentlyContinue
            if ($ExistingShare) {
                Write-Verbose "SMB share '$ShareName' found. Proceeding with removal."
                Remove-SmbShare -Name $ShareName -CimSession $CimSession -Force:$Force -ErrorAction Stop
                Write-Verbose "Successfully removed SMB share '$ShareName' on '$ComputerName'."
            } else {
                Write-Warning "SMB share with the name '$ShareName' not found on '$ComputerName'."
            }
        }
        catch {
            Write-Error "An error occurred while trying to remove the SMB share '$ShareName' on '$ComputerName': $($_.Exception.Message)"
        }
        finally {
            if ($CimSession) {
                Write-Verbose "Removing CIM session to '$ComputerName'."
                Remove-CimSession -CimSession $CimSession -ErrorAction SilentlyContinue
            }
        }
    }
}