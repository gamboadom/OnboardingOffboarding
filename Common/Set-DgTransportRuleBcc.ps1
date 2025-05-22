function Set-DgTransportRuleBcc {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)][string[]]$Identity,
        [Parameter(Mandatory)][string]$BlindCopyTo,
        [Parameter(Mandatory,ParameterSetName='Set')][switch]$Set,
        [Parameter(Mandatory,ParameterSetName='Remove')][switch]$Remove
    )
    
    begin {
        Get-DgConnectionInformation | Out-Null
    }    
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Set') {
            foreach ($RuleId in $Identity) {
                $BccTRule = (Get-TransportRule $RuleId).BlindCopyTo
                if ($BccTRule -notcontains $BlindCopyTo) {
                    try {
                        Set-TransportRule -Identity $RuleId -BlindCopyTo ((Get-TransportRule $RuleId).BlindCopyTo + $BlindCopyTo)
                        Write-Verbose "Done adding '$BlindCopyTo' to 'BlindCopyTo' property of transport rule '$RuleId'."
                    }
                    catch {
                        Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                    }                
                } elseif ($BccTRule -contains $BlindCopyTo) {
                    Write-Warning "'$BlindCopyTo' already exists in BlindCopyTo of '$RuleId'."
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'Remove') {
            foreach ($RuleId in $Identity) {
                $BccTRule = (Get-TransportRule $RuleId).BlindCopyTo
                if ($BccTRule -contains $BlindCopyTo) {
                    try {
                        $BccTRule.Remove($BlindCopyTo)
                        Set-TransportRule -Identity $RuleId -BlindCopyTo $BccTRule
                        Write-Verbose "Done removing '$BlindCopyTo' from 'BlindCopyTo' property of transport rule '$RuleId'."
                    }
                    catch {
                        Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                    }                
                } elseif ($BccTRule -notcontains $BlindCopyTo) {
                    Write-Warning "'$BlindCopyTo' has already been removed from BlindCopyTo property of '$RuleId'."
                }
            }
        }
         
    }
}