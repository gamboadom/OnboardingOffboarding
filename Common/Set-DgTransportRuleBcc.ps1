function Set-DgTransportRuleBcc {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)][string[]]$Identity,
        [Parameter(Mandatory)][string]$BlindCopyTo,
        [Parameter(Mandatory,ParameterSetName='Set')][switch]$Set,
        [Parameter(Mandatory,ParameterSetName='Remove')][switch]$Remove
    )

    begin {
        Get-DgConnectionInformation | Out-Null # Assuming this connects to Exchange Online or similar
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Set') {
            foreach ($RuleId in $Identity) {
                $currentBccRules = (Get-TransportRule $RuleId).BlindCopyTo

                # Ensure currentBccRules is treated as an array for comparison and addition
                # This property is typically a MultiValuedProperty, which acts like an array
                if ($currentBccRules -notcontains $BlindCopyTo) {
                    try {
                        # The + operator automatically creates a new array with the combined elements
                        Set-TransportRule -Identity $RuleId -BlindCopyTo ($currentBccRules + $BlindCopyTo)
                        Write-Verbose "Done adding '$BlindCopyTo' to 'BlindCopyTo' property of transport rule '$RuleId'."
                    }
                    catch {
                        Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                    }
                } elseif ($currentBccRules -contains $BlindCopyTo) {
                    Write-Warning "'$BlindCopyTo' already exists in BlindCopyTo of '$RuleId'."
                }
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Remove') {
            # Trim and convert to lowercase for consistent comparison with the target
            $BlindCopyToToMatch = $BlindCopyTo.Trim().ToLowerInvariant()

            foreach ($RuleId in $Identity) {
                # Get current rules, trim each entry, and convert to lowercase for comparison
                # Note: We keep the original casing in $currentBccRules for the final Set-TransportRule,
                # but use a ToLowerInvariant version for filtering.
                $originalBccRules = (Get-TransportRule $RuleId).BlindCopyTo
                $currentBccRulesLower = $originalBccRules | ForEach-Object { $_.Trim().ToLowerInvariant() }

                Write-Verbose "--- Debugging Rule: $($RuleId) ---"
                Write-Verbose "Value to remove (normalized): '$($BlindCopyToToMatch)'"
                Write-Verbose "Current BlindCopyTo property (original values): $($originalBccRules -join ', ')"
                Write-Verbose "Current BlindCopyTo property (normalized for comparison): $($currentBccRulesLower -join ', ')"
                Write-Verbose "Is '$BlindCopyToToMatch' contained in normalized list (initial check)? $($currentBccRulesLower -contains $BlindCopyToToMatch)"

                # Perform the check using the case-insensitive normalized list
                if ($currentBccRulesLower -contains $BlindCopyToToMatch) {
                    try {
                        # Create a NEW array/collection excluding the item (case-insensitively)
                        # We filter the *original* items, but compare using the lowercased version.
                        $updatedBccRules = $originalBccRules | Where-Object { $_.Trim().ToLowerInvariant() -ne $BlindCopyToToMatch }

                        # Set-TransportRule expects an array or MultiValuedProperty-like object.
                        # PowerShell handles converting a regular array to MultiValuedProperty for this parameter.
                        Set-TransportRule -Identity $RuleId -BlindCopyTo $updatedBccRules
                        Write-Verbose "Done removing '$BlindCopyTo' from 'BlindCopyTo' property of transport rule '$RuleId'."
                    }
                    catch {
                        Write-Error -Message "Error removing BCC: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                    }
                } elseif ($currentBccRulesLower -notcontains $BlindCopyToToMatch) {
                    Write-Warning "'$BlindCopyTo' has already been removed from BlindCopyTo property of '$RuleId'."
                }
            }
        }
    }
}