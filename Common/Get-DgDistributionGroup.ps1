function Get-DgDistributionGroup {
    <#
    .SYNOPSIS
        Get the distribution groups for a specified member.
    .DESCRIPTION
        This function retrieves the distribution groups for a specified member in Exchange Online.
        It uses the Get-EXOMailbox cmdlet to get the member's distinguished name and then uses the Get-DistributionGroup cmdlet to find the groups.
    .PARAMETER Member
        The member's identity (email address or user principal name) for whom to retrieve the distribution groups.
        This parameter is mandatory and must be a valid identity that can be resolved by the Get-EXOMailbox cmdlet.
    .EXAMPLE
        Get-DgDistributionGroup -Member "user1@example.com"
        This example retrieves the distribution groups for the member with the email address "user1@example.com".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateScript({ Get-EXOMailbox -Identity $_ })][string]$Member
    )
    begin {
        Get-DgConnectionInformation | Out-Null
    } 
    process {
        # Get the member's distinguished name        
        $MemberDN = (Get-EXOMailbox -Identity $Member).DistinguishedName      
        try {
            # Get the distribution groups for the member
            Get-DistributionGroup -ResultSize Unlimited -Filter "Members -like '$MemberDN'" -ErrorAction Stop    
        }
        catch {
            # Handle errors if the command fails
            Write-Error "Failed to get distribution groups for member '$Member'. Error: $($_.Exception.Message)"
        }
    }
}
