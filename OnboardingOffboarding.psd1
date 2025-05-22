@{
    # Required Module Information
    ModuleVersion = '1.0.0.0'
    GUID = (New-Guid).ToString() # Run New-Guid in PowerShell and paste the output here

    # Optional Module Information
    Author = 'Dom Gamboa'
    CompanyName = 'Alkhair Capital Dubai Ltd.'
    Copyright = '(c) 2025 Dom Gamboa. All rights reserved.'
    Description = 'PowerShell Module for Employee Onboarding and Offboarding processes.'
    PowerShellVersion = '5.1' # Or higher, depending on your functions' requirements

    # List all your function script files relative to the .psd1 file
    ScriptsToProcess = @(
        'Onboarding\Add-DgCalendarPermission.ps1',
        'Onboarding\Add-DgMailboxPermission.ps1',
        'Offboarding\Remove-DgCalendarPermission.ps1',
        'Offboarding\Remove-DgEntraGroupMember.ps1',
        'Offboarding\Remove-DgMailboxPermission.ps1',
        'Offboarding\Remove-DgMailboxPermissionv2.ps1',
        'Offboarding\Remove-DgSmbShare.ps1',
        'Offboarding\Stop-EmployeeServices.ps1',        
        'Common\Get-DgAclPerUser.ps1'
        'Common\Get-DgConnectionInformation.ps1',
        'Common\Get-DgAclv2.ps1',
        'Common\Get-DgCalendarPermission.ps1',
        'Common\Get-DgEXOMailboxPermission.ps1',
        'Common\Get-DgDistributionGroup.ps1',
        'Common\Get-DgEXORecipientPermission.ps1',
        'Common\Get-DgMgContext.ps1',
        'Common\Get-DgSendOnBehalfPermission.ps1',
        'Common\Set-DgAclv2.ps1',
        'Common\Set-DgTransportRuleBcc.ps1',
        'Common\Set-NtfsPermissions.ps1'        
        # Add all other .ps1 files here, one per line
    )

    # List the names of the functions you want to export and make available to users
    FunctionsToExport = @(
        'Add-DgCalendarPermission',
        'Add-DgMailboxPermission',
        'Remove-DgCalendarPermission',
        'Remove-DgEntraGroupMember',
        'Remove-DgMailboxPermission',
        'Remove-DgMailboxPermissionv2',
        'Remove-DgSmbShare',
        'Stop-EmployeeServices',
        'Get-DgAclPerUser',
        'Get-DgConnectionInformation',
        'Get-DgAclv2',
        'Get-DgCalendarPermission',
        'Get-DgEXOMailboxPermission',
        'Get-DgDistributionGroup',
        'Get-DgEXORecipientPermission',
        'Get-DgMgContext',
        'Get-DgSendOnBehalfPermission',
        'Set-DgAclv2',
        'Set-DgTransportRuleBcc',
        'Set-NtfsPermissions'
        # Add all other function names you want to export here
    )

    # You can also export other types if needed (variables, cmdlets, aliases)
    # VariablesToExport = @()
    # CmdletsToExport = @()
    # AliasesToExport = @()

    # If your module depends on other modules, list them here
    # RequiredModules = @()

    # If you have a .psm1 file (next step), you might use NestedModules instead of ScriptsToProcess
    # NestedModules = @('OnboardingOffboarding.psm1')
}