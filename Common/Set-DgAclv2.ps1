function Set-DgAclv2 {
    <#
    .SYNOPSIS
        Adds or removes ACLs for a specified path.
    .DESCRIPTION
        This function adds or removes Access Control List (ACL) entries for a given path (file or directory).
        You can specify the identity, rights, inheritance, propagation, and type of access rule to add or remove.
    .PARAMETER Path
        The path to the file or directory where the ACL will be modified.
    .PARAMETER Identity
        The user or group identity to whom the access rule applies (e.g., "Domain\User", "Everyone").
    .PARAMETER Rights
        The file system rights to grant or deny (e.g., "FullControl", "ReadAndExecute", "Modify").
        Valid values are defined by the System.Security.AccessControl.FileSystemRights enumeration.
    .PARAMETER Inheritance
        Specifies how the access rule is inherited by child objects (e.g., "ContainerInherit, ObjectInherit", "None").
        Valid values are defined by the System.Security.AccessControl.InheritanceFlags enumeration.
    .PARAMETER Propagation
        Specifies how inheritance is propagated to child objects (e.g., "None", "InheritOnly").
        Valid values are defined by the System.Security.AccessControl.PropagationFlags enumeration.
    .PARAMETER Type
        Specifies whether the access rule is for allowing or denying access (e.g., "Allow", "Deny").
        Valid values are defined by the System.Security.AccessControl.AccessControlType enumeration.    
    .PARAMETER Add
        Switch parameter. If specified, the function will add the access rule.
    .PARAMETER Remove
        Switch parameter. If specified, the function will remove the access rule.
        Note: You must provide the exact same parameters used to add the rule for successful removal.
    .EXAMPLE
        # Add an allow rule for a group with Modify permissions
        Set-DgAclv2 -Identity "Domain\GroupName" -Rights "Modify" -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Path "\\fileserver\Share1\Folder" -Add

    .EXAMPLE
        # Remove the previously added allow rule
        Set-DgAclv2 -Identity "Domain\GroupName" -Rights "Modify" -Inheritance "ContainerInherit, ObjectInherit" -Propagation "None" -Type "Allow" -Path "\\fileserver\Share1\Folder" -Remove
    
    .EXAMPLE
        # Remove the permissions of a user from bulk folders using the value from pipeline
        Get-DgAclPerUser -Path "\\fileserver\d$" -Identity username | Set-DgAclv2 -Remove 
    #>
    [CmdletBinding(DefaultParameterSetName='Add', SupportsShouldProcess=$true)]
    param (        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)][ValidateScript({ Test-Path -Path $_ })][string]$Path,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=1)][Alias('IdentityReference')][string]$Identity,
        [Parameter()][ValidateSet("FullControl", "Modify", "ReadAndExecute", "ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadPermissions", "WriteAttributes", "ReadAttributes", "Delete", "DeleteSubdirectoriesAndFiles", "ChangePermissions", "TakeOwnership")][string]$Rights = "FullControl",
        [Parameter()][ValidateSet("None", "ContainerInherit", "ObjectInherit", "ContainerInherit, ObjectInherit", "ObjectInherit, ContainerInherit")][string]$Inheritance = "ContainerInherit, ObjectInherit",
        [Parameter()][ValidateSet("None", "InheritOnly", "NoPropagateInherit", "InheritOnly, NoPropagateInherit", "NoPropagateInherit, InheritOnly")][string]$Propagation = "None",
        [Parameter()][ValidateSet("Allow", "Deny")][string]$Type = "Allow",

        # TODO: Make it mandatory to specify either Add or Remove        
        [Parameter(ParameterSetName='Add')][Switch]$Add,
        [Parameter(ParameterSetName='Remove')][Switch]$Remove
    )
    process {
        try {
            # Convert string parameters to enumeration types
            $FileSystemRights = [System.Security.AccessControl.FileSystemRights]::$Rights
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::Parse([System.Security.AccessControl.InheritanceFlags], $Inheritance)
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::Parse([System.Security.AccessControl.PropagationFlags], $Propagation)
            $AccessControlType = [System.Security.AccessControl.AccessControlType]::$Type            

            # Get the current ACL of the specified path
            $Acl = Get-Acl -Path $Path
            # TODO: Check the size of the folder, if the size is more than 1GB, display a warning message and ask for confirmation to proceed with the ACL modification.

            if ($PSBoundParameters.ContainsKey('Add')) {
                # Create a new FileSystemAccessRule object
                $formattedIdentity = $((Get-ADDomain).NetBIOSName + "\" + $Identity)
                $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($formattedIdentity,
                    $FileSystemRights,
                    $InheritanceFlags,
                    $PropagationFlags,
                    $AccessControlType
                )
                # Add the new access rule to the ACL
                $Acl.AddAccessRule($Ace)
                Set-Acl -Path $Path -AclObject $Acl | Out-Null
                Write-Output "Successfully added ACL for '$Identity' on '$Path' with '$Rights' rights, and type '$Type'."
            }
            elseif ($PSBoundParameters.ContainsKey('Remove')) {
                $IdentityToRemove = $Acl.Access | Where-Object { $_.IdentityReference -like "$Identity" }
                $AceToRemove = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($IdentityToRemove.IdentityReference,
                $FileSystemRights,
                $InheritanceFlags,
                $PropagationFlags,
                $AccessControlType
                )
                # Remove the access rule from the ACL
                $AceToRemove | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
                Set-Acl -Path $Path -AclObject $Acl | Out-Null
                Write-Output "Successfully removed ACL for '$Identity' on '$Path' with rights '$Rights'."              
            }
            
        }
        catch {
            Write-Error "Error modifying ACL on '$Path': $($_.Exception.Message)"
        }
    }
}