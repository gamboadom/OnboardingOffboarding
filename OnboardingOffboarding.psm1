# Get the path to the directory containing the .psm1 file
$ModulePath = $PSScriptRoot

# Define the subfolders where your functions are located
$FunctionFolders = @('Common', 'Onboarding', 'Offboarding')

# Loop through each folder and dot-source all .ps1 files
foreach ($folder in $FunctionFolders) {
    $folderPath = Join-Path -Path $ModulePath -ChildPath $folder
    if (Test-Path -Path $folderPath -PathType Container) {
        Get-ChildItem -Path $folderPath -Filter '*.ps1' | ForEach-Object {
            Write-Verbose "Dot-sourcing function file: $($_.FullName)"
            . $_.FullName # Dot-source the file
        }
    } else {
        Write-Warning "Function folder not found: $folderPath"
    }
}

# You might have other module-level setup here
# For example, loading specific .NET assemblies or setting global module variables

# It's good practice to explicitly export functions here,
# even though the .psd1 also specifies them.
# This ensures they are exported if the .psm1 is loaded directly.
# Export-ModuleMember -Function * # Or list specific functions