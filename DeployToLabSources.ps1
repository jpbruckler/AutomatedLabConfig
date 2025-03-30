[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $LabSourcesPath
)

if (-not (Test-Path $LabSourcesPath)) {
    Write-Error "LabSourcesPath does not exist: $LabSourcesPath"
    exit 1
}
$InformationPreference = 'Continue'

Write-Information "Copying Custom Roles to $LabSourcesPath"
Copy-Item -Path (Join-Path $PSScriptRoot 'CustomRoles') -Destination $LabSourcesPath -Recurse -Force

Write-Information "Copying Lab Definitions to $LabSourcesPath"
Copy-Item -Path (Join-Path $PSScriptRoot 'LabDefinitions') -Destination $LabSourcesPath -Recurse -Force

Write-Information "Copying PostInstallationActivities to $LabSourcesPath"
Copy-Item -Path (Join-Path $PSScriptRoot 'PostInstallationActivities') -Destination $LabSourcesPath -Recurse -Force
