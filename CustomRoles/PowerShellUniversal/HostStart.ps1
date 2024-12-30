param(
    [Parameter(Mandatory = $true)]
    [string] $ComputerName,
    [string] $RepositoryPath = 'C:\UniversalAutomation\Repository',
    [string] $ServiceAccountName,
    [string] $ServiceAccountPass,
    [int] $MajorVersion = 5,
    [switch] $Force
)

#region functions
function Get-PSUInstallerInfo {
    param(
        [int]$MajorVersion = 4
    )

    begin {}

    process {
        $VersionUrl = 'https://imsreleases.blob.core.windows.net/universal/production/v{0}-version.txt' -f $MajorVersion

        try {
            $LatestVersion = (Invoke-WebRequest $VersionUrl -UseBasicParsing -ErrorAction Stop).Content
            $MsiFileName = "PowerShellUniversal.$LatestVersion.msi"
            $InstallerUrl = "https://imsreleases.blob.core.windows.net/universal/production/$LatestVersion/$MsiFileName"
            $InstallerInfo = @{
                Version     = $LatestVersion
                FileName    = $MsiFileName
                DownloadUrl = $InstallerUrl
            }
            return $InstallerInfo
        }
        catch {
            Write-Error "Failed to get installer info. $_"
        }
    }
}
#endregion

Import-Lab -Name $data.Name -NoValidation -NoDisplay
$vm = Get-LabVM -ComputerName $ComputerName

$PSUService = Invoke-LabCommand -ComputerName $vm.Name -ActivityName 'Get PSU Service' -ScriptBlock {
    Get-Service -Name 'PowerShellUniversal'
} -PassThru

if ($PSUService -and -not $Force) {
    Write-ScreenInfo -Message 'PowerShell Universal is already installed on the target machine. Use the -Force switch to reinstall.'
    return
}

# Get information about the latest PowerShell Universal version and
# download the installer to the C:\temp folder.
$psuInfo = Get-PSUInstallerInfo -MajorVersion $MajorVersion
Get-LabInternetFile -Uri $psuInfo.DownloadUrl -Path "$labSources\SoftwarePackages" -FileName $psuInfo.FileName

# Ensure $RepositoryPath is in the correct format and
# that it exists.
if (($RepositoryPath | Split-Path -Leaf) -ne 'Repository') {
    $RepositoryPath = Join-Path $RepositoryPath 'Repository'
}

Invoke-LabCommand -ComputerName $vm.Name -ActivityName 'Create Repository Folder' -ScriptBlock {
    if (-not (Test-Path $RepositoryPath)) {
        New-Item -Path $RepositoryPath -ItemType Directory
    }
} -Variable (Get-Variable RepositoryPath)

# Prepare the installation arguments for the PowerShell Universal installer.
$RepositoryRoot = $RepositoryPath | Split-Path -Parent
$InstallArgs = @(
    '/qn',
    '/l*v',
    "$SCRIPTTEMPFOLDER\$($psuInfo.FileName)_install.log",
    "REPOFOLDER=$RepositoryPath",
    ('CONNECTIONSTRING="Data Source={0}\database.db"' -f $RepositoryRoot),
    'STARTSERVICE=0'
)

# If a service account name and password were provided, add them to the installation arguments.
if ($ServiceAccountName -and $ServiceAccountPass) {
    $InstallArgs += "SERVICEACCOUNT=$ServiceAccountName"
    $InstallArgs += "SERVICEACCOUNTPASSWORD=$ServiceAccountPass"
}

# Install PowerShell Universal on the target machine.
Write-ScreenInfo -Message "Installing PowerShell Universal with arguments $($InstallArgs -join ' ')"
Install-LabSoftwarePackage -Path "$labSources\SoftwarePackages\$($psuInfo.FileName)" -CommandLine ($InstallArgs -join ' ') -ComputerName $vm.Name
Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Install Carbon Module' -ScriptBlock {
    Install-Module -Name Carbon -Scope AllUsers -Force
}
$script = Get-Command -Name $PSScriptRoot\PowerShellUniversal.ps1
$params = Sync-Parameter -Command $script -Parameters $PSBoundParameters
Copy-LabFileItem -Path $labSources\CustomRoles\PowerShellUniversal -ComputerName $vm.Name -DestinationFolderPath 'C:\' -Recurse
Invoke-LabCommand -ComputerName $vm -ActivityName 'PowerShellUniversal' -ScriptBlock {
    & C:\PowerShellUniversal\PowerShellUniversal.ps1 @params
} -Variable (Get-Variable params)

Invoke-LabCommand -ComputerName $vm.Name -ActivityName 'Start PSU Service' -ScriptBlock {
    Start-Service -Name 'PowerShellUniversal'
} -PassThru

Invoke-LabCommand -ComputerName $vm.Name -ActivityName 'Cleanup' -ScriptBlock {
    Remove-Item -Path C:\PowerShellUniversal -Recurse -Force -ErrorAction SilentlyContinue
}