param(
    [string] $ComputerName,
    [string] $RepositoryPath = 'C:\UniversalAutomation\Repository',
    [string] $ServiceAccountName,
    [string] $ServiceAccountPass,
    [int] $MajorVersion = 5
)

# Import the lib.ps1 file.
Install-Module -Name Carbon -Force -AllowClobber -Scope AllUsers -ErrorAction SilentlyContinue
Import-Module Carbon
$Cert = Get-ChildItem cert:\localmachine\my -ErrorAction SilentlyContinue | Where-Object Subject -Like "CN=$($env:COMPUTERNAME)*" | Select-Object -First 1

if ($Cert) {
    $appSettings = @'
{
  "Kestrel": {
    "Endpoints": {
      "HTTP": {
        "Url": "http://*:5000"
      },
      "HTTPS": {
        "Url": "https://*:443",
        "Certificate": {
          "StoreName": "My",
          "Location": "LocalMachine",
          "Subject": "{{servername}}",
          "AllowInvalid": true
        }
      }
    }
  },
  "Api": {
      "TrustCertificate": true
  },
  "Plugins": [
    "SQLite"
  ],
  "Data": {
    "RepositoryPath": "{{repositorypath}}",
    "ConnectionString": "Data Source={{repositoryroot}}\\database.db"
  }
}
'@
    $appSettings = $appSettings -replace '{{servername}}', $env:COMPUTERNAME
    $appSettings = $appSettings -replace '{{repositorypath}}', ($RepositoryPath -replace '\\', '\\')
    $appSettings = $appSettings -replace '{{repositoryroot}}', (($RepositoryPath | Split-Path -Parent) -replace '\\', '\\')
    $appSettings | Set-Content -Path (Join-Path $env:ProgramData 'PowerShellUniversal\appsettings.json') -Force
}


if ($PSBoundParameters.ContainsKey('ServiceAccountName')) {

    if ($Cert) {
        # If there's a cert, ensure the service account has permissions to read it
        $path = "cert:\localmachine\my\$($cert.Thumbprint)"
        Grant-CPermission -Identity $ServiceAccountName -Permission FullControl -Path $path -Type Allow
    }

    Add-CGroupMember -Name 'Performance Log Users' -Member $ServiceAccountName
    Add-CGroupMember -Name 'Performance Monitor Users' -Member $ServiceAccountName

    # Privelges needed by the service account
    $Privileges = @(
        'SeServiceLogonRight',
        'SeBatchLogonRight',
        'SeInteractiveLogonRight',
        'SeAssignPrimaryTokenPrivilege',
        'SeIncreaseQuotaPrivilege'
    )

    foreach ($Privilege in $Privileges) {
        Grant-CPrivilege -Identity $ServiceAccountName -Privilege $Privilege
    }

    Grant-CPermission -Identity $ServiceAccountName -Permission FullControl -Path $RepositoryPath -Type Allow -ApplyTo ContainerAndSubContainersAndLeaves
    Grant-CPermission -Identity $ServiceAccountName -Permission FullControl -Path $env:ProgramData\PowerShellUniversal -Type Allow -ApplyTo ContainerAndLeaves
    Grant-CPermission -Identity $ServiceAccountName -Permission FullControl -Path $env:ProgramData\PowerShellUniversal\appsettings.json -Type Allow
}

Start-Service -Name 'PowerShellUniversal' -ErrorAction SilentlyContinue