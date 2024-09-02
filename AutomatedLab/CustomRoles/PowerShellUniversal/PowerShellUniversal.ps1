param(
    [string] $ComputerName,
    [ValidateSet(4,5)]
    [int] $MajorVersion = 5,
    [string] $REPOFOLDER,
    [string] $TCPPORT,
    [pscredential] $SERVICEACCOUNT,
    [string] $CONNECTIONSTRING,
    [switch] $SkipSSL
)

Import-Lab -Name $data.Name -NoValidation -NoDisplay
$labMachine = Get-LabVM -ComputerName $ComputerName

#Install-LabWindowsFeature -ComputerName $ComputerName -FeatureName RSAT-AD-PowerShell -IncludeAllSubFeature
#Wait-LabVMRestart -ComputerName $ComputerName

$releaseFile = 'https://imsreleases.blob.core.windows.net/universal/production/v{0}-version.txt' -f $MajorVersion
$releaseVer  = Invoke-RestMethod -Uri $releaseFile -UseBasicParsing
$dlFileName  = 'PowerShellUniversal.{0}.msi' -f $releaseVer
$installArgs = @(
    "/qn", 
    "/l*v C:\temp\psu_install.log",
    "STARTSERVICE=0"
)


if ($MajorVersion -eq 5) {
    $downloadUri = 'https://powershelluniversal.com/download/psu/windows/{0}' -f $releaseVer
}
else {
    $downloadUri = 'https://powershelluniversal.com/download/psu/previous/{0}/PowerShellUniversal.{0}.msi' -f $releaseVer
}

Get-LabInternetFile -Uri $downloadUri -Path $labSources\SoftwarePackages -FileName $dlFileName
Invoke-LabCommand -ActivityName 'Ensure temp folder exists' -ComputerName $ComputerName -ScriptBlock { if (-not(Test-Path 'c:\temp')) { New-Item -Path 'C:\temp' -ItemType File -Force } }

if ($REPOFOLDER) {
    $installArgs += 'REPOFOLDER="{0}"' -f $REPOFOLDER
    Invoke-LabCommand -ComputerName $labMachine -ActivityName "Creating RepoFolder" -ScriptBlock { New-Item -Path $REPOFOLDER -ItemType Directory -Force } -Variable (Get-Variable -Name REPOFOLDER)
}

if ($CONNECTIONSTRING) {
    $installArgs += 'CONNECTIONSTRING="{0}"' -f $CONNECTIONSTRING
}

if ($TCPPORT) {
    $installArgs += 'TCPPORT={0}' -f $TCPPORT
}

Write-ScreenInfo -Type Info -Message "Starting installation of PowerShell Universal $MajorVersion on $labMachine"
Write-ScreenInfo -Type Info -Message "$($installArgs -join ' ')"
$installation = Install-LabSoftwarePackage -Path (Join-Path $labSources\SoftwarePackages $dlFileName) -CommandLine $($installArgs -join ' ') -ComputerName $labMachine -ExpectedReturnCodes 0, 3010 -AsJob -PassThru -NoDisplay 

Write-ScreenInfo -Type Info -Message "Waiting for Installation to finish on $labMachine"
Wait-LWLabJob -Job $installation -ProgressIndicator 5 -NoNewLine -NoDisplay

if ($installation.State -eq 'Failed') {
    Write-ScreenInfo -Type Error -Message "Installing PowerShell Universal on $labMachine failed. Review the errors with Get-Job -Id $($installation.Id) | Receive-Job -Keep"
    Write-ScreenInfo -Type Error -Message "MSI Installation logs are on $labMachine at C:\temp\psu_install.log"
    return
}
else {
    Write-ScreenInfo -Type Info -Message "Installation completed with $($installation.State)"
}

if ($SERVICEACCOUNT) {
    try {
        $identity = $SERVICEACCOUNT.UserName
        Write-ScreenInfo -Type Verbose -Message "Configuring Domain Service account $($SERVICEACCOUNT.UserName) on $labMachine"
        Invoke-LabCommand -ComputerName $labMachine -ActivityName "Configure PowerShellUniversal Service Account" -ScriptBlock { start-process pwsh.exe -argumentlist "-Command { Set-Service -Name 'PowerShellUniversal' -Credential $SERVICEACCOUNT }" } -ErrorAction Stop -PassThru -Variable (Get-Variable -Name SERVICEACCOUNT)

        Write-ScreenInfo -Type Verbose -Message "Installing Carbon PowerShell Module to manage permissions"
        Invoke-LabCommand -ComputerName $labMachine -ActivityName "Trust PSGallery" -ScriptBlock { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
        Invoke-LabCommand -ComputerName $labMachine -ActivityName "Install Carbon" -ScriptBlock { Install-Module -Name Carbon -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber } -ErrorAction Stop

        Write-ScreenInfo -Type Verbose -Message "Adding service account to local groups..."
        Invoke-LabCommand -ComputerName $labMachine -Activity "Add $($SERVICEACCOUNT.UserName) to Performance Monitor Users" -ScriptBlock { Add-CGroupMember -Name "Performance Monitor Users" -Member $identity } -Variable (Get-Variable -Name identity)
        Invoke-LabCommand -ComputerName $labMachine -Activity "Add $($SERVICEACCOUNT.UserName) to Performance Log Users" -ScriptBlock { Add-CGroupMember -Name "Performance Log Users" -Member $identity } -Variable (Get-Variable -Name identity)

        Write-ScreenInfo -Type Verbose -Message "Adding privileges for $($SERVICEACCOUNT.UserName)"
        $privileges = @(
            @{
                Name = 'Adjust memory quotas for a process'
                Privilege = 'SeIncreaseQuotaPrivilege'
            },
            @{
                Name = 'Log on as a service'
                Privilege = 'SeServiceLogonRight'
            },
            @{
                Name = 'Replace a process level token'
                Privilege = 'SeAssignPrimaryTokenPrivilege'
            }
        )
        foreach ($priv in $privileges) {
            $Activity = "Granting '$($priv.Name)' ($($priv.Privilege)) to $($SERVICEACCOUNT.UserName) on $localMachine"
            $splat = @{
                Identity = $identity
                Privilege = $priv.Privilege
            }
            Invoke-LabCommand -ComputerName $labMachine -ActivityName $Activity -ScriptBlock { Grant-CPrivilege @splat } -Variable (Get-Variable -Name splat) -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed to configure service account on $labMachine" -Exception $_
    }
}

if ($SkipSSL -eq $false) {
    Write-ScreenInfo -Type Info -Message "Requesting SSL certificate for $labMachine"
    if ($labMachine.IsDomainJoined -and (Get-LabIssuingCA -DomainName $labMachine.DomainName -ErrorAction SilentlyContinue) ) {
        $san = $labMachine.Name
        $cert = Request-LabCertificate -Subject "CN=$($labMachine.FQDN)" -SAN $san -TemplateName WebServer -ComputerName $labMachine -PassThru -ErrorAction Stop
    }
    Write-ScreenInfo -Type Verbose -Message "Granting read rights to $($SERVICEACCOUNT.UserName) for SSL certificate"
    $splat = @{
        Path = 'Cert:\LocalMachine\My\{0}' -f $cert.Thumbprint
        Identity = $identity
    }
    Invoke-LabCommand -ComputerName $labMachine -ActivityName "Allow service account to read SSL certificate." -ScriptBlock { Grant-CPermission @splat -Permission ReadData -Type Allow } -Variable (Get-Variable -Name splat)
    $httpsEndpoint = @{ 
        Url = "https://*:443"; 
        Certificate = @{ 
            StoreName = "My"; 
            Location = 'LocalMachine'; 
            Subject = $labMachine.FQDN; 
            AllowInvalid = $true 
        }
    }

    Write-ScreenInfo -Type Verbose -Message "Updating appsettings.json on $labMachine"
    $tempFile = New-TemporaryFile
    $session  = New-LabPSSession -ComputerName $labMachine
    Receive-File -SourceFilePath 'C:\ProgramData\PowerShellUniversal\appsettings.json' -DestinationFilePath $tempFile.FullName -Session $session -ErrorAction Stop
    $appSettings =@"
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
  "Plugins": [
    "SQLite"
  ],
  "Data": {
    "RepositoryPath": "D:\\UniversalAutomation\\Repository",
    "ConnectionString": "Data Source=D:\\UniversalAutomation\\database.db"
  }
}
"@ 
    

    $content = $appSettings -replace '{{servername}}', $ComputerName
    
    Invoke-LabCommand -ComputerName $labMachine -ActivityName "Adding HTTPS endpoint to appsettings.json" -ScriptBlock { Set-Content -Path (Join-Path $env:ProgramData 'PowerShellUniversal\appsettings.json') -Value $content -Force } -Variable (Get-Variable -Name content)
}