$LabName = 'PSUSmol'
$InstallUser = 'Administrator'
$InstallPass = 'L4bP@ssw0rd'
$DefaultPass = $InstallPass
$DomainName = 'lab.local'
$DefaultServerOS = 'Windows Server 2022 Datacenter Evaluation'
$LabAddressSpace = '172.17.112.0/24'
$LabRootAddress = ($LabAddressSpace -split '\.0\/\d{0,2}$')
$LabExternalVSwitch = 'Default Switch'

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath 'C:\AutomatedLab-VMs'
Set-LabInstallationCredential -Username $InstallUser -Password $InstallPass
Add-LabDomainDefinition -Name $DomainName -AdminUser $InstallUser -AdminPassword $InstallPass
Add-LabVirtualNetworkDefinition -Name $LabExternalVSwitch -HyperVProperties @{SwitchType = 'External'; AdapterName = 'Ethernet' }

# Setup cmdlet default parameter values to simplify the lab definition.
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = $DomainName
    'Add-LabMachineDefinition:OperatingSystem' = $DefaultServerOS

    # Calculate the gateway address based on the lab address space.
    #'Add-LabMachineDefinition:Gateway'         = ('{0}.2' -f $LabRootAddress)
    #'Add-LabMachineDefinition:Network'         = $LabExternalVSwitch

    # Set the DNS server addresses.
    'Add-LabMachineDefinition:DnsServer1'      = ('{0}.70' -f $LabRootAddress)
    'Add-LabMachineDefinition:DnsServer2'      = '1.1.1.1'

    # Set the default memory & processor values for the lab machines.
    'Add-LabMachineDefinition:Memory'          = 1gb
    'Add-LabMachineDefinition:MinMemory'       = 512mb
    'Add-LabMachineDefinition:MaxMemory'       = 2gb
}

Add-LabDiskDefinition -Name psu_datadisk01 -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
$machines = @(
    @{
        Name                     = 'svr-lab-dc'
        IpAddress                = ('{0}.70' -f $LabRootAddress)
        Memory                   = 1gb
        Roles                    = @(
            (Get-LabMachineRoleDefinition -Role RootDC),
            (Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
                CACommonName        = 'UniversalLabRootCA'
                KeyLength           = '4096'
                ValidityPeriod      = 'Years'
                ValidityPeriodUnits = '20'
            })
        )
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PopulateAD -Properties @{
            EmailDomain = $DomainName
        }
    },
    @{
        Name                     = 'svr-lab-psu'
        IpAddress                = ('{0}.101' -f $LabRootAddress)
        Memory                   = 4gb
        MaxMemory                = 8gb
        Processors               = 4
        DiskName                 = 'psu_datadisk01'
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{
            RepositoryPath     = 'D:\UniversalAutomation\Repository'
            ServiceAccountName = 'lab\svc-imsrun'
            ServiceAccountPass = $DefaultPass
            MajorVersion       = 5
            ComputerName       = 'svr-lab-psu'
        }
    }
)

foreach ($Definition in $machines) {
    Add-LabMachineDefinition @Definition
}

Install-Lab -NetworkSwitches -BaseImages -VMs
Install-Lab -Domains

Install-Lab -CA
Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning

Install-Lab -StartRemainingMachines
Enable-LabVMRemoting -All

$RootCA = Get-LabVM | Where-Object { $_.Roles.Name -like 'CaRoot' }
$RootDC = Get-LabVM | Where-Object { $_.Roles.Name -like 'RootDC' }
Invoke-LabCommand -ActivityName 'Publish WebServer Certificate' -ComputerName $RootCA -ScriptBlock {
    Publish-CaTemplate -TemplateName 'WebServer'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'DomainName Users:GR'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'DomainName Users:CA;Enroll'
} -Variable (Get-Variable -Name DomainName)

Invoke-LabCommand -ActivityName 'Create Lab AD Structure' -ComputerName $RootDC -ScriptBlock {
    $labUsers = @(
        @{
            Name           = 'PSU Service Account'
            SamAccountName = 'svc-imsrun'
        },
        @{
            Name           = 'Lab Developer'
            SamAccountName = 'labdev'
        }
    )

    foreach ($user in $labUsers) {
        if (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'") {
            continue
        }
        $userProps = @{
            Name              = $user.Name
            SamAccountName    = $user.SamAccountName
            UserPrincipalName = "$($user.SamAccountName)@$DomainName"
            AccountPassword   = (ConvertTo-SecureString $DefaultPass -AsPlainText -Force)
            Enabled           = $true
        }
        New-ADUser @userProps
    }
} -Variable (Get-Variable -Name DefaultPass), (Get-Variable -Name DomainName) -PassThru

$LabVMs = Get-LabVM | Select-Object -ExpandProperty Name
$LabVMs | ForEach-Object {
    # Create temp directory
    Invoke-LabCommand -ActivityName 'Create C:\Temp' -ComputerName $_ -ScriptBlock {
        New-Item -ItemType Directory -Path C:\Temp -Force
    }

    # Update PowerShell Nuget Provider and Install Carbon module
    Invoke-LabCommand -ActivityName 'PowerShell 5 Config' -ComputerName $_ -ScriptBlock {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module carbon -Force -Scope AllUsers
    }

    $latest = Invoke-RestMethod -Uri 'api.github.com/repos/powershell/powershell/releases/latest'
    $target = $latest.assets | Where-Object name -Like '*win-x64.msi'
    if (-not (Test-Path -Path "$labSources\SoftwarePackages\$($target.name)")) {
        Invoke-WebRequest -Uri $target.browser_download_url -OutFile "$labSources\SoftwarePackages\$($target.name)"
    }

    Install-LabSoftwarePackage -ComputerName $_ -Path "$labSources\SoftwarePackages\$($target.name)" -CommandLine '/qn /l*v C:\temp\Pwsh_install.log ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1'

    if ($_ -eq 'svr-lab-psu') {
        # Install Scoop
        Invoke-LabCommand -ActivityName 'Install Scoop' -ComputerName $_ -ScriptBlock {
            Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin"
        }

        # Scoop install some things
        Invoke-LabCommand -ActivityName 'Install Git and Neovim' -ComputerName $_ -ScriptBlock {
            scoop install neovim
            scoop install git
            scoop bucket add extras
            scoop install extras/vcredist2022
        }

        # Update Pester
        Invoke-LabCommand -ActivityName 'Update Pester' -ComputerName $_ -ScriptBlock {
            $module = 'C:\Program Files\WindowsPowerShell\Modules\Pester'
            & takeown.exe /F $module /A /R
            & icacls.exe $module /reset
            & icacls.exe $module /grant '*S-1-5-32-544:F' /inheritance:d /T
            Remove-Item -Path $module -Recurse -Force -Confirm:$false

            # Install latest Pester
            Install-Module -Name Pester -Scope AllUsers -Force
        }
    }

    Invoke-LabCommand -ActivityName 'Enable PowerShell 7 WinRM' -ComputerName $_ -ScriptBlock {
        Start-Process pwsh -ArgumentList '-Command &{ Enable-PSRemoting -Force }'
    }

    # Add web server certificate
    $cert = Get-LabCertificate -Computer $_ -SearchString $_ -FindType FindBySubjectName -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My
    if ($null -eq $cert) {
        $subject = 'CN={0}' -f (Get-LabVM -ComputerName $_).FQDN
        $san = @(
                    ('{0}.{1}' -f $_, $DomainName),
                    ('{0}' -f $_)
        )
        Request-LabCertificate -Subject $subject -SAN $san -TemplateName WebServer -ComputerName $_
    }

    # Install RSAT
    Install-LabWindowsFeature -FeatureName RSAT -ComputerName $_ -IncludeAllSubFeature -IncludeManagementTools
}

# Retrieve Root CA certificate and place in $labSources\SoftwarePackages

Invoke-LabCommand -ComputerName $RootCA.Name -ActivityName 'Export Root CA Certificate' -ScriptBlock {
    $cert = Get-ChildItem -Path cert:\localmachine\root | Where-Object { $_.Subject -like '*UniversalLabRootCA*' } | Select-Object -First 1
    Export-Certificate -Cert $cert -FilePath c:\temp\UniversalLabRootCA.cer -Type CERT
}
$RootCaSession = New-LabPSSession $RootCA.name
Receive-File -SourceFilePath C:\temp\UniversalLabRootCA.cer -DestinationFilePath $labSources\SoftwarePackages\UniversalLabRootCA.cer -Session $RootCaSession
$RootCaSession = $null

Get-LabVM | Restart-LabVM -Wait

Install-Lab -PostInstallations

Show-LabDeploymentSummary