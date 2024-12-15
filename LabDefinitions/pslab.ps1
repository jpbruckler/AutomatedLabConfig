$labName = 'pslab'
$AdminUser = 'Administrator'
$AdminPass = 'L4bP@ssw0rd'
$DomainName = 'lab.local'
$DefaultPass = 's0methingS@fe1'

New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV -VmPath "C:\AutomatedLab-VMs\$labName"
Set-LabInstallationCredential -Username $AdminUser -Password $AdminPass

Add-LabDomainDefinition -Name $DomainName -AdminUser $AdminUser -AdminPassword $AdminPass


Add-LabVirtualNetworkDefinition -Name 'PSLabInternalVSwitch' -AddressSpace 172.17.112.0/24 -HyperVProperties @{SwitchType = 'Internal' }
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{SwitchType = 'External'; AdapterName = 'Ethernet' } 


$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = $DomainName
    'Add-LabMachineDefinition:Gateway'         = '172.17.112.2'
    'Add-LabMachineDefinition:DnsServer1'      = '172.17.112.70'
    'Add-LabMachineDefinition:DnsServer2'      = '8.8.8.8'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter'
    'Add-LabMachineDefinition:Network'         = 'PSLabInternalVSwitch'
    'Add-LabMachineDefinition:Memory'          = 1gb
    'Add-LabMachineDefinition:MinMemory'       = 512mb
    'Add-LabMachineDefinition:MaxMemory'       = 2gb
}

#endregion
Add-LabDiskDefinition -Name psu_datadisk -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
Add-LabDiskDefinition -Name psu_datadisk1 -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
$adUserPIA = @{
    DependencyFolder = "$labSources\PostInstallationActivities\PrepareFirstChildDomain"
    ScriptFileName   = 'New-ADLabAccounts 2.0.ps1'
}
$machineDefinitions = @(
    @{
        Name      = 'svr-lab-rootca'
        IpAddress = '172.17.112.30'
        Memory    = 512mb
        Roles     = Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
            CACommonName        = 'labRootCA'
            KeyLength           = '4096'
            ValidityPeriod      = 'Years'
            ValidityPeriodUnits = '20'
        }
    },
    @{
        Name                     = 'svr-lab-dc01'
        IpAddress                = '172.17.112.70'
        Processors               = 1
        Roles                    = Get-LabMachineRoleDefinition -Role RootDC
        PostInstallationActivity = Get-LabPostInstallationActivity @adUserPIA
    },
    @{
        Name           = 'svr-lab-router'
        Roles          = Get-LabMachineRoleDefinition -Role Routing
        NetworkAdapter = @(
            New-LabNetworkAdapterDefinition -VirtualSwitch 'PSLabInternalVSwitch' -Ipv4Address 172.17.112.2
            New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp
        )
    }
    @{
        Name                     = 'svr-lab-wac01'
        IpAddress                = '172.17.112.100'
        Processors               = 2
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole WindowsAdminCenter -Properties @{ 
            ComputerName = 'svr-lab-wac01'
        }
        OperatingSystem          = 'Windows Server 2022 Datacenter (Desktop Experience)'
    },
    @{
        Name                     = 'svr-lab-psu01'
        IpAddress                = '172.17.112.101'
        Memory                   = 2gb
        MaxMemory                = 4gb
        Processors               = 2
        DiskName                 = 'psu_datadisk'
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{
            RepositoryPath     = 'D:\UniversalAutomation\Repository'
            ServiceAccountName = 'lab\svc-imsrun'
            ServiceAccountPass = $DefaultPass
            MajorVersion       = 4
            ComputerName       = 'svr-lab-psu01'
        }
    },
    @{
        Name                     = 'svr-lab-psu02'
        IpAddress                = '172.17.112.102'
        Memory                   = 2gb
        MaxMemory                = 4gb
        Processors               = 2
        DiskName                 = 'psu_datadisk1'
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{
            RepositoryPath     = 'D:\UniversalAutomation\Repository'
            ServiceAccountName = 'lab\svc-imsrun'
            ServiceAccountPass = $DefaultPass
            MajorVersion       = 5
            ComputerName       = 'svr-lab-psu02'
        }
    }
)

foreach ($Definition in $MachineDefinitions) {
    Add-LabMachineDefinition @Definition
}

Install-Lab -NetworkSwitches -BaseImages -VMs
Install-Lab -Domains
Install-Lab -Routing
Enable-LabInternalRouting -RoutingNetworkName PSLabInternalVSwitch
Install-Lab -CA
Install-Lab -StartRemainingMachines
Enable-LabVMRemoting -All
Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning

Invoke-LabCommand -ActivityName 'Publish WebServer Certificate' -ComputerName svr-lab-rootca -ScriptBlock {
    Publish-CaTemplate -TemplateName 'WebServer'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:GR'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:CA;Enroll'
}

Invoke-LabCommand -ActivityName 'Create lab OU' -ComputerName svr-lab-dc01 -ScriptBlock { 
    if (-not (Get-ADOrganizationalUnit -Filter { Name -eq 'lab' })) {
        New-ADOrganizationalUnit -Name 'lab' -Path 'DC=lab,DC=local' 
    }
}

Invoke-LabCommand -ActivityName 'Create lab users' -ComputerName svr-lab-dc01 -ScriptBlock {
    $labOU = Get-ADOrganizationalUnit -Filter { Name -eq 'lab' }
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
            Path              = $labOU.DistinguishedName
        }
        New-ADUser @userProps
    }
} -Variable (Get-Variable -Name DefaultPass), (Get-Variable -Name DomainName)


# Install Software on all machines
$LabVMs = Get-LabVM | Select-Object -ExpandProperty Name
$LabVMs | ForEach-Object {
    # --------------------------------------------------------------------------
    # Every machine gets this same setup steps
    # --------------------------------------------------------------------------
    # Create log directory and do some initial PowerShell configuration
    Invoke-LabCommand -ActivityName 'Create C:\Temp' -ComputerName $_ -ScriptBlock { 
        New-Item -ItemType Directory -Path C:\Temp -Force
    }

    Invoke-LabCommand -ActivityName 'PowerShell 5 Config' -ComputerName $_ -ScriptBlock { 
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
        Install-Module carbon -Force
    }

    if (-not (Invoke-LabCommand -ComputerName $_ -ScriptBlock { Get-Command pwsh } -PassThru)) {
        Install-LabSoftwarePackage -ComputerName $_ -Path "$labSources\SoftwarePackages\PowerShell-7.4.6-win-x64.msi" -CommandLine '/qn /l*v C:\temp\Pwsh_install.log ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1'
        Restart-LabVM -ComputerName $_
    }

    # # Install Chocolatey and base sofware
    # Invoke-LabCommand -ActivityName 'Install Chocolatey' -ComputerName $_ -ScriptBlock {
    #     if ($null -eq (Get-Command choco -ErrorAction SilentlyContinue)) {
    #         Set-ExecutionPolicy Bypass -Scope Process -Force 
    #         [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 
    #         Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    #     }
    # }

    # # Install chocolatey packages
    # $packageNames = @(
    #     '7zip'
    # )
    # foreach ($package in $packageNames) { 
    #     Invoke-LabCommand -ActivityName "Install $package" -ComputerName $_ -ScriptBlock { 
    #         choco install $package -y 
    #     } -Variable (Get-Variable -Name package)
    # }

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

Install-Lab -PostInstallations 
Show-LabDeploymentSummary -Detailed