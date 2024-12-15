<#
#>

$labName = "UniversalLab"
$InstallUser = "Administrator"
$InstallPass = "L4bP@ssw0rd"
$DefaultPass = "L4bP@ssw0rd"
$Domain = "psu.local"
$DefaultServerOS = "Windows Server 2022 Datacenter Evaluation"
$DefaultDesktpOS = "Windows 11 Enterprise Evaluation"
$LabAddressSpace = '172.17.110.0/24'
$LabRootAddress = ($LabAddressSpace -split '\.0\/\d{0,2}$')
$LabInternalVSwitch = 'LabInternalVSwitch'
$LabExternalVSwitch = 'Default Switch'

# Create the lab definition, set the installation credentials, and add the domain definition.
New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV  -VmPath "C:\AutomatedLab-VMs\$labName"
Set-LabInstallationCredential -Username $InstallUser -Password $InstallPass
Add-LabDomainDefinition -Name $Domain -AdminUser $InstallUser -AdminPassword $InstallPass

# Define the lab network.
# - LabInternalVSwitch: Internal virtual switch for the lab network. All lab machines will connect to 
#                       this switch.
# - Default Switch:     External virtual switch for the lab network. This switch is the default Hyper-V
#                       switch that connects to the host's network adapter and provides internet access.
Add-LabVirtualNetworkDefinition -Name $LabInternalVSwitch -AddressSpace $LabAddressSpace -HyperVProperties @{SwitchType = 'Internal' }
Add-LabVirtualNetworkDefinition -Name $LabExternalVSwitch -HyperVProperties @{SwitchType = 'External'; AdapterName = 'Ethernet' } 

# Setup cmdlet default parameter values to simplify the lab definition.
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = $Domain
    'Add-LabMachineDefinition:OperatingSystem' = $DefaultServerOS
    
    # Calculate the gateway address based on the lab address space.
    'Add-LabMachineDefinition:Gateway'         = ('{0}.2' -f  $LabRootAddress)
    'Add-LabMachineDefinition:Network'         = $LabInternalVSwitch
    
    # Set the DNS server addresses.
    'Add-LabMachineDefinition:DnsServer1'      = ('{0}.70' -f $LabRootAddress)
    'Add-LabMachineDefinition:DnsServer2'      = '1.1.1.1'

    # Set the default memory & processor values for the lab machines.
    'Add-LabMachineDefinition:Memory'          = 1gb
    'Add-LabMachineDefinition:MinMemory'       = 512mb
    'Add-LabMachineDefinition:MaxMemory'       = 2gb
}

# =============================================================================
# Lab machine definitions
# =============================================================================
# The array of hash tables defines the lab machines to create. Each hash table
# represents a lab machine and its properties. The properties include the machine
# name, IP address, memory, processor count, roles, and post-installation activities.
# Each machine definition is passed to the Add-LabMachineDefinition cmdlet via
# splatting.
# -----------------------------------------------------------------------------
Add-LabDiskDefinition -Name psu_datadisk -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
$machineDefinitions = @(
    # Domain Controller and RootCA
    @{
        Name      = 'svr-lab-pdc'
        IpAddress = ('{0}.70' -f $LabRootAddress)
        Memory    = 1gb
        Roles     = @(
            (Get-LabMachineRoleDefinition -Role RootDC),
            (Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
                CACommonName        = 'UniversalLabRootCA'
                KeyLength           = '4096'
                ValidityPeriod      = 'Years'
                ValidityPeriodUnits = '20'
            })
        )
    },
    # Router
    @{
        Name           = 'svr-lab-rtr'
        Roles          = Get-LabMachineRoleDefinition -Role Routing
        NetworkAdapter = @(
            New-LabNetworkAdapterDefinition -VirtualSwitch $LabInternalVSwitch -Ipv4Address ('{0}.2' -f  $LabRootAddress)
            New-LabNetworkAdapterDefinition -VirtualSwitch $LabExternalVSwitch -UseDhcp
        )
    },
    @{
        Name                     = 'svr-lab-wac'
        IpAddress                = '172.17.112.100'
        Processors               = 2
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole WindowsAdminCenter -Properties @{ 
            ComputerName = 'svr-lab-wac'
        }
        OperatingSystem          = 'Windows Server 2022 Datacenter Evaluation (Desktop Experience)'
    },
    @{
        Name                     = 'svr-lab-psu'
        IpAddress                = '172.17.112.101'
        Memory                   = 2gb
        MaxMemory                = 4gb
        Processors               = 2
        DiskName                 = 'psu_datadisk'
        PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{
            RepositoryPath     = 'D:\UniversalAutomation\Repository'
            ServiceAccountName = 'lab\svc-imsrun'
            ServiceAccountPass = $DefaultPass
            MajorVersion       = 5
            ComputerName       = 'svr-lab-psu'
        }
    }
)

foreach ($Definition in $MachineDefinitions) {
    Add-LabMachineDefinition @Definition
}

Install-Lab -NetworkSwitches -BaseImages -VMs
Install-Lab -Domains

Install-Lab -Routing
Enable-LabInternalRouting -RoutingNetworkName 'LabInternalVSwitch'
Install-Lab -CA

Install-Lab -StartRemainingMachines
Enable-LabVMRemoting -All
Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning

# =============================================================================
# Software installs
# =============================================================================
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
    # Create temp directory
    Invoke-LabCommand -ActivityName 'Create C:\Temp' -ComputerName $_ -ScriptBlock { 
        New-Item -ItemType Directory -Path C:\Temp -Force
    }

    # Update PowerShell Nuget Provider and Install Carbon module
    Invoke-LabCommand -ActivityName 'PowerShell 5 Config' -ComputerName $_ -ScriptBlock { 
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
        Install-Module carbon -Force
    }

    # Install PowerShell 7.4.6
    if (-not (Invoke-LabCommand -ComputerName $_ -ScriptBlock { Get-Command pwsh } -PassThru)) {
        Install-LabSoftwarePackage -ComputerName $_ -Path "$labSources\SoftwarePackages\PowerShell-7.4.6-win-x64.msi" -CommandLine '/qn /l*v C:\temp\Pwsh_install.log ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1'
        Restart-LabVM -ComputerName $_
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

Install-Lab -PostInstallations 
Show-LabDeploymentSummary -Detailed