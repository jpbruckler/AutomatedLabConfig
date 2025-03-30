$LabName            = 'smol'
$DomainName         = 'smol.lab'
$InstallUser        = "Administrator"
$DefaultPass        = "L4bP@ssw0rd"
$LabAddressSpace    = '172.17.112.0/24'
$LabRootAddress     = ($LabAddressSpace -split '\.0\/\d{0,2}$')
$LabInternalVSwitch = 'LabInternalVSwitch'
$LabExternalVSwitch = 'Default Switch'

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = $DomainName
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter Evaluation (Desktop Experience)'
    'Add-LabMachineDefinition:Memory'          = 1gb
    'Add-LabMachineDefinition:MinMemory'       = 512mb
    'Add-LabMachineDefinition:MaxMemory'       = 2gb
    # Calculate the gateway address based on the lab address space.
    'Add-LabMachineDefinition:Gateway'         = ('{0}.70' -f $LabRootAddress)
    'Add-LabMachineDefinition:Network'         = $LabInternalVSwitch

    # Set the DNS server addresses.
    'Add-LabMachineDefinition:DnsServer1'      = ('{0}.70' -f $LabRootAddress)
    #'Add-LabMachineDefinition:DnsServer2'      = '1.1.1.1'
}

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath 'C:\AutomatedLab-VMs'
Set-LabInstallationCredential -Username $InstallUser -Password $DefaultPass
Add-LabDomainDefinition -Name $DomainName -AdminUser $InstallUser -AdminPassword $DefaultPass
Add-LabVirtualNetworkDefinition -Name $LabInternalVSwitch -AddressSpace $LabAddressSpace -HyperVProperties @{SwitchType = 'Internal' }
Add-LabVirtualNetworkDefinition -Name $LabExternalVSwitch -HyperVProperties @{SwitchType = 'External'; AdapterName = 'Ethernet' }


$Dc = @{
    Name                     = 'smol-pdc'
    Memory                   = 2gb
    Roles                    = @(
        (Get-LabMachineRoleDefinition -Role RootDC),
        (Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
            CACommonName        = 'UniversalLabRootCA'
            KeyLength           = '4096'
            ValidityPeriod      = 'Years'
            ValidityPeriodUnits = '20'
        }),
        (Get-LabMachineRoleDefinition -Role Routing)
    )
    PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PopulateAD -Properties @{
        EmailDomain = $DomainName
    }
    NetworkAdapter = @(
        New-LabNetworkAdapterDefinition -VirtualSwitch $LabInternalVSwitch -Ipv4Address ('{0}.70' -f $LabRootAddress)
        New-LabNetworkAdapterDefinition -VirtualSwitch $LabExternalVSwitch -UseDhcp
    )
}

$Psu = @{
    Name                     = 'smol-psu'
    IpAddress                = ('{0}.100' -f $LabRootAddress)
    Memory                   = 2gb
    MaxMemory                = 4gb
    Processors               = 2
    PostInstallationActivity = Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{
        RepositoryPath     = 'C:\UniversalAutomation\Repository'
        ServiceAccountName = 'lab\svc-imsrun'
        ServiceAccountPass = $DefaultPass
        MajorVersion       = 5
        ComputerName       = 'svr-lab-psu'
    }
}
Add-LabMachineDefinition @Dc
Add-LabMachineDefinition @Psu


Install-Lab -NetworkSwitches -BaseImages -VMs
Install-Lab -Domains

Install-Lab -Routing
Enable-LabInternalRouting -RoutingNetworkName 'LabInternalVSwitch'

Install-Lab -CA
Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning

Install-Lab -StartRemainingMachines
Enable-LabVMRemoting -All
