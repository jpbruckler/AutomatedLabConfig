$labName    = 'pslab'
$AdminUser  = 'Administrator'
$AdminPass  = 'L4bP@ssw0rd'
$DomainName = 'lab.local'
$DefaultPass = 's0methingS@fe1'

New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV -VmPath C:\AutomatedLab-VMs
Set-LabInstallationCredential -Username $AdminUser -Password $AdminPass

Add-LabDomainDefinition -Name $DomainName -AdminUser $AdminUser -AdminPassword $AdminPass


Add-LabVirtualNetworkDefinition -Name 'PSLabInternalVSwitch' -AddressSpace 172.17.112.0/24 -HyperVProperties @{SwitchType = 'Internal'}
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{SwitchType = 'External'; AdapterName = 'Ethernet'} 


$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'        = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'       = $DomainName
    'Add-LabMachineDefinition:Gateway'          = '172.17.112.2'
    'Add-LabMachineDefinition:DnsServer1'       = '172.17.112.70'
    'Add-LabMachineDefinition:DnsServer2'       = '8.8.8.8'
    'Add-LabMachineDefinition:OperatingSystem'  = 'Windows Server 2022 Datacenter'
    'Add-LabMachineDefinition:Network'          = 'PSLabInternalVSwitch'
    'Add-LabMachineDefinition:Memory'           = 1gb
    'Add-LabMachineDefinition:MinMemory'        = 512mb
    'Add-LabMachineDefinition:MaxMemory'        = 2gb
}

#endregion
#Add-LabDiskDefinition -Name psu_datadisk -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
Add-LabDiskDefinition -Name psu_datadisk1 -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb

$machineDefinitions = @(
    @{
        Name            = 'svr-lab-rootca'
        IpAddress       = '172.17.112.30'
        Memory          = 512mb
        Roles           = Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
            CACommonName        = 'labRootCA'
            KeyLength           = '4096'
            ValidityPeriod      = 'Years'
            ValidityPeriodUnits = '20'
        }
    },
    @{
        Name            = 'svr-lab-dc01'
        IpAddress       = '172.17.112.70'
        Processors      = 1
        Roles           = Get-LabMachineRoleDefinition -Role RootDC
    },
    @{
        Name            = 'svr-lab-router'
        NetworkAdapter  = @(
            New-LabNetworkAdapterDefinition -VirtualSwitch 'PSLabInternalVSwitch' -Ipv4Address 172.17.112.2
            New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp
        )
        Roles           = Get-LabMachineRoleDefinition -Role Routing
    }
    @{
        Name            = 'svr-lab-wac01'
        IpAddress       = '172.17.112.100'
        Processors      = 2
        Roles           = Get-LabMachineRoleDefinition -Role WindowsAdminCenter
        OperatingSystem = 'Windows Server 2022 Datacenter (Desktop Experience)'
    },
    # @{
    #     Name            = 'svr-lab-psu01'
    #     IpAddress       = '172.17.112.101'
    #     Memory          = 4gb
    #     MaxMemory       = 8gb
    #     Processors      = 4
    #     DiskName        = 'psu_datadisk'
    # },
    @{
        Name            = 'svr-lab-psu02'
        IpAddress       = '172.17.112.102'
        Memory          = 2gb
        MaxMemory       = 4gb
        Processors      = 2
        DiskName        = 'psu_datadisk1'
        PostInstallationActivity = (
            Get-LabPostInstallationActivity -CustomRole PowerShellUniversal -Properties @{ 
                ComputerName = 'svr-lab-psu02'
                REPOFOLDER = 'D:\UniversalAutomation\Repository'
                CONNECTIONSTRING = 'Data Source=D:\UniversalAutomation\database.db'
                SERVICEACCOUNT = [pscredential]::new('lab\svc-ims', (ConvertTo-SecureString $DefaultPass -AsPlainText -Force))
            }
        )
    }
)

foreach ($Definition in $MachineDefinitions) {
    Add-LabMachineDefinition @Definition
}

Install-Lab -NetworkSwitches -BaseImages -VMs

$LabVMs = Get-LabVM
$definedDCs = ($machineDefinitions | Where-Object { $_.Roles.Name -like '*DC' }).Name
$deployedDCs = ($LabVMs | Where-Object { $_.Roles.Name -like '*DC' }).Name

# if no lab vms or not enough DCs deployed
if ($null -eq $LabVMs -or ($definedDCs | Where-Object { $_ -notin $deployedDCs })) {
    Install-Lab -Domains
}

# if no lab vms or no router
if ($null -eq $LabVMs -or (-not ($LabVMs | Where-Object { $_.Roles.Name -eq 'Routing'}))) {
    Install-Lab -Routing
    Enable-LabInternalRouting -RoutingNetworkName PSLabInternalVSwitch
}

# If no lab vms, or no root ca
if ($null -eq $LabVMs -or (-not ($LabVMs | Where-Object { $_.Roles.Name -eq 'CaRoot'}))) {
    Install-Lab -CA
    Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning 
}

Invoke-LabCommand -ActivityName 'Publish WebServer Certificate' -ComputerName svr-lab-rootca -ScriptBlock {
    $tplExists = Get-CaTemplate -TemplateName 'WebServer'
    if ($null -eq $tplExists) {
        Publish-CaTemplate -TemplateName 'WebServer'
        dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:GR'
        dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:CA;Enroll'
    }
} -Variable (Get-Variable -Name DomainName)

Install-Lab -StartRemainingMachines

Enable-LabVMRemoting -All

# Install Software on all machines
$LabVMs = Get-LabVM | Select-Object -ExpandProperty Name
$LabVMs | ForEach-Object { 
    # Create log directory
    Invoke-LabCommand -ActivityName "Create C:\Temp" -ComputerName $_ -ScriptBlock { New-Item -ItemType Directory -Path C:\Temp -force }

    # Install Chocolatey
    $sb = { 
        Set-ExecutionPolicy Bypass -Scope Process -Force; 
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    Invoke-LabCommand -ActivityName "Install Chocolatey" -ComputerName $_ -ScriptBlock $sb
    Restart-LabVM -ComputerName $_ -Wait
    # Install chocolatey packages
    $packageNames = @(
        'powershell-core',
        '7zip',
        'vscode'
    )
    foreach ($package in $packageNames) { 
        $chocoPkg = $package
        Invoke-LabCommand -ActivityName "Install $package" -ComputerName $_ -ScriptBlock { choco.exe install $chocoPkg -y } -PassThru -Variable (Get-Variable -name chocoPkg)
    }

    Restart-LabVM -ComputerName $_ -Wait
    Invoke-LabCommand -ComputerName $_ -ActivityName 'Enable PowerShell 7 Remoting' -ScriptBlock { start-process 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '{ Enable-PSRemoting -Force -SkipNetworkProfileCheck }'}
} 

# Specific Machines
#region svr-lab-dc01
Invoke-LabCommand -ActivityName "Create lab OU" -ComputerName svr-lab-dc01 -ScriptBlock { 
    if ($null -eq (Get-ADOrganizationalUnit -Filter "Name -eq 'lab'")) {
        New-ADOrganizationalUnit -Name 'lab' -Path 'DC=lab,DC=local' -ErrorAction SilentlyContinue 
    }
}
Invoke-LabCommand -ActivityName "Create svc-ims user" -ComputerName svr-lab-dc01 -ScriptBlock { 
    if (-not (Get-AdUser -Filter "SamAccountName -eq 'svc-ims'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name 'svc-ims' -AccountPassword (ConvertTo-SecureString $DefaultPass -AsPlainText -Force) -Enabled $true -Path 'OU=lab,DC=lab,DC=local' 
    }
} -Variable (Get-Variable -Name DefaultPass)
#endregion

#region svr-lab-wac01
$cert = Get-LabCertificate -Computer svr-lab-wac01 -SearchString svr-lab-wac01 -FindType FindBySubjectName -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My -ErrorAction SilentlyContinue
if ($null -eq $cert) {
    $cert = Request-LabCertificate -Subject 'CN=svr-lab-psu01' -SAN 'svr-lab-psu01.lab.local' -TemplateName WebServer -ComputerName svr-lab-psu01
}

#Install-LabWindowsFeature -FeatureName RSAT -ComputerName svr-lab-wac01 -IncludeAllSubFeature -IncludeManagementTools
#Wait-LabVMRestart -ComputerName 'svr-lab-wac01'
Get-LabInternetFile -Uri https://aka.ms/wacdownload -Path C:\LabSources\SoftwarePackages\ -FileName wacinstall.msi -Verbose -force
# Setup Windows Admin Center

$InstallArgs = @("/qn", "/l*v", "C:\temp\wac_install.log", "SME_PORT=6516")
if ($ThumbPrint) {
    $InstallArgs += "SME_THUMBPRINT=$($cert.Thumbprint)"
    $InstallArgs += "SSL_CERTIFICATE_OPTION=installed"
} else {
    $InstallArgs += "SSL_CERTIFICATE_OPTION=generate"
}
Install-LabSoftwarePackage -Path $labSources\SoftwarePackages\wacinstall.msi -CommandLine ($InstallArgs -join ' ') -ComputerName svr-lab-wac01
#endregion

$LabVMs | Where-Object { $_ -like '*psu0*' } | ForEach-Object {
    Install-LabWindowsFeature -ComputerName $_ -FeatureName RSAT-AD-PowerShell
}


# #region svr-lab-psu01
# Request-LabCertificate -Subject 'CN=svr-lab-wac01' -SAN 'svr-lab-wac01.lab.local' -TemplateName WebServer -ComputerName svr-lab-wac01
# Install-LabWindowsFeature -FeatureName RSAT -ComputerName svr-lab-psu01 -IncludeAllSubFeature -IncludeManagementTools
# # Setup PowerShellUniversal
# $ThumbPrint = $null
# $ThumbPrint = Invoke-LabCommand -ComputerName svr-lab-psu01 -ScriptBlock { Get-ChildItem cert:\localmachine\my | Select-Object -ExpandProperty Thumbprint } -PassThru
# Invoke-LabCommand -ActivityName "Create D:\UniveralAutomation" -ComputerName svr-lab-psu01 -ScriptBlock { New-Item -ItemType Directory -Path D:\UniversalAutomation -force }
# $InstallArgs = @(
#     "/qn", 
#     "/l*v", 
#     "C:\temp\psu_install.log",
#     "REPOFOLDER=D:\UniversalAutomation\Repository",
#     'CONNECTIONSTRING="Data Source=D:\UniversalAutomation\database.db"'
# )
# Install-LabSoftwarePackage -Path $labSources\SoftwarePackages\PowerShellUniversalServer.4.3.4.msi -CommandLine ($InstallArgs -join ' ') -ComputerName svr-lab-psu01
# #endregion

Add-LabWacManagedNode
Show-LabDeploymentSummary -Detailed