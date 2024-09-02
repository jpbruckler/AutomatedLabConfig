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
Add-LabDiskDefinition -Name psu_datadisk -DiskSizeInGb 100 -Label Apps -DriveLetter D -AllocationUnitSize 64kb
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
        #Roles           = Get-LabMachineRoleDefinition -Role WindowsAdminCenter -Properties @{ 
        #    Port = '6516';
        #    UseSsl = 'generated' 
        #}
        OperatingSystem = 'Windows Server 2022 Datacenter (Desktop Experience)'
    },
    @{
        Name            = 'svr-lab-psu01'
        IpAddress       = '172.17.112.101'
        Memory          = 4gb
        MaxMemory       = 8gb
        Processors      = 4
        DiskName        = 'psu_datadisk'
    },
    @{
        Name            = 'svr-lab-psu02'
        IpAddress       = '172.17.112.102'
        Memory          = 2gb
        MaxMemory       = 4gb
        Processors      = 2
        DiskName        = 'psu_datadisk1'
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
Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning 

Invoke-LabCommand -ActivityName 'Publish WebServer Certificate' -ComputerName svr-lab-rootca -ScriptBlock {
    Publish-CaTemplate -TemplateName 'WebServer'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:GR'
    dsacls "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainName" /G 'Domain Users:CA;Enroll'
}

Install-Lab -StartRemainingMachines

Enable-LabVMRemoting -All

# Install Software on all machines
$LabVMs = Get-LabVM | Select-Object -ExpandProperty Name | Where-Object { $_ -notlike 'rtr*' }
$LabVMs | ForEach-Object { 
    # Create log directory
    Invoke-LabCommand -ActivityName "Create C:\Temp" -ComputerName $_ -ScriptBlock { New-Item -ItemType Directory -Path C:\Temp -force }
    Invoke-LabCommand -ActivityName "Trust PSGallery" -ComputerName $_ -ScriptBlock { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
    Invoke-LabCommand -ActivityName "Install Modules" -ComputerName $_ -ScriptBlock { Install-Module carbon -Force }

    # Install Chocolatey
    $sb = { 
        Set-ExecutionPolicy Bypass -Scope Process -Force; 
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    Invoke-LabCommand -ActivityName "Install Chocolatey" -ComputerName $_ -ScriptBlock $sb

    # Install chocolatey packages
    $packageNames = @(
        'powershell-core',
        '7zip',
        'vscode'
    )
    foreach ($package in $packageNames) { 
        Invoke-LabCommand -ActivityName "Install $package" -ComputerName $_ -ScriptBlock { Start-Process 'C:\ProgramData\chocolatey\choco.exe' -ArgumentList "install $package -y" }
    }
} 

# Specific Machines
#region svr-lab-dc01
Invoke-LabCommand -ActivityName "Create lab OU" -ComputerName svr-lab-dc01 -ScriptBlock { New-ADOrganizationalUnit -Name 'lab' -Path 'DC=lab,DC=local' }
Invoke-LabCommand -ActivityName "Create svc-ims user" -ComputerName svr-lab-dc01 -ScriptBlock { New-ADUser -Name 'svc-ims' -AccountPassword (ConvertTo-SecureString $DefaultPass -AsPlainText -Force) -Enabled $true -Path 'OU=lab,DC=lab,DC=local' }


#region svr-lab-wac01
$cert = Get-LabCertificate -Computer svr-lab-wac01 -SearchString svr-lab-wac01 -FindType FindBySubjectName -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My
if ($null -eq $cert) {
    Request-LabCertificate -Subject 'CN=svr-lab-psu01' -SAN 'svr-lab-psu01.lab.local' -TemplateName WebServer -ComputerName svr-lab-psu01
}
else {
    # Set to null for next computer
    $cert = $null
}
Install-LabWindowsFeature -FeatureName RSAT -ComputerName svr-lab-wac01 -IncludeAllSubFeature -IncludeManagementTools
# Setup Windows Admin Center
$ThumbPrint = Invoke-LabCommand -ComputerName svr-lab-wac01 -ScriptBlock { Get-ChildItem cert:\localmachine\my | Select-Object -ExpandProperty Thumbprint } -PassThru
$InstallArgs = @("/qn", "/l*v", "C:\temp\wac_install.log", "SME_PORT=6516")
if ($ThumbPrint) {
    $InstallArgs += "SME_THUMBPRINT=$ThumbPrint"
    $InstallArgs += "SSL_CERTIFICATE_OPTION=installed"
} else {
    $InstallArgs += "SSL_CERTIFICATE_OPTION=generate"
}
Install-LabSoftwarePackage -Path $labSources\SoftwarePackages\wacinstall.msi -CommandLine ($InstallArgs -join ' ') -ComputerName svr-lab-wac01
#endregion


#region svr-lab-psu01
$cert = Get-LabCertificate -Computer svr-lab-wac01 -SearchString svr-lab-wac01 -FindType FindBySubjectName -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My
if ($null -eq $cert) {
    Request-LabCertificate -Subject 'CN=svr-lab-wac01' -SAN 'svr-lab-wac01.lab.local' -TemplateName WebServer -ComputerName svr-lab-wac01
}
else {
    # Set to null for next computer
    $cert = $null
}
Install-LabWindowsFeature -FeatureName RSAT -ComputerName svr-lab-psu01 -IncludeAllSubFeature -IncludeManagementTools
# Setup PowerShellUniversal 4
$ThumbPrint = $null
$ThumbPrint = Invoke-LabCommand -ComputerName svr-lab-psu01 -ScriptBlock { Get-ChildItem cert:\localmachine\my | Select-Object -ExpandProperty Thumbprint } -PassThru
 svr-lab-psu01
#endregion

#region PowerShellUniversal Servers
$vms = Get-LabVM | Where-Object { $_.Name -like 'svr-lab-psu0*' }
foreach ($vm in $vms) {
    $svc = Invoke-LabCommand -ActivityName 'Check PowerShell Universal Service' -ComputerName $vm.Name -ScriptBlock { Get-Service -Name 'PowerShellUniversal' } -PassThru
    if ($svc) {
        continue
    }
    # Privelges needed by the service account
    $Privileges = @(
        'SeServiceLogonRight', 
        'SeIncreaseWorkingSetPrivilege', 
        'SeAssignPrimaryTokenPrivilege'
    )

    foreach ($Privilege in $Privileges) {
        Invoke-LabCommand -ActivityName "Add $Privilege" -ComputerName $($vm.Name) -ScriptBlock { 
            Grant-CPrivilege -Identity 'lab\svc-ims' -Privilege $Using:Privilege
        }
    }

    $Cert = Get-LabCertificate -ComputerName svr-lab-psu02 -FindType FindByTemplateName -SearchString WebServer -Location CERT_SYSTEM_STORE_LOCAL_MACHINE -Store My
    if ($null -eq $Cert) {
        $Cert = Request-LabCertificate -Subject "CN=$($vm.Name)" -SAN "$($vm.Name).lab.local" -TemplateName WebServer -ComputerName $vm.Name -PassThru
    }
    else {
        # Set to null for next computer
        $Cert = $null
    }

    Invoke-LabCommand -ActivityName 'Grant service account permissions to SSL certificate' -ComputerName $vm.Name -ScriptBlock { 
        $Cert = Get-ChildItem cert:\localmachine\my | Where-Object { $_.Subject -eq "CN=$($Using:vm.Name)" }
        $path = "cert:\{0}" -f ($Cert.PSPath.split('::',2)[1])
        Grant-CPermission -Identity 'lab\svc-ims' -Permission Read -Path $path -Type Allow
        Add-CGroupMember -Name 'Performance Log Users' -Member lab\svc-ims
        Add-CGroupMember -Name 'Performance Monitor Users' -Member lab\svc-ims
    }

    # Install PowerShellUniversal
    Invoke-LabCommand -ActivityName "Create D:\UniveralAutomation" -ComputerName svr-lab-psu01 -ScriptBlock { New-Item -ItemType Directory -Path D:\UniversalAutomation -force }
    $InstallArgs = @(
        "/qn", 
        "/l*v", 
        "C:\temp\psu_install.log",
        "REPOFOLDER=D:\UniversalAutomation\Repository",
        'CONNECTIONSTRING="Data Source=D:\UniversalAutomation\database.db"'
    )
    # psu01 is v4, psu02 is v5
    $packagePath = if ($vm.Name -eq 'svr-lab-psu01') {
            Join-Path $labSources 'SoftwarePackages\PowerShellUniversalServer.4.3.4.msi'
        }
        else {
            Join-Path $labSources 'SoftwarePackages\PowerShellUniversal.5.0.4.msi'
        }
    Install-LabSoftwarePackage -Path $packagePath -CommandLine ($InstallArgs -join ' ') -ComputerName $vm.Name

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
    $content = $appSettings -replace '{{servername}}', $vm.Name
    Invoke-LabCommand -ActivityName "Create PowerShell Universal appsettings.json" -ComputerName $vm.Name -ScriptBlock { 
        $Using:content | Out-File -FilePath 'C:\ProgramData\PowerShellUniversal\appsettings.json' -Force
    }

    $Cred = [PSCredential]::new('lab\svc-ims', (ConvertTo-SecureString $DefaultPass -AsPlainText -Force))
    Invoke-LabCommand -ActivityName 'Set Service Account' -ComputerName $vm.Name -ScriptBlock { 
        Set-Service -Name 'UniversalAutomation' -StartupType 'Automatic' -Credential $Using:Cred
    }

    Invoke-LabCommand -ActivityName "Start PowerShell Universal" -ComputerName $vm.Name -ScriptBlock { 
        Start-Service -Name 'UniversalAutomation'
    }

    Invoke-LabCommand -ActivityName 'Create Modules Share' -ComputerName $vm.Name -ScriptBlock { 
        if (-not (Test-Path 'D:\UniversalAutomation\Repository\Modules')) {
            New-Item -ItemType Directory -Path 'D:\UniversalAutomation\Repository\Modules' -Force
        }
        New-SMBShare -Name 'Modules' -Path 'D:\UniversalAutomation\Repository\Modules' -FullAccess Administrators
    }
}

#endregion


Show-LabDeploymentSummary -Detailed