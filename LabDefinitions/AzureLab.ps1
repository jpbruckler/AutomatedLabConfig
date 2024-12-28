$labName = 'AzurePSU'
$azureDefaultLocation = 'Central US'

New-LabDefinition -Name $labName -DefaultVirtualizationEngine Azure
Add-LabAzureSubscription -DefaultLocationName $azureDefaultLocation

Add-LabVirtualNetworkDefinition -Name azpsu-lab-net -AddressSpace 192.168.41.0/24 -AzureProperties @{ 
    DnsServers = '192.168.41.10'; 
    LocationName = $azureDefaultLocation 
}

Add-LabDomainDefinition -Name lab.local -AdminUser Install -AdminPassword 'L4bP@ssw0rd'


$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:OperatingSystem'= 'Windows Server 2022 Datacenter'
    'Add-LabMachineDefinition:Memory' = 512MB
}

Set-LabInstallationCredential -Username Install -Password 'L4bP@ssw0rd'
$roles = Get-LabMachineRoleDefinition -Role RootDC
$postInstallActivity = Get-LabPostInstallationActivity -ScriptFileName PrepareRootDomain.ps1 -DependencyFolder $labSources\PostInstallationActivities\PrepareRootDomain
Add-LabMachineDefinition -Name tst-lab-dc -IpAddress 192.168.41.10 -Network azpsu-lab-net -DomainName lab.local -Roles $roles -PostInstallationActivity $postInstallActivity

Install-Lab
Show-LabDeploymentSummary -Detailed