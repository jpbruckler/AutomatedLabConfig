$labName = 'SingleMachine'

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $labName -AddressSpace 172.17.100.0/24

Set-LabInstallationCredential -Username Install -Password Somepass1

#Our one and only machine with nothing on it
Add-LabMachineDefinition -Name TestClient1 -Memory 1GB -Network $labName -IpAddress 172.17.100.12 `
    -OperatingSystem 'Windows 11 Enterprise Evaluation'

Install-Lab

Show-LabDeploymentSummary -Detailed