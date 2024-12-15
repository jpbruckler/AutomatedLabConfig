param(
    [Parameter(Mandatory = $true)]
    [string] $ComputerName
)

if (-not (Test-Path $labSources\SoftwarePackages\install-docker-ce.ps1)) {
    Write-ScreenInfo -Message 'Downloading Docker CE installation script...'
    Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1' -o $labSources\SoftwarePackages\install-docker-ce.ps1
}

Write-ScreenInfo -Message 'Copying Docker CE installation script to target machine...'
Copy-LabFileItem -Path $labSources\SoftwarePackages\install-docker-ce.ps1 -Destination C:\ -ComputerName $ComputerName

Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Install Docker' -ScriptBlock {
    if (-not (Get-Service docker -ErrorAction SilentlyContinue)) {
        C:\install-docker-ce.ps1
    }
}

Write-ScreenInfo -Message 'Restarting target machine...'
Restart-LabVM -ComputerName $ComputerName -Wait

Write-ScreenInfo -Message 'Configuring Docker on target machine...'
Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Configure Docker' -ScriptBlock {
    $DockerDrive = Get-CimInstance win32_logicaldisk -Filter 'DriveType=3' | 
        Sort-Object -Property FreeSpace -Descending |
        Select-Object -First 1
    $DaemonCfgPath = Join-Path $env:ProgramData 'Docker\config\daemon.json'
    
    # Create the Docker configuration directory if it doesn't exist, then write
    # the configuration file to it.
    if (-not (Test-Path $DaemonCfgPath)) {
        New-Item -Path (Split-Path $DaemonCfgPath) -ItemType Directory -Force

        $DaemonCfg = @{
            'data-root' = (Join-Path $DockerDrive.DeviceID 'ProgramData\Docker')
            'group'     = 'docker'
        }
        $DaemonCfg | ConvertTo-Json | Set-Content -Path $DaemonCfgPath -Force
    }
    else {
        $DaemonCfg = Get-Content -Path $DaemonCfgPath | ConvertFrom-Json
    }
    
    if ($DaemonCfg.ContainsKey('data-root') -and (-not (Test-Path $DaemonCfg['data-root'])) ) {
        New-Item -Path $DaemonCfg['data-root'] -ItemType Directory -Force
        Grant-CPermission -Path $DaemonCfg['data-root'] -Identity 'docker' -Permission 'FullControl' -Type Allow
    }
    
    New-Item -Path (Join-Path $DockerDrive.DeviceID 'containers') -ItemType Directory -Force
    
    Restart-Service -Name docker -ErrorAction SilentlyContinue
}

Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Install Microsoft Docker Provider' -ScriptBlock {
    Install-Module -Name DockerMsftProvider -Force -Confirm:$false
    Install-Package -Name docker -Force -Confirm:$false
}



Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Hello World' -ScriptBlock { docker run hello-world } -PassThru