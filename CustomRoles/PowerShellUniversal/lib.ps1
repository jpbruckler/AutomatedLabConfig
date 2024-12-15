function Get-PSUInstallerInfo {
    param(
        [int]$MajorVersion = 4
    )

    begin {}

    process {
        $VersionUrl = 'https://imsreleases.blob.core.windows.net/universal/production/v{0}-version.txt' -f $MajorVersion

        try {
            $LatestVersion = (Invoke-WebRequest $VersionUrl -UseBasicParsing -ErrorAction Stop).Content
            $MsiFileName = "PowerShellUniversal.$LatestVersion.msi"
            $InstallerUrl = "https://imsreleases.blob.core.windows.net/universal/production/$LatestVersion/$MsiFileName"
            $InstallerInfo = @{
                Version     = $LatestVersion
                FileName    = $MsiFileName
                DownloadUrl = $InstallerUrl
            }
            return $InstallerInfo
        }
        catch {
            Write-Error "Failed to get installer info. $_"
        }
    }
}

function Set-PSUServiceAccountPrivilege {
    param(
        [string]$ServiceAccountName,
        [string]$ComputerName
    )

    begin {}

    process {
        Write-ScreenInfo -Message "Granting privileges for identity $ServiceAccountName on $ComputerName." -TaskStart

        Invoke-LabCommand -ComputerName $ComputerName -ScriptBlock {
            $Privileges = @(
                'SeServiceLogonRight',
                'SeBatchLogonRight',
                'SeInteractiveLogonRight',
                'SeAssignPrimaryTokenPrivilege',
                'SeIncreaseQuotaPrivilege'
            )

            foreach ($Privilege in $Privileges) { 
                Grant-CPrivilege -Identity $ServiceAccountName -Privilege $Privilege
            }
        } -Variable (Get-Variable ServiceAccountName)

        Write-ScreenInfo -Message "Finished granting privileges for identity $ServiceAccountName." -TaskEnd
    }
}

function Assert-PSUFilePermission {
    param(
        [string]$ServiceAccountName,
        [string]$ComputerName
    )
    
    Write-ScreenInfo -Message "Asserting file permissions for identity $ServiceAccountName on $ComputerName." -TaskStart

    $appSettings = Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Get App Settings' -ScriptBlock {
        $appSettings = Get-Content -Path (Join-Path $env:ProgramData 'PowerShellUniversal\appsettings.json') -Raw
        $appSettings | ConvertFrom-Json
    } -PassThru

    $RepositoryPath = $appSettings.Data.RepositoryPath
    $asrtRepoPermission = Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Get Repository Permissions' -ScriptBlock {
        $acl = Get-Acl -Path $RepositoryPath

        $hasFullControl = $false

        # Check for the specific permissions
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference -eq $Identity -and 
                $rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
                $rule.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None -and
                $rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit -and
                $rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        
                $hasFullControl = $true
                break
            }
        }

        $hasFullControl
    } -Variable (Get-Variable RepositoryPath) -PassThru

    if ($asrtRepoPermission -eq $false) {
        Write-ScreenInfo -Message "Setting file permissions for $RepositoryPath." -TaskStart
        Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Set Repository Permissions' -ScriptBlock {
            $repoAclRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ServiceAccountName,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl = Get-Acl -Path $RepositoryPath
            $acl.AddAccessRule($repoAclRule)
            Set-Acl -Path $RepositoryPath -AclObject $acl
        } -Variable (Get-Variable RepositoryPath)
        Write-ScreenInfo -Message "Finished setting file permissions for $RepositoryPath." -TaskEnd
    }

    $asrtPrgDataPermissions = Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Get ProgramData Permissions' -ScriptBlock {
        $acl = Get-Acl -Path (Join-Path $env:ProgramData 'PowerShellUniversal')

        $hasFullControl = $false

        # Check for the specific permissions
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference -eq $Identity -and 
                $rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
                $rule.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None -and
                $rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit -and
                $rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
        
                $hasFullControl = $true
                break
            }
        }

        $hasFullControl
    } -PassThru

    if ($asrtPrgDataPermissions -eq $false) {
        Write-ScreenInfo -Message "Setting file permissions for $($env:ProgramData)\PowerShellUniversal." -TaskStart
        Invoke-LabCommand -ComputerName $ComputerName -ActivityName 'Set ProgramData Permissions' -ScriptBlock {
            $prgDataAclRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ServiceAccountName,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl = Get-Acl -Path (Join-Path $env:ProgramData 'PowerShellUniversal')
            $acl.AddAccessRule($prgDataAclRule)
            Set-Acl -Path (Join-Path $env:ProgramData 'PowerShellUniversal') -AclObject $acl
        }
        Write-ScreenInfo -Message "Finished setting file permissions for $($env:ProgramData)\PowerShellUniversal." -TaskEnd
    } 

    Write-ScreenInfo -Message "Finished asserting file permissions for identity $ServiceAccountName on $ComputerName." -TaskEnd
}

function Assert-PSUCertificatePermission {
    param(
        [string]$ServiceAccountName
    )

    
    $Cert = Get-ChildItem cert:\localmachine\my | Where-Object { $_.Subject -eq "CN=$($env:ComputerName)" }
        
    if (-not $Cert) {
        Write-Error "Certificate with subject 'CN=$($env:ComputerName)' not found in LocalMachine\My store."
        return
    }
        
    # Get the private key file path
    $KeyPath = $Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $KeyPathFull = Join-Path -Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" -ChildPath $KeyPath
        
    if (-not (Test-Path -Path $KeyPathFull)) {
        Write-Error "Private key file not found at $KeyPathFull."
        return
    }
        
        
    # Get the current ACL for the private key
    $acl = Get-Acl -Path $KeyPathFull
        
    # Check if the identity already has permissions
    $existingRule = $acl.Access | Where-Object {
        $_.IdentityReference -eq $ServiceAccountName -and
        $_.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl
    }
        
    if ($existingRule) {
        Write-Host "The identity $ServiceAccountName already has FullControl permissions on the private key." -ForegroundColor Green
    }
    else {
        Write-Host "Updating permissions for $ServiceAccountName on the private key..."
        
        # Create a new access rule
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        # Add the new rule to the ACL
        $acl.AddAccessRule($newRule)
        
        # Apply the updated ACL
        Set-Acl -Path $KeyPathFull -AclObject $acl
        
        Write-Host "Permissions updated: $ServiceAccountName now has FullControl on the private key." -ForegroundColor Green
    }
}

function Assert-PSUServiceAccountPrivilege {
    param(
        [string]$ServiceAccountName
    )

    $Privileges = @(
        'SeServiceLogonRight',
        'SeBatchLogonRight',
        'SeInteractiveLogonRight',
        'SeAssignPrimaryTokenPrivilege',
        'SeIncreaseQuotaPrivilege'
    )

    Import-Module C:\Carbon\*\Carbon.psd1 -Force

    foreach ($Privilege in $Privileges) { 
        Grant-CPrivilege -Identity $ServiceAccountName -Privilege $Privilege
    }

    Add-CGroupMember -Name 'Performance Log Users' -Member $ServiceAccountName
    Add-CGroupMember -Name 'Performance Monitor Users' -Member $ServiceAccountName
}
