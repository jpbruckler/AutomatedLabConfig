<#
example.local
├─ Users
│  ├─ HR
│  ├─ Finance
│  ├─ IT
│  ├─ Sales
│  └─ Contractors
├─ Computers
│  ├─ Workstations
│  │  ├─ HQ
│  │  └─ BranchOffices
│  └─ Servers
│     ├─ Production
│     └─ Development
├─ Groups
│  ├─ Security
│  ├─ Distribution
│  └─ Dynamic
└─ ServiceAccounts
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    <#Category#>'PSAvoidUsingConvertToSecureStringWithPlainText',
    <#CheckId#>"",
    Justification = 'Random password generation'
)]
param(
    [string] $EmailDomain
)

$InformationPreference = 'Continue'

#region Functions

# Test whether an OU already exists
Function Test-OUPath {
    param([string]$path)

    $OUExists = [adsi]::Exists("LDAP://$path")

    return $OUExists
}

# Random password generator
Function Get-TempPassword {
    Param(
        [int]$length = 16
    )

    $sourcedata = For ($a = 33; $a -le 126; $a++) {
        [char][byte]$a
    }

    For ($loop = 1; $loop -le $length; $loop++) {
        $TempPassword += ($sourcedata | Get-Random)
    }

    return ($TempPassword | ConvertTo-SecureString -AsPlainText -Force)
}
#endregion


#region Script data
$NameList = [System.Collections.Generic.List[string]]@()
Get-Content .\nameList.txt | Select-Object -Skip 1 | ForEach-Object {
    $null = $NameList.Add($_)
}
$ShuffledNameList = $NameList | Sort-Object { [Guid]::NewGuid() }
$DepartmentList = Get-Content .\departmentList.json -Raw | ConvertFrom-Json
$OfficeList = Import-Csv .\officeList.csv
$DomainInfo = Get-ADDomain
$domainDN = $DomainInfo.DistinguishedName

if ([string]::IsNullOrEmpty($EmailDomain)) {
    $EmailDomain = $DomainInfo.DnsRoot
}

$LabRootOU = "OU=$($DomainInfo.DNSRoot),$domainDN"
$SubOUs = @(
    'Users',
    'ServiceAccounts',
    'Computers',
    'Groups'
)

$ComputerOUs = @(
    'Workstations',
    'Servers'
)

$GroupOUs = @(
    'Security',
    'Distribution',
    'Dynamic'
)
#endregion

#region Create Lab OU structure
# Create Root OU
if (-not (Test-OUPath $LabRootOU)) {
    Write-Information 'Creating Lab OU structure...'
    try {
        New-ADOrganizationalUnit -Name 'Lab' -Path $domainDN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
    }
    catch {
        # rethrow for AutomatedLab to catch
        Write-Information 'Error creating Root Lab OU structure. Exiting.' -ForegroundColor Red
        throw 'Error creating Root Lab OU structure. Exiting.'
    }
}

# Create Sub OUs
foreach ($ou in $SubOUs) {
    $ouPath = "OU=$ou,$LabRootOU"
    if (-not (Test-OUPath $ouPath)) {
        try {
            Write-Information "`tCreating OU: $ou"
            New-ADOrganizationalUnit -Name $ou -Path $LabRootOU -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }
        catch {
            # rethrow for AutomatedLab to catch
            Write-Information "Error creating Sub OU '$ou'. Exiting." -ForegroundColor Red
            throw "Error creating Sub OU '$ou'. Exiting."
        }
    }
}

# Create User OUs
$DepartmentList.Departments | ForEach-Object {
    $ouName = $_.Name
    $ouPath = "OU=Users,$LabRootOU"
    if (-not (Test-OUPath "OU=$ouName,$ouPath")) {
        try {
            Write-Information "`tCreating OU: $ouName"
            New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not create OU: $ouName. Skipping."
        }
    }
}

# Create Computer OUs
$ComputerOUs | ForEach-Object {
    $ouName = $_
    $ouPath = "OU=Computers,$LabRootOU"
    if (-not (Test-OUPath "OU=$ouName,$ouPath")) {
        try {
            Write-Information "`tCreating OU: $ouName"
            New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not create OU: $ouName. Skipping."
        }
    }
}

# Create Group OUs
$GroupOUs | ForEach-Object {
    $ouName = $_
    $ouPath = "OU=Groups,$LabRootOU"
    if (-not (Test-OUPath "OU=$ouName,$ouPath")) {
        try {
            Write-Information "`tCreating OU: $ouName"
            New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not create OU: $ouName. Skipping."
        }
    }
}
#endregion

#region Create Users
# create the CEO
$user = $ShuffledNameList[0]
$office = $OfficeList | Get-Random
$employeeNumber = '000000'
$samAccountName = '{0}{1}' -f $user.Split(' ')[1].substring(0, 1).ToLower(), $employeeNumber
$userAccount = @{
    Name              = $samAccountName
    SamAccountName    = $samAccountName
    UserPrincipalName = ("$($user.Replace(' ', '.'))@$EmailDomain").toLower()
    Department        = $deptName
    GivenName         = $user.Split(' ')[0]
    Surname           = $user.Split(' ')[1]
    DisplayName       = $user
    EmailAddress      = "$($user.Replace(' ', '.'))@$EmailDomain"
    Title             = $title.Title
    OfficePhone       = "555-555-$($employeeNumber.substring(1,4))"
    PostalCode        = $office.ZIP
    City              = $office.City
    State             = $office.State
    StreetAddress     = $office.StreetAddress
    Office            = $office.BranchOffice
    Path              = $ouPath
    Enabled           = $true
    AccountPassword   = Get-TempPassword -sourcedata $ascii
}
New-ADUser @userAccount -ErrorAction Stop

$totalUsers = 0
$DepartmentList.Departments.titles | ForEach-Object { $totalUsers = $totalUsers + $_.count }
$currentIndex = 1

Write-Information 'Creating users...'
foreach ($dept in $DepartmentList.Departments) {
    $deptName = $dept.FullName
    $ouName = $dept.Name
    $ouPath = "OU=$ouName,OU=Users,$LabRootOU"

    foreach ($title in $dept.titles) {
        # get COUNT random names from the list
        $chosenNames = $ShuffledNameList[$currentIndex..($currentIndex + $title.count - 1)]
        $currentIndex += $title.count

        foreach ($user in $chosenNames) {
            # Progress bar
            $percent = [int](($userCounter / $totalUsers) * 100)
            Write-Progress -Activity "Creating Users in $deptName" -Status "Title: $($title.Title) — Creating user $($userCounter + 1) of $totalUsers" -PercentComplete $percent

            # User attributes
            $idx = $ShuffledNameList.IndexOf($user)
            $employeeNumber = '{0:000000.##}' -f $idx
            $office = $OfficeList | Get-Random
            $samAccountName = '{0}{1}' -f $user.Split(' ')[1].substring(0, 1).ToLower(), $employeeNumber

            $userAccount = @{
                Name              = $samAccountName
                SamAccountName    = $samAccountName
                UserPrincipalName = ("$($user.Replace(' ', '.'))@$EmailDomain").toLower()
                Department        = $deptName
                GivenName         = $user.Split(' ')[0]
                Surname           = $user.Split(' ')[1]
                DisplayName       = $user
                EmailAddress      = "$($user.Replace(' ', '.'))@$EmailDomain"
                Title             = $title.Title
                OfficePhone       = "555-555-$($employeeNumber.substring(1,4))"
                PostalCode        = $office.ZIP
                City              = $office.City
                State             = $office.State
                StreetAddress     = $office.StreetAddress
                Office            = $office.BranchOffice
                Path              = $ouPath
                Enabled           = $true
                AccountPassword   = Get-TempPassword -sourcedata $ascii
            }

            try {
                New-ADUser @userAccount -ErrorAction Stop
            }
            catch {
                Write-Warning "Error creating user $($userAccount.Name) ($($_.Exception.Message))"
            }

            $userCounter++
            $currentIndex++
        }

    }
}
Write-Progress -Activity 'Creating Users' -Status 'User Creation complete.' -PercentComplete 100


# Create User Hierarchies
$managers = $DepartmentList.Departments.titles | Where-Object { $_.DirectReports }
foreach ($manager in $managers) {
    Write-Information "Assigning direct reports to $($manager.Title)..."
    if ($manager.count -eq 1) {
        $managerDN = Get-ADUser -Filter "Title -eq '$($manager.Title)'" | Select-Object -ExpandProperty DistinguishedName
        foreach ($drt in $manager.DirectReports) {
            $filter = 'Title -eq "{0}"' -f $drt
            $drs = Get-ADUser -Filter $filter
            $drs | ForEach-Object {
                Set-ADUser -Identity $_.DistinguishedName -Manager $managerDN
            }
        }
    }
    else {
        # MULTIPLE managers => round-robin
        $mgrCount = $managerUsers.Count
        $i = 0

        foreach ($drUser in $drList) {
            $assignedManagerDN = $managerUsers[$i % $mgrCount].DistinguishedName
            Set-ADUser -Identity $drUser.DistinguishedName -Manager $assignedManagerDN
            $i++
        }
    }
}