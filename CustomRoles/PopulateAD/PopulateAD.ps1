<#
.SYNOPSIS
    This script creates a lab Active Directory structure with users, computers, and groups.
.DESCRIPTION
    This script:
        - creates a lab Active Directory structure with users, computers, and groups.
        - creates a root OU based on the AD Domain's DNS Root in the domain root.
            DNSRoot
                ├─ Users
                │  ├─ < Department >...
                ├─ Computers
                │  ├─ Workstations
                │  └─ Servers
                ├─ Groups
                │  ├─ Security
                │  ├─ Distribution
                │  └─ Dynamic
                └─ ServiceAccounts
        - creates ~1000 user accounts from a shuffled list of names in namelist.txt.
            - Each user is assigned a department and title.
            - Each user is assigned a random office location from officeList.csv.
            - Each user is assigned a phone number based on the employee number.
            - Each user is assigned a manager based on the department and title.
        - creates a number of groups in the Groups OU.
            - Security, Distribution, and Dynamic groups.

#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    <#Category#>'PSAvoidUsingConvertToSecureStringWithPlainText',
    <#CheckId#>'',
    Justification = 'Random password generation'
)]
param(
    [string] $EmailDomain
)

$InformationPreference = 'Continue'


#region Script data
if (-not (Test-Path (Join-Path $PSScriptRoot 'nameList.txt'))) {
    throw 'nameList.txt not found.'
}

if (-not (Test-Path (Join-Path $PSScriptRoot 'departmentList.json'))) {
    throw 'departmentList.json not found.'
}

if (-not (Test-Path (Join-Path $PSScriptRoot 'officeList.csv'))) {
    throw 'officeList.csv not found.'
}

$NameList = [System.Collections.Generic.List[string]]@()
Get-Content (Join-Path $PSScriptRoot 'nameList.txt') | Select-Object -Skip 1 | ForEach-Object {
    $null = $NameList.Add($_)
}
$ShuffledNameList = $NameList | Sort-Object { [Guid]::NewGuid() }
$DepartmentList = Get-Content (Join-Path $PSScriptRoot 'departmentList.json') -Raw | ConvertFrom-Json
$OfficeList = Import-Csv (Join-Path $PSScriptRoot 'officeList.csv')
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


#region Functions

# Test whether an OU already exists
Function Test-ADSIPath {
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



#region Create Lab OU structure
# Create Root OU
Write-Information 'Creating Lab OU structure...'
if (-not (Test-ADSIPath $LabRootOU)) {
    Write-Information "Creating Root Lab OU '$LabRootOU'"
    try {
        New-ADOrganizationalUnit -Name "$($DomainInfo.DNSRoot)" -Path $domainDN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
    }
    catch {
        # rethrow for AutomatedLab to catch
        Write-Information 'Error creating Root Lab OU structure. Exiting.'
        throw 'Error creating Root Lab OU structure. Exiting.'
    }
}

# Create Sub OUs
foreach ($ou in $SubOUs) {
    $ouPath = "OU=$ou,$LabRootOU"
    if (-not (Test-ADSIPath $ouPath)) {
        try {
            Write-Information "`tCreating OU: $ou"
            New-ADOrganizationalUnit -Name $ou -Path $LabRootOU -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        }
        catch {
            # rethrow for AutomatedLab to catch
            Write-Information "Error creating Sub OU '$ou'. Exiting."
            throw "Error creating Sub OU '$ou'. Exiting."
        }
    }
}

# Create User OUs
$DepartmentList.Departments | ForEach-Object {
    $ouName = $_.Name
    $ouPath = "OU=Users,$LabRootOU"
    if (-not (Test-ADSIPath "OU=$ouName,$ouPath")) {
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
    if (-not (Test-ADSIPath "OU=$ouName,$ouPath")) {
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
    if (-not (Test-ADSIPath "OU=$ouName,$ouPath")) {
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
# Create a samAccountName based on the first letter of the last name and the employee number
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
# Create the CEO
# nested try-catch to avoid the script from stopping if the user already exists
# and to prevent Get-ADUser puking output to the console
try {
    Get-ADUser -Identity $samAccountName -ErrorAction Stop | Out-Null
}
catch {
    try {
        New-ADUser @userAccount -ErrorAction Stop
    }
    catch {
        Write-Warning "Error creating user $($userAccount.Name) ($($_.Exception.Message))"
    }
}

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
            Write-Progress -Activity 'Creating Users' -Status "Title: $($title.Title)" -PercentComplete $percent

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

            # nested try-catch to avoid the script from stopping if the user already exists
            # and to prevent Get-ADUser puking output to the console
            try {
                Get-ADUser -Identity $samAccountName -ErrorAction Stop | Out-Null
            }
            catch {
                try {
                    New-ADUser @userAccount -ErrorAction Stop
                }
                catch {
                    Write-Warning "User $samAccountName already exists. Skipping."
                }
            }

            $userCounter++
            $currentIndex++
        }

    }
}
Write-Progress -Activity 'Creating Users' -Status 'User Creation complete.' -PercentComplete 100 -Completed
#endregion

#region Create User Hierarchies

function Add-DirectReport {
    param(
        [string]$Title,
        [string[]]$SubordinateTitles
    )

    $manager = Get-ADUser -Filter "Title -eq '$Title'"
    $managerCount = ($manager | Measure-Object).Count

    $subordinates = @()

    foreach ($sub in $SubordinateTitles) {
        $subordinates += Get-ADUser -Filter "Title -eq '$sub'"
    }

    if ($managerCount -eq 1) {
        $managerDN = $manager.DistinguishedName
        foreach ($sub in $subordinates) {
            Set-ADUser -Identity $sub.DistinguishedName -Manager $managerDN
        }
    }
    else {
        Write-Warning "Round-robin assignment of direct reports to managers"
        $i = 0
        foreach ($sub in $subordinates) {
            $assignedManagerDN = $manager[$i % $managerCount].DistinguishedName
            Set-ADUser -Identity $sub.DistinguishedName -Manager $assignedManagerDN
            $i++
        }
    }
}

$DepartmentList.Departments.Titles | ForEach-Object {
    if ($_.DirectReports) {
        Write-Information "Setting direct reports for title $($_.Title)..." -InformationAction Continue
        Add-DirectReport -Title $_.Title -SubordinateTitles $_.DirectReports
    }
}
#endregion


#region Create Groups
Write-Information 'Creating Department groups...'
$DepartmentList.Departments | ForEach-Object {
    $secGroupName = 'ORG-{0}' -f $_.FullName.trim()
    $secGroupPath = "OU=Security,OU=Groups,$LabRootOU"
    $distGroupName = 'DIST-{0}' -f $_.FullName.trim()
    $distGroupPath = "OU=Distribution,OU=Groups,$LabRootOU"
    $members = Get-ADUser -Filter "Department -eq '$($_.FullName)'" | Select-Object -ExpandProperty SamAccountName
    $group = @{
        Name           = $secGroupName
        DisplayName    = $secGroupName
        SamAccountName = $secGroupName
        GroupCategory  = 'Security'
        GroupScope     = 'Global'
        Path           = $secGroupPath
    }
    try {
        if (-not (Test-ADSIPath "CN=$secGroupName,$secGroupPath")) {
            Write-Information "Creating security group $secGroupName"
            New-ADGroup @group -ErrorAction Stop

            Write-Information "Adding department members to $secGroupName"
            Add-ADGroupMember -Identity $secGroupName -Members $members -ErrorAction Stop
        }
        else {
            Write-Warning "Group $secGroupName already exists. Skipping."
        }
    }
    catch {
        Write-Warning "Error creating group $secGroupName ($($_.Exception.Message))"
    }

    $group.Name = $distGroupName
    $group.DisplayName = $distGroupName
    $group.SamAccountName = $distGroupName
    $group.GroupCategory = 'Distribution'
    $group.Path = $distGroupPath
    try {
        if (-not (Test-ADSIPath "CN=$distGroupName,$distGroupPath")) {
            Write-Information "Creating distribution group $distGroupName"
            New-ADGroup @group -ErrorAction Stop

            Write-Information "Adding department members to $distGroupName"
            Add-ADGroupMember -Identity $distGroupName -Members $members -ErrorAction Stop
        }
        else {
            Write-Warning "Group $distGroupName already exists. Skipping."
        }
    }
    catch {
        Write-Warning "Error creating group $distGroupName ($($_.Exception.Message))"
    }
}

Write-Information 'Creating All Users Security group...'
$allUsersGroup = @{
    Name           = 'All Users'
    DisplayName    = 'All Users'
    SamAccountName = 'AllUsers'
    GroupCategory  = 'Security'
    GroupScope     = 'Global'
    Path           = "OU=Security,OU=Groups,$LabRootOU"
}
try {
    if (-not (Test-ADSIPath "CN=All Users,OU=Security,OU=Groups,$LabRootOU")) {
        $newGroup = New-ADGroup @allUsersGroup -ErrorAction Stop -PassThru
        $allUsers = Get-ADUser -Filter * -SearchBase "OU=Users,$LabRootOU" | Select-Object -ExpandProperty SamAccountName
        $newGroup | Add-ADGroupMember -Members $allUsers -ErrorAction Stop
    }
    else {
        Write-Warning "Group 'All Users' already exists. Skipping."
    }
}
catch {
    Write-Warning "Error creating group 'All Users' ($($_.Exception.Message))"
}

Write-Information 'Creating Executive Security group...'
$execGroup = @{
    Name           = 'Executives'
    DisplayName    = 'Executives'
    SamAccountName = 'Executives'
    GroupCategory  = 'Security'
    GroupScope     = 'Global'
    Path           = "OU=Security,OU=Groups,$LabRootOU"
}
try {
    if (-not (Test-ADSIPath "CN=Executives,OU=Security,OU=Groups,$LabRootOU")) {
        $newGroup = New-ADGroup @execGroup -ErrorAction Stop -PassThru
        $execs = Get-ADUser -Filter * -SearchBase "OU=EXE,OU=Users,$LabRootOU" | Select-Object -ExpandProperty SamAccountName
        $newGroup | Add-ADGroupMember -Members $execs -ErrorAction Stop
    }
    else {
        Write-Warning "Group 'Executives' already exists. Skipping."
    }
}
catch {
    Write-Warning "Error creating group 'Executives' ($($_.Exception.Message))"
}
#endregion