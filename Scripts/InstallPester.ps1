# Remove the pre-installed version
$module = "C:\Program Files\WindowsPowerShell\Modules\Pester"
& takeown.exe /F $module /A /R
& icacls.exe $module /reset
& icacls.exe $module /grant "*S-1-5-32-544:F" /inheritance:d /T
Remove-Item -Path $module -Recurse -Force -Confirm:$false

# Install latest Pester
Install-Module -Name Pester -SkipPublisherCheck -Force -Scope AllUsers