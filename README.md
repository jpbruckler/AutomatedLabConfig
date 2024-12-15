# AutomatedLab Congig

Custom roles and lab definitions for use with [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab).

## Custom Roles

### PowerShell Universal

Prepares a machine for running [PowerShell Universal](https://powershelluniversal.com/). Downloads
the latest version of the MSI installer and installs it, and optionally configures the service to
run as a specific user.

### WindowsDocker

Installs Docker CE, the `DockerMsftProvider`, and the `docker` NuGet package on a Windows server.
This role will also look for the local disk with the most available free space and configure Docker
to use that disk for its storage.

## Lab Definitions

### PSLab
