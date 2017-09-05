#Requires -Version 4.0 -RunAsAdministrator 

#TODO: Set/Check Execution Policy
#TODO: Make sure MIM Admin account is SysAdmin in SQL
#TODO: SharePoint Farm account needs dbcreator and securityadmin in SQL
#TODO: Add to Local Intranet: Mim Portal, Pasword Reg, Password Reset, UNC of automation root share, http://localhost:8080

cls
$VerbosePreference = "Continue"

$EnvironmentStore = "Dev"

#Get the Partent folder from the folder where this script is running
#Note this only works if you running the whole script.
$ScriptPath = Split-Path $script:MyInvocation.MyCommand.Path 
Write-Verbose "Detected Script Path: $ScriptPath"
$ScriptPathRoot = $ScriptPath | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent
Write-Verbose "Calulated Root Path: $ScriptPathRoot"

$MIMDeployPathDriveLetter = "Z" 

Remove-PSDrive -Name $MIMDeployPathDriveLetter -Force -ErrorAction SilentlyContinue
Write-Verbose "Mapping $($MIMDeployPathDriveLetter): to $ScriptPathRoot"
New-PSDrive –Name $MIMDeployPathDriveLetter –PSProvider FileSystem –Root ($ScriptPathRoot) -Persist -Scope Global

$MIMDeployPath = "$($MIMDeployPathDriveLetter):"
$MIMDeployPathUNC = $ScriptPathRoot

Set-Location "$($MIMDeployPath)"

. ".\EnvironmentStore\$($EnvironmentStore)\Scripts\MIMDeploy\MIMDeploy.ConfigurationData.ps1"
. ".\EnvironmentStore\$($EnvironmentStore)\Scripts\MIMDeploy\MIMDeploy.ConfigurationData.Creds.ps1"
. ".\Scripts\MIMDeploy\MIMDeploy.Helpers.ps1"


$VerbosePreference = "SilentlyContinue"

Import-Module ServerManager 
Add-WindowsFeature RSAT-AD-PowerShell 
Add-WindowsFeature RSAT-DNS-Server 
Import-Module ActiveDirectory
Import-Module DnsServer
asnp Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
Import-Module WebAdministration -ErrorAction SilentlyContinue

$VerbosePreference = "Continue"

psEdit ".\EnvironmentStore\$($EnvironmentStore)\Scripts\MIMDeploy\MIMDeploy.ConfigurationData.ps1"
psEdit ".\EnvironmentStore\$($EnvironmentStore)\Scripts\MIMDeploy\MIMDeploy.ConfigurationData.Creds.ps1"
psEdit ".\Scripts\MIMDeploy\MIMDeploy.Helpers.ps1" 
PsEdit ".\Scripts\MIMDeploy\MIMDeploy.Main.ps1"

