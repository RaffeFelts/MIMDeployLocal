#region Always Run Items

$MIMDeployPath = "\\ha-mim01\MIMDeploy"

#TODO:  Convert this to prompt for Creds as needed
$UpFrontCredsFarmAccount = New-Object System.Management.Automation.PSCredential ("CORP\MIMSPFarm", (ConvertTo-SecureString 'Pa$$w0rd' -AsPlainText -Force))
$UpFrontCredsAppPoolCred = New-Object System.Management.Automation.PSCredential ("CORP\MIMSPAppPool", (ConvertTo-SecureString 'Pa$$w0rd' -AsPlainText -Force))

$FarmPassphrass = 'Pa$$w0rd'

#endregion

#region Onetime Run Items

#Set a few naughty things keep us from jumping off the building

#TODO Get *contoso.com in local Intranet IE Zone
#TODO Get \\ha-mim01 into  in local Intranet IE Zone, disabling uac or mapping a drive may fix this.

function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been enabled." -ForegroundColor Green
}
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}

Disable-InternetExplorerESC
Disable-UserAccessControl

#Disable Lookback Checking
New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value "1" -PropertyType dword

#TODO: Setup user rights for MIM Sync Properly
#TODO: Setup user rights for MIM Service Properly

#endregion 

#region Install RSAT Tools

Import-Module ServerManager
Add-WindowsFeature RSAT-AD-PowerShell
Add-WindowsFeature RSAT-DNS-Server

#endregion

#region Account Creation

#Create MIM Accounts
 
import-module activedirectory

$sp = ConvertTo-SecureString 'Pa$$w0rd' –asplaintext –force
 
New-ADUser –SamAccountName MIMAdmin –name MIMAdmin
Set-ADAccountPassword –identity MIMAdmin –NewPassword $sp
Set-ADUser –identity MIMAdmin –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMMA –name MIMMA
Set-ADAccountPassword –identity MIMMA –NewPassword $sp
Set-ADUser –identity MIMMA –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMPassword –name MIMPassword
Set-ADAccountPassword –identity MIMPassword –NewPassword $sp
Set-ADUser –identity MIMPassword –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMService –name MIMService
Set-ADAccountPassword –identity MIMService –NewPassword $sp
Set-ADUser –identity MIMService –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMSPAppPool –name MIMSPAppPool
Set-ADAccountPassword –identity MIMSPAppPool –NewPassword $sp
Set-ADUser –identity MIMSPAppPool –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMSPFarm –name MIMSPFarm
Set-ADAccountPassword –identity MIMSPFarm –NewPassword $sp
Set-ADUser –identity MIMSPFarm –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMSync –name MIMSync
Set-ADAccountPassword –identity MIMSync –NewPassword $sp
Set-ADUser –identity MIMSync –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMADMA –name MIMADMA
Set-ADAccountPassword –identity MIMADMA –NewPassword $sp
Set-ADUser –identity MIMADMA –Enabled 1 –PasswordNeverExpires 1

New-ADUser –SamAccountName MIMTask –name MIMTask
Set-ADAccountPassword –identity MIMTask –NewPassword $sp
Set-ADUser –identity MIMTask –Enabled 1 –PasswordNeverExpires 1

#Create Groups
New-ADGroup –name MIMAdmins –GroupCategory Security –GroupScope Global –SamAccountName MIMAdmins
New-ADGroup –name MIMServices –GroupCategory Security –GroupScope Global –SamAccountName MIMServices
New-ADGroup –name MIMSyncAdmins –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncAdmins
New-ADGroup –name MIMSyncOperators –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncOperators
New-ADGroup –name MIMSyncJoiners –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncJoiners
New-ADGroup –name MIMSyncBrowse –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncBrowse
New-ADGroup –name MIMSyncPasswordSet –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncPasswordSet

Add-ADGroupMember -identity MIMSyncAdmins -Members MIMAdmin
Add-ADGroupmember -identity MIMSyncAdmins -Members MIMService
Add-ADGroupmember -identity MIMSyncBrowse -Members MIMService
Add-ADGroupmember -identity MIMSyncPasswordSet -Members MIMService
Add-ADGroupmember -identity MIMAdmins -Members MIMAdmin
Add-ADGroupmember -identity MIMServices -Members MIMSync
Add-ADGroupmember -identity MIMServices -Members MIMService
Add-ADGroupmember -identity MIMServices -Members MIMTask
Add-ADGroupmember -identity MIMServices -Members MIMMA

# MIMPassword SPNs
setspn -S HTTP/passwordreg CORP\MIMPassword
setspn -S HTTP/passwordreg.corp.contoso.com CORP\MIMPassword

setspn -S HTTP/passwordreset CORP\MIMPassword
setspn -S HTTP/passwordreset.corp.contoso.com CORP\MIMPassword

# MIMSPAppPool SPNs
setspn -S HTTP/mimportal.corp.contoso.com CORP\MIMSPAppPool

# MIM Service SPNs
setspn -S FIMService/mimservice.corp.contoso.com CORP\MIMService

# Set Allow to Delegate to only "FIMService"
$user = Get-ADObject -LDAPFilter "(&(objectCategory=person)(sAMAccountName=MIMService))"
Set-ADObject $user.DistinguishedName -Add @{"msDS-AllowedToDelegateTo" = "FIMService/mimservice.corp.contoso.com"}

$user = Get-ADObject -LDAPFilter "(&(objectCategory=person)(sAMAccountName=MIMSPAppPool))"
Set-ADObject $user.DistinguishedName -Add @{"msDS-AllowedToDelegateTo" = "FIMService/mimservice.corp.contoso.com"}

#endregion

#region DNS Record Creation

#Create DNS Records
import-module DNSServer

Add-DnsServerResourceRecordA -Name "mimportal" -IPv4Address "192.168.0.27" -ZoneName "corp.contoso.com" -ComputerName HA-DC01

Add-DnsServerResourceRecordA -Name "passwordreg" -IPv4Address "192.168.0.27" -ZoneName "corp.contoso.com" -ComputerName HA-DC01

Add-DnsServerResourceRecordA -Name "passwordreset" -IPv4Address "192.168.0.27" -ZoneName "corp.contoso.com" -ComputerName HA-DC01

Add-DnsServerResourceRecordA -Name "mimservice" -IPv4Address "192.168.0.27" -ZoneName "corp.contoso.com" -ComputerName HA-DC01

#endregion

#region Request Certificate
# Request Certificate

[String[]]$DnsStringArray = @()
$DnsStringArray += "mimportal"
$DnsStringArray += "mimportal.corp.contoso.com"
$DnsStringArray += "passwordreset"
$DnsStringArray += "passwordreset.corp.contoso.com"
$DnsStringArray += "passwordreg"
$DnsStringArray += "passwordreg.corp.contoso.com"

Get-Certificate -Template WebServer -CertstoreLocation cert:\LocalMachine\My -SubjectName "cn=MIM Certificate" -DnsName $DnsStringArray

#endregion

#region Install DotNet 3.5
#NOTE: We need this installed before running SharePoint Pre-Req Installer
Install-WindowsFeature Net-Framework-Core -source \\ha-mim01\MIMDeploy\OS\sxs
#endregion

#region Install SharePoint Pre-Reqs

#Install SharePoint Pre-Reqs
#TODO Need a way to make this location Local intranet
#TODO Need to automate this process, for now it needs to be run manually

$SharePoint2013SP1Path = "$MIMDeployPath\SharePoint\Install" #No slash at the end here!

$ArgumentListString = $Null
$ArgumentListString += "/SQLNCli:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\sqlncli.msi"" "
$ArgumentListString += "/IDFX:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu"" "
$ArgumentListString += "/IDFX11:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi"" "
$ArgumentListString += "/Sync:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\Synchronization.msi"" "
$ArgumentListString += "/AppFabric:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe"" "
$ArgumentListString += "/KB2671763:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\AppFabric1.1-RTM-KB2671763-x64-ENU.exe"" "
$ArgumentListString += "/MSIPCClient:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\setup_msipc_x64.msi"" "
$ArgumentListString += "/WCFDataServices:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\WcfDataServices.exe"" "
$ArgumentListString += "/WCFDataServices56:""$SharePoint2013SP1Path\PrerequisiteInstallerFiles\WcfDataServices56.exe"""

$ArgumentListString

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$SharePoint2013SP1Path\prerequisiteinstaller.exe" -ArgumentList $ArgumentListString -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#endregion

#region Install and Patch SharePoint Binaries

#Deploy SharePoint Binaries 

$SharePointPath= "$MIMDeployPath\SharePoint"

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$SharePointPath\Install\Setup.exe" -ArgumentList "/config $SharePointPath\Install\files\setupfarmsilent\config.xml" -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#Patch SharePoint Binaries 

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$SharePointPath\Patch\ubersts2013-kb3118271-fullfile-x64-glb.exe" -ArgumentList "/Passive" -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#endregion

#region Create SQL Aliases

# Clear and Create All MIM SQL Aliases

function Clear-SQLAliases { 
  [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')] 
  param 
  ( 
  ) 
  process { 
    $x86 = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"
    $x64 = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"
    Clear-Item $x86 -ErrorAction SilentlyContinue
    Clear-Item $x64 -ErrorAction SilentlyContinue

  } 
}

function Create-SQLAlias { 
  [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')] 
  param 
  ( 
    [Parameter(Mandatory=$True)] 
    [string]$ServerName,         
    [string]$AliasName
  ) 
  process { 
    $x86 = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"
    $x64 = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"

    #We're going to see if the ConnectTo key already exists, and create it if it doesn't.

    if ((test-path -path $x86) -ne $True)
        {
            New-Item $x86
        }
    if ((test-path -path $x64) -ne $True)
        {
            New-Item $x64
        }
    
    $TCPAlias = "DBMSSOCN," + $ServerName

    #Creating our TCP/IP Aliases
    New-ItemProperty -Path $x86 -Name $AliasName -PropertyType String -Value $TCPAlias 
    New-ItemProperty -Path $x64 -Name $AliasName -PropertyType String -Value $TCPAlias

  } 
}

Clear-SQLAliases

Create-SQLAlias -ServerName "HA-SQL03\MIMInstance" -AliasName "SQLMIMSharePoint"
Create-SQLAlias -ServerName "HA-SQL03\MIMInstance" -AliasName "SQLMIMService"
Create-SQLAlias -ServerName "HA-SQL03\MIMInstance" -AliasName "SQLMIMSync"

#endregion

#region Create SharePoint Farm

asnp Microsoft.SharePoint.PowerShell

#Deploy Farm:

$databaseServer = "SQLMIMSharePoint"
$configDatabase = "MIMSharePoint_Config" # Farm DB
$adminContentDB = "MIMSharePoint_Admin" # Central Admin Content DB
$passphrase = 'Pa$$w0rd'
$farmAccount = $UpFrontCredsFarmAccount
$passphrase = (ConvertTo-SecureString $passphrase -AsPlainText -force)

Write-Host "Creating Configuration Database and Central Admin Content Database..."
New-SPConfigurationDatabase -DatabaseServer $databaseServer -DatabaseName $configDatabase `
    -AdministrationContentDatabaseName $adminContentDB `
    -Passphrase $passphrase -FarmCredentials $farmAccount
    
$spfarm = Get-SPFarm -ErrorAction SilentlyContinue -ErrorVariable err        
if ($spfarm -eq $null -or $err) {
   throw "Unable to verify farm creation."
}

Write-Host "ACLing SharePoint Resources..."
Initialize-SPResourceSecurity
Write-Host "Installing Services ..."
Install-SPService   
Write-Host "Installing Features..."
Install-SPFeature -AllExistingFeatures

Write-Host "Farm Creation Done!"

#endregion

#region Create Central Admin Website

asnp Microsoft.SharePoint.PowerShell

Write-Host "Creating Central Administration..."              
New-SPCentralAdministration -Port 8080 -WindowsAuthProvider NTLM 

Write-Host "Installing Help..."
Install-SPHelpCollection -All        
Write-Host "Installing Application Content..."
Install-SPApplicationContent

Write-Host "Central Administration Creation Done!"

#endregion

#region Create SharePoint Web Application

asnp Microsoft.SharePoint.PowerShell
Import-Module WebAdministration

#Deploy Web Application

$waAppPoolName = "MIM SharePoint AppPool"

$waUrl = "https://mimportal.corp.contoso.com" # Use as the default AAM
$hostHeader = "mimportal.corp.contoso.com"
$webAppName = "MIM SharePoint Web Site" #Show Up in IIS
$contentDBName = "MIMSharePoint_Content"
$ownerEmail = "noreply@corp.contoso.com" # required, but isn't typically valid
$ownerAlias = "CORP\MIMAdmin" # Site Collection Admin

# Create Managed Account

$appPoolCred = $UpFronCredsAppPoolCred
Write-Host "Creating Managed Account..."
$waAppPoolAccount = New-SPManagedAccount -Credential $appPoolCred

# Create a new SSL Web App in the default Proxy Group using Windows Classic 
Write-Host "Creating Web Application..."
$webApp = New-SPWebApplication `
    -ApplicationPool $waAppPoolName `
    -ApplicationPoolAccount $waAppPoolAccount `
    -Name $webAppName `
    -Port 443 `
    -HostHeader $hostHeader `
    -SecureSocketsLayer:$true `
    -AuthenticationMethod Kerberos `
    -DatabaseName $contentDBName

#Fix SharePoint website bindings
#New-WebBinding -Name "MIM SharePoint Web Site" -Protocol "https" -Port 443 -HostHeader "mimportal.corp.contoso.com" -SslFlags 0
#Remove old Bindings
#Get-WebBinding -Name "MIM SharePoint Web Site" -HostHeader "mimportal" | Remove-WebBinding
#Assign Cert to binding, Note: this sets all 443 ssl binds on all websites
Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=MIM Certificate" } | select -First 1 | New-Item IIS:\SslBindings\0.0.0.0!443

# configure ViewState as MIM likes it
Write-Host "Configuring View State..."
$contentService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService;
$contentService.ViewStateOnServer = $false;
$contentService.Update();

#endregion

#region Create SharePoint Site Collection

asnp Microsoft.SharePoint.PowerShell
Import-Module WebAdministration

# Create a root Site Collection

$waName = "MIM SharePoint Teamsite"
$waUrl = "https://mimportal.corp.contoso.com"
$ownerEmail = "noreply@corp.contoso.com" # required, but isn't typically valid 
$ownerAlias = "CORP\MIMAdmin" # Site Collection Admin

Write-Host "Creating root Site Collection..."
New-SPSite `
    -Name $waName `
    -Url $waUrl `
    -owneralias $ownerAlias `
    -ownerEmail $ownerEmail `
    -Template "STS#1" `
    -CompatibilityLevel 14 

Write-Host "Disabling self service upgrade..."
$spSite = Get-SpSite($waUrl);
$spSite.AllowSelfServiceUpgrade = $false

Write-Host "MIM SP Web Application done!"

#endregion

#region Deploy MIM Sync

#Deploy MIM Sync$ArgumentListString = $Null$ArgumentListString +=  "/q /i ""$MIMDeployPath\MIM\Install\Synchronization Service\Synchronization Service.msi"" "$ArgumentListString += "ACCEPT_EULA=1 " $ArgumentListString += "SQLServerStore=RemoteMachine "$ArgumentListString += "STORESERVER=SQLMIMSync "$ArgumentListString += "SQLDB=MIMSynchronization "#$ArgumentListString += "SQLINSTANCE=MIMINSTANCE "$ArgumentListString += "SERVICEACCOUNT=MIMSync "$ArgumentListString += 'SERVICEPASSWORD=Pa$$w0rd '$ArgumentListString += "SERVICEDOMAIN=CORP "$ArgumentListString += "GROUPADMINS=CORP\MIMSyncAdmins "$ArgumentListString += "GROUPOPERATORS=CORP\MIMSyncOperators "$ArgumentListString += "GROUPACCOUNTJOINERS=CORP\MIMSyncJoiners "$ArgumentListString += "GROUPBROWSE=CORP\MIMSyncBrowse "$ArgumentListString += "GROUPPASSWORDSET=CORP\MIMSyncPasswordSet "$ArgumentListString += "FIREWALL_CONF=1 "$ArgumentListString += "/L*v ""C:\DeployMIMSync.txt"""
$ArgumentListString

$InstallExitCode = $null
$InstallExitCode = (Start-Process "msiexec" -ArgumentList $ArgumentListString -wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#TODO this command might be need on a fresh install
#Start-Process "C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin\miiskmu.exe" `
#    -ArgumentList """$MIMDeploypath\MIM\key.bin"" /u:CORP\MIMSync Pa`$`$w0rd" -Wait

$InstallExitCode = $null
$InstallExitCode = (Start-Process "C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin\miisactivate.exe" `
    -ArgumentList """$MIMDeploypath\MIM\key.bin"" Corp\MIMSync Pa`$`$w0rd /q" -Wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#endregion

#region Patch MIM Sync

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$MIMDeploypath\MIM\Patch\FIMSyncService_x64_KB4012498.msp" `
    -ArgumentList "/Passive" -Wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}


#endregion

#region Deploy MIM Service and Portal

#Deploy MIM Service, Portal, and SSPR

$ArgumentListString = $Null
$ArgumentListString +=  "/qn /i ""$MIMDeployPath\MIM\Install\Service and Portal\Service and Portal.msi"" "
$ArgumentListString += "ACCEPT_EULA=1 "
$ArgumentListString += "ADDLOCAL=CommonServices,WebPortals,RegistrationPortal,ResetPortal "

#MIM Service 
$ArgumentListString += "SQMOPTINSETTING=1 "
# $ArgumentListString += "IS_REMOTE_SQL_SERVER=1 "
$ArgumentListString += "SQLSERVER_SERVER=SQLMIMService "
$ArgumentListString += "SQLSERVER_DATABASE=MIMService "
$ArgumentListString += "EXISTINGDATABASE=1 "
$ArgumentListString += "MAIL_SERVER=mail.corp.contoso.com "
$ArgumentListString += "MAIL_SERVER_USE_SSL=0 "
$ArgumentListString += "MAIL_SERVER_IS_EXCHANGE=0 "
$ArgumentListString += "POLL_EXCHANGE_ENABLED=0 "
$ArgumentListString += "SERVICE_ACCOUNT_NAME=MIMService "
$ArgumentListString += 'SERVICE_ACCOUNT_PASSWORD=Pa$$w0rd ' 
$ArgumentListString += "SERVICE_ACCOUNT_DOMAIN=CORP "
$ArgumentListString += "SERVICE_ACCOUNT_EMAIL=mimservice@corp.contoso.com "
$ArgumentListString += "SYNCHRONIZATION_SERVER=HA-MIM07 "
$ArgumentListString += "SYNCHRONIZATION_SERVER_ACCOUNT=CORP\MIMMA "
#$ArgumentListString += "REQUIRE_REGISTRATIONPORTAL_INFO=1 "
#$ArgumentListString += "REQUIRE_RESETPORTAL_INFO=1 "
#$ArgumentListString += "REGISTRATION_ACCOUNT=CORP\MIMPassword "
#$ArgumentListString += "RESET_ACCOUNT=CORP\MIMPassword "


#Portal Properties:
$ArgumentListString += "SERVICEADDRESS=mimservice.corp.contoso.com "
$ArgumentListString += "SHAREPOINT_URL=https://mimportal.corp.contoso.com "
$ArgumentListString += "REGISTRATION_PORTAL_URL=https://passwordreg.corp.contoso.com " 
$ArgumentListString += "FIREWALL_CONF=1 " 
$ArgumentListString += "SHAREPOINTUSERS_CONF=1 "
#$ArgumentListString += "REQUIRE_REGISTRATION_INFO=1 "
#$ArgumentListString += "REGISTRATION_ACCOUNT_NAME=MIMPassword " 
#$ArgumentListString += "REGISTRATION_ACCOUNT_DOMAIN=CORP " 
#$ArgumentListString += "REQUIRE_RESET_INFO=1 " 
#$ArgumentListString += "RESET_ACCOUNT_NAME=MIMPassword " 
#$ArgumentListString += "RESET_ACCOUNT_DOMAIN=CORP " 

#SSPR Portal
$ArgumentListString += "REGISTRATION_ACCOUNT=CORP\MIMPassword " 
$ArgumentListString += 'REGISTRATION_ACCOUNT_PASSWORD=Pa$$w0rd ' 
$ArgumentListString += "REGISTRATION_HOSTNAME=passwordreg.corp.contoso.com " 
$ArgumentListString += "REGISTRATION_PORT=80 " 
$ArgumentListString += "REGISTRATION_FIREWALL_CONF=1 " 
$ArgumentListString += "REGISTRATION_SERVERNAME=mimservice.corp.contoso.com " 
$ArgumentListString += "IS_REGISTRATION_EXTRANET=Extranet " 
$ArgumentListString += "RESET_ACCOUNT=CORP\MIMPassword " 
$ArgumentListString += 'RESET_ACCOUNT_PASSWORD=Pa$$w0rd ' 
$ArgumentListString += "RESET_HOSTNAME=passwordreset.corp.contoso.com " 
$ArgumentListString += "RESET_PORT=80 " 
$ArgumentListString += "RESET_FIREWALL_CONF=1 "  
$ArgumentListString += "RESET_SERVERNAME=mimservice.corp.contoso.com " 
$ArgumentListString += "IS_RESET_EXTRANET=Extranet "

#Sharepoint:
#$ArgumentListString += "SHAREPOINTTIMEOUT=600 "

#Logging
$ArgumentListString += "/L*v ""C:\MIMPortalLog.txt"""

$ArgumentListString

$InstallExitCode = $null
$InstallExitCode = (Start-Process "msiexec" -ArgumentList $ArgumentListString -Wait -Passthru).ExitCode
if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}

#endregion

#region Patch MIM Service
$InstallExitCode = $null
$InstallExitCode = (Start-Process "$MIMDeploypath\MIM\Patch\FIMService_x64_KB4012498.msp" -ArgumentList "/Passive" -Wait -Passthru).ExitCode
if ($InstallExitCode -eq 0){
    “Installation Successful”
} else {
    “Installation Failed with code $InstallExitCode – check Windows Event Viewer for errors”
}
#TODO Add logging to all patching

#endregion

#region Fix Up SSPR URLs an Authentication Settings


New-WebBinding -Name "MIM Password Registration Site" -Protocol "https" -Port 443 -HostHeader "passwordreg" -SslFlags 0
New-WebBinding -Name "MIM Password Registration Site" -Protocol "https" -Port 443 -HostHeader "passwordreg.corp.contoso.com" -SslFlags 0

New-WebBinding -Name "MIM Password Reset Site" -Protocol "https" -Port 443 -HostHeader "passwordreset" -SslFlags 0
New-WebBinding -Name "MIM Password Reset Site" -Protocol "https" -Port 443 -HostHeader "passwordreset.corp.contoso.com" -SslFlags 0

#Remove old Bindings
Get-WebBinding -Name "MIM Password Registration Site" -HostHeader "passwordreg.corp.contoso.com" -Port 80 | Remove-WebBinding
Get-WebBinding -Name "MIM Password Reset Site" -HostHeader "passwordreset.corp.contoso.com" -Port 80 | Remove-WebBinding

#Turn off Kernel-mode Authentication, Note this requires an iisreset
$ArgumentListString = $Null
$ArgumentListString += "set config ""MIM Password Registration Site"" -section:system.webServer/security/authentication/windowsAuthentication /useKernelMode:""False""  /commit:apphost"
$ArgumentListString
Start-Process "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList $ArgumentListString -Wait

iisreset

#endregion

#region Setup Shortname and identitymanagment Redirection
#TODO
#endregion

#region Set SharePoint and Password Registration to Kerberos Only
#TODO
#endregion