#region Relax UAC, Looback Checking, and IE ESC

Write-Verbose "Relax UAC, Looback Checking, and IE ESC"
#Set a few naughty things keep us from jumping off the building
#TODO Get *contoso.com in local Intranet IE Zone
#TODO Get \\ha-mim01 into  in local Intranet IE Zone, disabling uac or mapping a drive may fix this.

Disable-InternetExplorerESC
Disable-UserAccessControl

#Disable Lookback Checking
Write-Verbose "Loopback Checking Disabled"
New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value "1" -PropertyType dword -ErrorAction SilentlyContinue

#TODO: Setup user rights for MIM Sync Properly
#TODO: Setup user rights for MIM Service Properly

#endregion

#region Account Creation

Write-Verbose "Create MIM Accounts"

$sp = ConvertTo-SecureString 'Pa$$w0rd' –asplaintext –force

#Create Users:
#TODO  Add OU, handle password properly
$Cfg.NonNode.AllUsers | ForEach-Object {
    New-ADUser –SamAccountName $_ –name $_
    Set-ADAccountPassword –identity $_ –NewPassword $sp
    Set-ADUser –identity $_ –Enabled 1 –PasswordNeverExpires 1
    }

#Create Groups:

$Cfg.NonNode.AllGroups | ForEach-Object {
        New-ADGroup –name $_ –GroupCategory Security –GroupScope Global –SamAccountName $_
    }

Write-Verbose "Add Members to Groups"

#TODO This one is not working
foreach ($Group in $Cfg.NonNode.MembersToAdd.GetEnumerator()) {
    foreach ($Member in $Group.Value) {
        Write-Verbose "Add Group: $($Member) to $($Group.Name)"
        Add-ADGroupMember -identity $Group.Name -Members $Member
    }
} 

#Good Example of how to use a pipeline to access hashs of hashs
#$($Cfg.NonNode.SPNs.GetEnumerator())[0] | ForEach-Object {$Name = $_.name ; $_.value | ForEach-Object {Write-Verbose "$Name $_"}   }

Write-Verbose "Set SPNs"
foreach ($Row in $Cfg.NonNode.SPNs.GetEnumerator()) {
    foreach ($SPN in $Row.value) {
        Write-Verbose "setspn SPN: $($SPN) on Account: $($Cfg.NonNode.Domain)\$($Row.Name)"
        Invoke-Expression "setspn -S $($SPN) $($Cfg.NonNode.Domain)\$($Row.Name)"
    }
} 

Write-Verbose "Set Allow to Delegate to only FIMService"
foreach ($Row in $Cfg.NonNode.SPNDelegation.GetEnumerator()) {
    $user = Get-ADObject -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($Row.Name)))"
    Set-ADObject $user.DistinguishedName -Add @{"msDS-AllowedToDelegateTo" = "$($Row.Value)"}
} 

#endregion

#region DNS Record Creation

Write-Verbose "Create DNS Records"
foreach ($Row in $Cfg.NonNode.DNSRecords.GetEnumerator() ) {
    Add-DnsServerResourceRecordA -Name  $($Row.Value.Host) -IPv4Address $($Row.Value.IPv4Address) -ZoneName $($Row.Value.ZoneName) -ComputerName $($Row.Value.DNSSeverName)
} 
#endregion

#region Request Certificate

Write-Verbose "Request Certificate"
Get-Certificate -Template $Cfg.NonNode.CertRequest.Template -CertstoreLocation cert:\LocalMachine\My -SubjectName $Cfg.NonNode.CertRequest.SubjectName -DnsName $Cfg.NonNode.CertRequest.DnsName

$TestCert = Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Cfg.NonNode.CertRequest.SubjectName }

$TestCert = Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Cfg.NonNode.CertRequest.SubjectName } -ErrorAction SilentlyContinue -ErrorVariable err        
if ($TestCert -eq $null -or $err) {
   throw "Certificate Installation Failed"   
}

#endregion

#region Install DotNet 3.5
#NOTE: We need this installed before running SharePoint Pre-Req Installer
#TODO script is not find this path for some reason

Write-Verbose "Install DotNet 3.5"
Install-WindowsFeature Net-Framework-Core -source "$($MIMDeployPathUNC)\files\OS\sxs"

$TesDotNet = If (!(Get-WindowsFeature Net-Framework-Core).Installed){        
    throw "Net-Framework-Core Installation Failed"  
}

#endregion

#region Install SharePoint Pre-Reqs

Write-Verbose "Install SharePoint Pre-Reqs"
#TODO Need a way to make this location Local intranet
#TODO Need to automate this process, for now it needs to be run manually
#TODO No sure why have can't use the mapped drived below

$SharePointPath = "$($MIMDeployPathUNC)\Files\SharePoint" #No slash at the end here!

$ArgumentListString = ""
$ArgumentListString += "/SQLNCli:""$SharePointPath\Install\PrerequisiteInstallerFiles\sqlncli.msi"" "
$ArgumentListString += "/IDFX:""$SharePointPath\Install\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu"" "
$ArgumentListString += "/IDFX11:""$SharePointPath\Install\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi"" "
$ArgumentListString += "/Sync:""$SharePointPath\Install\PrerequisiteInstallerFiles\Synchronization.msi"" "
$ArgumentListString += "/AppFabric:""$SharePointPath\Install\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe"" "
$ArgumentListString += "/KB2671763:""$SharePointPath\Install\PrerequisiteInstallerFiles\AppFabric1.1-RTM-KB2671763-x64-ENU.exe"" "
$ArgumentListString += "/MSIPCClient:""$SharePointPath\Install\PrerequisiteInstallerFiles\setup_msipc_x64.msi"" "
$ArgumentListString += "/WCFDataServices:""$SharePointPath\Install\PrerequisiteInstallerFiles\WcfDataServices.exe"" "
$ArgumentListString += "/WCFDataServices56:""$SharePointPath\Install\PrerequisiteInstallerFiles\WcfDataServices56.exe"""

$ArgumentListString

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$SharePointPath\Install\prerequisiteinstaller.exe" -ArgumentList $ArgumentListString -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
}

#endregion

#region Install and Patch SharePoint Binaries

Write-Verbose "Deploy SharePoint Binaries"

$SharePointPath = "$($MIMDeployPathUNC)\Files\SharePoint" #No slash at the end here!

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$SharePointPath\Install\Setup.exe" -ArgumentList "/config $SharePointPath\Install\files\setupfarmsilent\config.xml" -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}

Write-Verbose "Patch SharePoint Binaries" 

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$($SharePointPath)\Patch\$($Cfg.NonNode.SP.PatchName)" -ArgumentList "/Passive" -Wait -Passthru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}

#endregion

#region Create SQL Aliases

Write-Verbose "Clear and Create SQL Aliases"

Clear-SQLAliases

Create-SQLAlias -ServerName $Cfg.NonNode.SQLAliases.SharePoint.ServerName -AliasName $Cfg.NonNode.SQLAliases.SharePoint.AliasName
Create-SQLAlias -ServerName $Cfg.NonNode.SQLAliases.MIMService.ServerName -AliasName $Cfg.NonNode.SQLAliases.MIMService.AliasName
Create-SQLAlias -ServerName $Cfg.NonNode.SQLAliases.MIMSync.ServerName -AliasName $Cfg.NonNode.SQLAliases.MIMSync.AliasName

#endregion

#region Create SharePoint Farm

Write-Verbose "Deploy SharePoint Farm"
#TODO Check add SharePoint Perms in SQL for MIM SP Farm Account,  Also make sure clean any old SharePoint Account in Logins

asnp Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$params = $null
$params = @{
            DatabaseServer = $Node.SP.SQLServer
            DatabaseName = $Node.SP.ConfDB 
            AdministrationContentDatabaseName = $Node.SP.AdminDB
            Passphrase = (ConvertTo-SecureString $Creds.FarmPassphrase -AsPlainText -force) 
            FarmCredentials = $Creds.FarmCredentials
            }

New-SPConfigurationDatabase @params

$TestFarm = Get-SPFarm -ErrorAction SilentlyContinue -ErrorVariable err        
if ($TestFarm -eq $null -or $err) {
   throw "Farm Installation Failed"   
}

$VerbosePreference = "SilentlyContinue"

Write-Verbose "ACLing SharePoint Resources"
Initialize-SPResourceSecurity | Out-Null
Write-Verbose "Installing Services ..."
Install-SPService | Out-Null  
Write-Verbose "Installing Features..."
Install-SPFeature -AllExistingFeatures | Out-Null

$VerbosePreference = "Continue"

#endregion

#region Create Central Admin Website

Write-Verbose "Creating Central Administration..."              
New-SPCentralAdministration -Port 8080 -WindowsAuthProvider NTLM 

$VerbosePreference = "SilentlyContinue"

Write-Verbose "Installing Help..."
Install-SPHelpCollection -All        
Write-Verbose "Installing Application Content..."
Install-SPApplicationContent

$VerbosePreference = "Continue"

#TODO There's got to be a better way to do this...
$TestCentralAdmin = Get-SPAlternateURL -ErrorAction SilentlyContinue -ErrorVariable err        
if ($TestCentralAdmin -eq $null -or $err) {
   throw "Central Admin Installation Failed"
   Break
}


#endregion

#region Create SharePoint Web Application

Write-Verbose "Deploy Web Application"

$ApplicationPoolAccount = & {
    Try {
        New-SPManagedAccount -Credential $Creds.ApplicationPoolAccount -ErrorAction Stop
    } Catch {
        Get-SPManagedAccount -Identity $Node.SP.AppPoolUserName
    }
}


$params = $Null
$params = @{
            ApplicationPool = $Node.SP.AppPoolName
            ApplicationPoolAccount = $ApplicationPoolAccount
            Name = $Node.Sp.WebAppName
            Port = "443"
            HostHeader = $Node.SP.WebAppHostHeader
            SecureSocketsLayer = $true
            AuthenticationMethod = "Kerberos"
            DatabaseName = $Node.SP.WebAppContentDB
            }

New-SPWebApplication @params

$TestWebApp = Get-SPWebApplication -ErrorAction SilentlyContinue -ErrorVariable err        
if ($TestWebApp -eq $null -or $err) {
   throw "Web App Installation Failed"
   Break
}

#Assign Cert to binding, Note: this sets all 443 ssl binds on all websites

#TODO Add @params block
Write-Verbose "Add SSL Cert to MIM Bindings"
Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Cfg.NonNode.CertRequest.SubjectName } | select -First 1 | New-Item IIS:\SslBindings\0.0.0.0!443

# configure ViewState as MIM likes it
Write-Verbose "Configuring View State"
$contentService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService;
$contentService.ViewStateOnServer = $false;
$contentService.Update();

#endregion

#region Create SharePoint Site Collection

Write-Verbose "Create Site Collection"

$params = $Null
$params = @{
            Name = $Node.SP.SiteName
            Url = $Node.SP.SiteUrl
            owneralias = $Node.SP.SiteOwnerAlias
            ownerEmail = $Node.SP.SiteOwnerEmail
            Template = "STS#1"
            CompatibilityLevel = 14
            }

New-SPSite @params

$TestSite = Get-SPSite -ErrorAction SilentlyContinue -ErrorVariable err        
if ($TestSite -eq $null -or $err) {
   throw "Site Installation Failed"
   Break
}

Write-Verbose "Disabling self service upgrade"
$spSite = Get-SpSite($Node.SP.SiteUrl);
$spSite.AllowSelfServiceUpgrade = $false

#endregion

#region Fix up SharePoint Authentication Settings

Write-Verbose "Fix up SharePoint Authentication Settings"
Write-Verbose "Set Negotiate:Kerberos on SharePoing Website"

### NOTE: This setting is important for MIM and it's support for non-IE browsers.  Without this setting
### browsers that don't properly support Kerberos can bring down SharePoing and MIM Service
$siteName = $Node.SP.WebAppName
#Set-WebConfiguration system.webServer/security/authentication/windowsAuthentication -PSPath IIS:\ -Location $siteName -Value @{enabled="True"}
#Set-WebConfigurationProperty -PSPath IIS:\ -Location $siteName -Filter //windowsAuthentication -Name useKernelMode -Value False
Remove-WebConfigurationProperty -Filter system.webServer/security/authentication/windowsAuthentication/providers -PSPath IIS:\ -Location $siteName -Name Collection
Add-WebConfiguration -Filter system.webServer/security/authentication/windowsAuthentication/providers -PSPath IIS:\ -Location $siteName -Value Negotiate:Kerberos
#Get-WebConfiguration -Filter system.webServer/security/authentication/windowsAuthentication/providers -PSPath IIS:\ -Location $siteName | Select-Object -ExpandProperty Collection 

#TODO This might not be needed
iisreset

#endregion

#region Deploy MIM Sync

Write-Verbose "Deploy MIM Sync"
$InstallExitCode = (Start-Process "msiexec" -ArgumentList $Node.MIMSync.ArgumentList -wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}


Write-Verbose "Run MiisActivate"

#TODO Something like this command might be needed on a fresh install
#Start-Process "C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin\miiskmu.exe" `
#    -ArgumentList """$MIMDeploypath\MIM\key.bin"" /u:CORP\MIMSync Pa`$`$w0rd" -Wait

$InstallExitCode = $null

$ArgumentList = $Null
$ArgumentList = """$($MIMDeployPathDriveLetter):\EnvironmentStore\$($EnvironmentStore)\MIM\key.bin"" Corp\MIMSync $($Creds.MiisactivatePassword) /q"

#TODO Trying -nonewindow here
$InstallExitCode = (Start-Process "C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Bin\miisactivate.exe" `
    -ArgumentList $ArgumentList -Wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}

#endregion

#region Patch MIM Sync

Write-Verbose "Patch MIM Sync"
$InstallExitCode = $null
$InstallExitCode = (Start-Process "$($MIMDeploypath)\Files\MIM\Patch\$($Node.MIMSync.Patch)" `
    -ArgumentList "/Passive" -Wait -PassThru).ExitCode

if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}


#endregion

#region Deploy MIM Service and Portal

Write-Verbose "Deploy MIM Service, Portal, and SSPR"

$InstallExitCode = $null
$InstallExitCode = (Start-Process "msiexec" -ArgumentList $Node.MIMService.ArgumentList -Wait -Passthru).ExitCode
if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}

#endregion

#region Patch MIM Service

Write-Verbose "Patch MIM Service"

$InstallExitCode = $null
$InstallExitCode = (Start-Process "$($MIMDeploypath)\Files\MIM\Patch\$($Node.MIMService.Patch)" -ArgumentList "/Passive" -Wait -Passthru).ExitCode
if ($InstallExitCode -eq 0){
    Write-Verbose “Installation Successful”
} else {
    Write-Verbose “Installation Failed with code $InstallExitCode – check Event Viewer and logs for errors”
    Break
}
#TODO Add logging to all patching

#endregion

#region Fix Up SSPR Bindings and Authentication Settings

Write-Verbose "Fix Up Bindings and Authentication Settings"
Write-Verbose "Add new Bindings"
New-WebBinding -Name $Node.Bindings.MIMPasswordRegSite.Name -Protocol "https" -Port 443 -HostHeader $Node.Bindings.MIMPasswordRegSite.HostHeaderShort -SslFlags 0
New-WebBinding -Name $Node.Bindings.MIMPasswordRegSite.Name -Protocol "https" -Port 443 -HostHeader $Node.Bindings.MIMPasswordRegSite.HostHeaderLong -SslFlags 0

New-WebBinding -Name $Node.Bindings.MIMPasswordResetSite.Name -Protocol "https" -Port 443 -HostHeader $Node.Bindings.MIMPasswordResetSite.HostHeaderShort -SslFlags 0
New-WebBinding -Name $Node.Bindings.MIMPasswordResetSite.Name -Protocol "https" -Port 443 -HostHeader $Node.Bindings.MIMPasswordResetSite.HostHeaderLong -SslFlags 0

Write-Verbose "Remove old Bindings"
Get-WebBinding -Name $Node.Bindings.MIMPasswordRegSite.Name -HostHeader $Node.Bindings.MIMPasswordRegSite.HostHeaderLong -Port 80 | Remove-WebBinding
Get-WebBinding -Name $Node.Bindings.MIMPasswordResetSite.Name -HostHeader $Node.Bindings.MIMPasswordResetSite.HostHeaderLong -Port 80 | Remove-WebBinding

Write-Verbose "Turn off Kernel-mode Authentication for MIM Reg Website" # Note this requires an iisreset
### NOTE: Setting is requried when using a custom AppPool account and
### when the MIM Reg site is using a URL that's not the name of the machine.
$ArgumentListString = $Null
$ArgumentListString += "set config ""$($Node.Bindings.MIMPasswordRegSite.Name)"" -section:system.webServer/security/authentication/windowsAuthentication /useKernelMode:""False""  /commit:apphost"
$ArgumentListString
Start-Process "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList $ArgumentListString -Wait

iisreset

#endregion

#region Configure DCOM Permissions for SSPR
#TODO
#endregion

#region Setup Shortnames and identitymanagment Redirection for Portal and SSPR
#TODO
#endregion

