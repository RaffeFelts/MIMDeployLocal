s# MIMDeployLocal
Automation Engine for Locally Deploying Microsoft Identity Manager (MIM) on Windows Server 2012 with SharePoint 2013

Getting Started:
1. Create Share with the name AutomationRoot. Popluate with Repo's contents
2. Download and populate Files folder with required install bits
3. Create MIM Admin Account
4. Add MIM Admin Account to Local admins of Target MIM Server.  Account should have perms to add Accounts/Groups to AD.
5. Add MIM Admin to SQL instance as Sysadmin
6. SQL should be pre-populated with MIM Sync and Service DB and MIM Service SQL Jobs
7. Logon to Target MIM Server with MIM Admin
8. Open an elevated Powershell ISE (at least PowerShell v4.0)
9. Add your MIM Portal/SSPR Sites and AutomationRoot URL to the Local Intranet Security Zone 
10. From the target MIM Server wack wack to the AutomationRoot
11. Execute EnvironmentStore\Dev\Scripts\MIMDeploy\MIMDeploy.Initialize.ps1
12. Modify MIMDeploy.ConfigurationData.Ps1 and MIMDeploy.ConfigurationData.Creds.ps1 to match your Environment
13. Once config files are properly populated Re-run MIMDeploy.Initialize.ps1
14. Run regions of MIMDeploy.Main.ps1 one at a time
