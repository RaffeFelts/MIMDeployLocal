
$Creds = 
@{

    #TODO:  Convert these to prompt for Creds as needed
    FarmCredentials = New-Object System.Management.Automation.PSCredential ("CORP\MIMSPFarm", (ConvertTo-SecureString 'Pa$$w0rd' -AsPlainText -Force))
    ApplicationPoolAccount = New-Object System.Management.Automation.PSCredential ("CORP\MIMSPAppPool", (ConvertTo-SecureString 'Pa$$w0rd' -AsPlainText -Force))
    FarmPassphrase = 'Pa$$w0rd'
    MiisactivatePassword = "Pa`$`$w0rd"
}
write-verbose "Creds Loaded"