$Cfg = 
@{
    AllNodes = 
    @(
        @{
        
        NodeName = “HA-MIM07”

        SP=
        @{
            SQLServer = "SQLMIMSharePoint"
            ConfDB    = "MIMSharePoint_Config"
            AdminDB ="MIMSharePoint_Admin"
            FarmUserName = "MIMSPFarm" #TODO What format?
            AppPoolUserName = "CORP\MIMSPAppPool"
            AppPoolName = "MIM SharePoint AppPool"
          
            WebAppName = "MIM SharePoint Web Site"
            WebAppContentDB = "MIMSharePoint_Content"
            WebAppHostHeader = "mimportal.corp.contoso.com"

            SiteName ="MIM SharePoint Team Site"
            SiteUrl = "https://mimportal.corp.contoso.com"  
            SiteOwnerAlias = "CORP\MIMAdmin" #Site Collection Administrator
            SiteOwnerEmail="noreply@corp.contoso.com"
        }

        MIMPortal=
        @{
            ServiceAddress = "mimservice.corp.contoso.com"
            SharePointURL ="https://mimportal.corp.contoso.com"
            RegPortalURL = "https://passwordreg.corp.contoso.com"
            RegAccountName = "MIMPassword"
            RegAccountDomain = "CORP"
            ResetAccountName = "MIMPassword"
            ResetAccountDomain = "CORP"
        }

        SSPRRegPortal=
        @{
            RegAccount = "CORP\MIMPassword"
            RegHostname = "passwordreg.corp.contoso.com"
            RegPort = "8888"
            RegServicename = "mimservice.corp.contoso.com"
            RegType = "Extranet"
        }

        SSPRResetPortal=
        @{
            ResetAccount = "CORP\MIMPassword"
            ResetHostname = "passwordreset.corp.contoso.com"
            ResetPort = "9999"
            ResetServicename = "mimservice.corp.contoso.com"
            ResetType = "Extranet"  #TODO Do we need this?
        }

        MIMService=
        @{
            SQLServer = "SQLMIMService"
            SQLDB = "MIMService"
            MailServer = "mail.corp.contoso.com "
            ServiceAccountName = "MIMService"
            ServiceAccountDomain = "CORP"
            ServiceAccountEmail = "MIMService@corp.contoso.com"
            SyncServer = "HA-MIM07"
            SyncServerAccount = "CORP\MIMMA"
            
            ArgumentList = & {

                #Deploy MIM Service, Portal, and SSPR

                $ArgumentListString = $Null
                $ArgumentListString +=  "/qn /i ""$MIMDeployPath\Files\MIM\Install\Service and Portal\Service and Portal.msi"" "
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
                }

                Patch = "FIMService_x64_KB4012498.msp"
        }

        MIMSync=
        @{
            ArgumentList = & {
                $ArgumentListString = $Null                $ArgumentListString +=  "/q /i ""$MIMDeployPath\Files\MIM\Install\Synchronization Service\Synchronization Service.msi"" "                $ArgumentListString += "ACCEPT_EULA=1 "                 $ArgumentListString += "SQLServerStore=RemoteMachine "                $ArgumentListString += "STORESERVER=SQLMIMSync "                $ArgumentListString += "SQLDB=MIMSynchronization "                #$ArgumentListString += "SQLINSTANCE=MIMINSTANCE "                $ArgumentListString += "SERVICEACCOUNT=MIMSync "                $ArgumentListString += 'SERVICEPASSWORD=Pa$$w0rd '                $ArgumentListString += "SERVICEDOMAIN=CORP "                $ArgumentListString += "GROUPADMINS=CORP\MIMSyncAdmins "                $ArgumentListString += "GROUPOPERATORS=CORP\MIMSyncOperators "                $ArgumentListString += "GROUPACCOUNTJOINERS=CORP\MIMSyncJoiners "                $ArgumentListString += "GROUPBROWSE=CORP\MIMSyncBrowse "                $ArgumentListString += "GROUPPASSWORDSET=CORP\MIMSyncPasswordSet "                $ArgumentListString += "FIREWALL_CONF=1 "                $ArgumentListString += "/L*v ""C:\MIMSyncLog.txt"""                $ArgumentListString
                }
            Patch= "FIMSyncService_x64_KB4012498.msp"
        }
        
        Bindings =@{
            MIMPasswordRegSite= @{
                Name = "MIM Password Registration Site"
                HostHeaderShort = "passwordreg"
                HostHeaderLong = "passwordreg.corp.contoso.com"
            }
            MIMPasswordResetSite= @{
                Name = "MIM Password Reset Site"
                HostHeaderShort = "passwordreset"
                HostHeaderLong = "passwordreset.corp.contoso.com"
            }

        }

                               
        },

        @{       
            NodeName = “HA-MIM08” #Example
            TestSetting = "Foo"
        }

    ) #AllNodes

    NonNode = 
    @{
        Domain = "CORP"
        DomainURL = "corp.contoso.com"

        AllUsers = 
            "MIMAdmin", 
            "MIMMA",
            "MIMPassword",
            "MIMService",
            "MIMSPAppPool",
            "MIMSPFarm",
            "MIMSync",
            "MIMADMA",
            "MIMTask"
        
         AllGroups =
            "MIMAdmins",
            "MIMServices",
            "MIMSyncAdmins",
            "MIMSyncOperators",
            "MIMSyncJoiners",
            "MIMSyncBrowse",
            "MIMSyncPasswordSet"

        MembersToAdd = #TODO Review this list
        @{
            MIMSyncAdmins = "MIMAdmins","MIMService"
            MIMSyncBrowse = "MIMService"
            MIMSyncPasswordSet = "MIMService"
            MIMAdmins = "MIMAdmin"
            MIMServices = "MIMSync","MIMService","MIMTask","MIMMA"
        }

        SPNs=
        @{
            MIMPassword = 
                "HTTP/passwordreg", 
                "HTTP/passwordreg.corp.contoso.com", 
                "HTTP/passwordreset", 
                "HTTP/passwordreset.corp.contoso.com"

            MIMSPAppPool = 
                "HTTP/mimportal.corp.contoso.com"

            MIMService = "FIMService/mimservice.corp.contoso.com"
        }

        SPNDelegation=
        @{
            MIMService = "FIMService/mimservice.corp.contoso.com"
            MIMSPAppPool = "FIMService/mimservice.corp.contoso.com"
        }

        DNSRecords=
        @{

            MIMPortalSite=
            @{
                Host="mimportal"
                IPv4Address = "192.168.0.27"
                ZoneName = "corp.contoso.com"
                DNSSeverName = "HA-DC01"                
            }

            MIMService=
            @{
                Host="mimservice"
                IPv4Address = "192.168.0.27"
                ZoneName = "corp.contoso.com"
                DNSSeverName = "HA-DC01"                
            }

            PasswordRegSite=
            @{
                Host= "passwordreg"
                IPv4Address = "192.168.0.27"
                ZoneName = "corp.contoso.com"
                DNSSeverName = "HA-DC01"
            }

            PasswordResetSite=
            @{
                Host= "passwordreset"
                IPv4Address = "192.168.0.27"
                ZoneName = "corp.contoso.com"
                DNSSeverName = "HA-DC01"
            }

        }

        CertRequest =
        @{
            Template = "WebServer"
            SubjectName = "cn=MIM Certificate"
            DnsName = & { 
                [String[]]$DnsStringArray = @()
                $DnsStringArray += "mimportal"
                $DnsStringArray += "mimportal.corp.contoso.com"
                $DnsStringArray += "passwordreset"
                $DnsStringArray += "passwordreset.corp.contoso.com"
                $DnsStringArray += "passwordreg"
                $DnsStringArray += "passwordreg.corp.contoso.com"
                $DnsStringArray
                }
        }

        SP =
        @{
            PatchName = "ubersts2013-kb3118271-fullfile-x64-glb.exe"
        }



        SQLAliases =
        @{
            SharePoint=
            @{
                ServerName = "HA-SQL03\MIMInstance"
                AliasName = "SQLMIMSharePoint"
            }

            MIMService=
            @{
                ServerName = "HA-SQL03\MIMInstance"
                AliasName = "SQLMIMService"
            }

            MIMSync=
            @{
                ServerName = "HA-SQL03\MIMInstance"
                AliasName = "SQLMIMSync"
            }
        }


     }   
} 

#Pruning

#TODO = Have node equal a target node instead of hard coding it here
$Node = $Cfg.AllNodes[0]
write-verbose "Configuration Loaded"

