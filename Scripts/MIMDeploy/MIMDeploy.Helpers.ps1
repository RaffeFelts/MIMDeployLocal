Write-Verbose "Helpers Loaded"

function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Verbose "IE Enhanced Security Configuration (ESC) has been disabled." 
}
function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
    Stop-Process -Name Explorer
    Write-Verbose "IE Enhanced Security Configuration (ESC) has been enabled." 
}
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Verbose "User Access Control (UAC) has been disabled."   
}

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


function Set-MIMWMI {
PARAM(
	[string]$Principal = $(throw "`nMissing -Principal DOMAIN\FIM PasswordSet"), 
	$Computers = $(throw "`nMissing -Computers ('fimnode01','fimnode02')")
)	

# USAGE: 
# 
# Set-MIMWMI -Principal "DOMAIN\<group or username>" -Computers ('<server1>', '<server2>',...) 
# 
# EXAMPLE: 
# Set-MIMWMI -Principal "DOMAIN\FIM PasswordSet" -Computers ('mimsyncprimary', 'mimyncstandby')


    Write-Host "Set-FIM-WMI - Updates WMI Permissions for FIM Password Reset"
    Write-Host "`tWritten by Brad Turner (bturner@ensynch.com)"
    Write-Host "`tBlog: http://www.identitychaos.com"

    function get-sid
    {
     PARAM ($DSIdentity)
     $ID = new-object System.Security.Principal.NTAccount($DSIdentity)
     return $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
    }

    $sid = get-sid $Principal

    #WMI Permission - Enable Account, Remote Enable for This namespace and subnamespaces 
    $WMISDDL = "A;CI;CCWP;;;$sid" 

    #PartialMatch
    $WMISDDLPartialMatch = "A;\w*;\w+;;;$sid"

    foreach ($strcomputer in $computers)
    {
      write-host "`nWorking on $strcomputer..."
      $security = Get-WmiObject -ComputerName $strcomputer -Namespace root/cimv2 -Class __SystemSecurity
      $binarySD = @($null)
      $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)

      # Convert the current permissions to SDDL 
      write-host "`tConverting current permissions to SDDL format..."
      $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
      $CurrentWMISDDL = $converter.BinarySDToSDDL($binarySD[0])

      # Build the new permissions 
      write-host "`tBuilding the new permissions..."
      if (($CurrentWMISDDL.SDDL -match $WMISDDLPartialMatch) -and ($CurrentWMISDDL.SDDL -notmatch $WMISDDL))
      {
       $NewWMISDDL = $CurrentWMISDDL.SDDL -replace $WMISDDLPartialMatch, $WMISDDL
      }
      else
      {
       $NewWMISDDL = $CurrentWMISDDL.SDDL += "(" + $WMISDDL + ")"
      }

      # Convert SDDL back to Binary 
      write-host `t"Converting SDDL back into binary form..."
      $WMIbinarySD = $converter.SDDLToBinarySD($NewWMISDDL)
      $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
 
      # Apply the changes
      write-host "`tApplying changes..."
      if ($CurrentWMISDDL.SDDL -match $WMISDDL)
      {
        write-host "`t`tCurrent WMI Permissions matches desired value."
      }
      else
      {
       $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions) 
       if($result='0'){write-host "`t`tApplied WMI Security complete."}
      }
    }
}

function Set-MIMDCOM {
PARAM( 
	[string]$Principal = $(throw "`nMissing -Principal DOMAIN\FIM PasswordSet"), 
	$Computers = $(throw "`nMissing -Computers ('fimnode01','fimnode02')")
)

# USAGE: 
#
# Set-MIMDCOM.ps1 -Principal "DOMAIN\<group or username>" -Computers ('<server1>', '<server2>',...)
#
# EXAMPLE:
# Set-MIMDCOM.ps1 -Principal "DOMAIN\FIM PasswordSet" -Computers ('mimsyncprimary', 'mimyncstandby')

Write-Host "Set-FIM-DCOM - Updates DCOM Permissions for FIM Password Reset"
Write-Host "`tWritten by Brad Turner (bturner@ensynch.com)"
Write-Host "`tBlog: http://www.identitychaos.com"

    function get-sid
    {
     PARAM ($DSIdentity)
     $ID = new-object System.Security.Principal.NTAccount($DSIdentity)
     return $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
    }

    $sid = get-sid $Principal

    #MachineLaunchRestriction - Local Launch, Remote Launch, Local Activation, Remote Activation
    $DCOMSDDLMachineLaunchRestriction = "A;;CCDCLCSWRP;;;$sid"

    #MachineAccessRestriction - Local Access, Remote Access
    $DCOMSDDLMachineAccessRestriction = "A;;CCDCLC;;;$sid"

    #DefaultLaunchPermission - Local Launch, Remote Launch, Local Activation, Remote Activation
    $DCOMSDDLDefaultLaunchPermission = "A;;CCDCLCSWRP;;;$sid"

    #DefaultAccessPermision - Local Access, Remote Access
    $DCOMSDDLDefaultAccessPermision = "A;;CCDCLC;;;$sid"

    #PartialMatch
    $DCOMSDDLPartialMatch = "A;;\w+;;;$sid"

    foreach ($strcomputer in $computers)
    {
     write-host "`nWorking on $strcomputer with principal $Principal ($sid):"
     # Get the respective binary values of the DCOM registry entries
     $Reg = [WMIClass]"\\$strcomputer\root\default:StdRegProv"
     $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
     $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
     $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
     $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue

     # Convert the current permissions to SDDL
     write-host "`tConverting current permissions to SDDL format..."
     $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
     $CurrentDCOMSDDLMachineLaunchRestriction = $converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)
     $CurrentDCOMSDDLMachineAccessRestriction = $converter.BinarySDToSDDL($DCOMMachineAccessRestriction)
     $CurrentDCOMSDDLDefaultLaunchPermission = $converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)
     $CurrentDCOMSDDLDefaultAccessPermission = $converter.BinarySDToSDDL($DCOMDefaultAccessPermission)

     # Build the new permissions
     write-host "`tBuilding the new permissions..."
     if (($CurrentDCOMSDDLMachineLaunchRestriction.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLMachineLaunchRestriction.SDDL -notmatch $DCOMSDDLMachineLaunchRestriction))
     {
       $NewDCOMSDDLMachineLaunchRestriction = $CurrentDCOMSDDLMachineLaunchRestriction.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLMachineLaunchRestriction
     }
     else
     {
       $NewDCOMSDDLMachineLaunchRestriction = $CurrentDCOMSDDLMachineLaunchRestriction.SDDL += "(" + $DCOMSDDLMachineLaunchRestriction + ")"
     }
  
     if (($CurrentDCOMSDDLMachineAccessRestriction.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLMachineAccessRestriction.SDDL -notmatch $DCOMSDDLMachineAccessRestriction))
     {
      $NewDCOMSDDLMachineAccessRestriction = $CurrentDCOMSDDLMachineAccessRestriction.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLMachineLaunchRestriction
     }
     else
     {
       $NewDCOMSDDLMachineAccessRestriction = $CurrentDCOMSDDLMachineAccessRestriction.SDDL += "(" + $DCOMSDDLMachineAccessRestriction + ")"
     }

     if (($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -notmatch $DCOMSDDLDefaultLaunchPermission))
     {
       $NewDCOMSDDLDefaultLaunchPermission = $CurrentDCOMSDDLDefaultLaunchPermission.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLDefaultLaunchPermission
     }
     else
     {
       $NewDCOMSDDLDefaultLaunchPermission = $CurrentDCOMSDDLDefaultLaunchPermission.SDDL += "(" + $DCOMSDDLDefaultLaunchPermission + ")"
     }

     if (($CurrentDCOMSDDLDefaultAccessPermission.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLDefaultAccessPermission.SDDL -notmatch $DCOMSDDLDefaultAccessPermision))
     {
       $NewDCOMSDDLDefaultAccessPermission = $CurrentDCOMSDDLDefaultAccessPermission.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLDefaultAccessPermision
     }
     else
     {
       $NewDCOMSDDLDefaultAccessPermission = $CurrentDCOMSDDLDefaultAccessPermission.SDDL += "(" + $DCOMSDDLDefaultAccessPermision + ")"
     }

     # Convert SDDL back to Binary
     write-host "`tConverting SDDL back into binary form..."
     $DCOMbinarySDMachineLaunchRestriction = $converter.SDDLToBinarySD($NewDCOMSDDLMachineLaunchRestriction)
     $DCOMconvertedPermissionsMachineLaunchRestriction = ,$DCOMbinarySDMachineLaunchRestriction.BinarySD

     $DCOMbinarySDMachineAccessRestriction = $converter.SDDLToBinarySD($NewDCOMSDDLMachineAccessRestriction)
     $DCOMconvertedPermissionsMachineAccessRestriction = ,$DCOMbinarySDMachineAccessRestriction.BinarySD

     $DCOMbinarySDDefaultLaunchPermission = $converter.SDDLToBinarySD($NewDCOMSDDLDefaultLaunchPermission)
     $DCOMconvertedPermissionDefaultLaunchPermission = ,$DCOMbinarySDDefaultLaunchPermission.BinarySD

     $DCOMbinarySDDefaultAccessPermission = $converter.SDDLToBinarySD($NewDCOMSDDLDefaultAccessPermission)
     $DCOMconvertedPermissionsDefaultAccessPermission = ,$DCOMbinarySDDefaultAccessPermission.BinarySD

     # Apply the changes
     write-host "`tApplying changes..."
     if ($CurrentDCOMSDDLMachineLaunchRestriction.SDDL -match $DCOMSDDLMachineLaunchRestriction)
     {
       write-host "`t`tCurrent MachineLaunchRestriction matches desired value."
     }
     else
     {
       $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction", $DCOMbinarySDMachineLaunchRestriction.binarySD)
       if($result.ReturnValue='0'){write-host "  Applied MachineLaunchRestricition complete."}
     }

     if ($CurrentDCOMSDDLMachineAccessRestriction.SDDL -match $DCOMSDDLMachineAccessRestriction)
     {
       write-host "`t`tCurrent MachineAccessRestriction matches desired value."
     }
     else
     {
       $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction", $DCOMbinarySDMachineAccessRestriction.binarySD)
       if($result.ReturnValue='0'){write-host "  Applied MachineAccessRestricition complete."}
     }

     if ($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -match $DCOMSDDLDefaultLaunchPermission)
     {
       write-host "`t`tCurrent DefaultLaunchPermission matches desired value."
     }
     else
     {
       $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission", $DCOMbinarySDDefaultLaunchPermission.binarySD)
       if($result.ReturnValue='0'){write-host "  Applied DefaultLaunchPermission complete."}
     }

     if ($CurrentDCOMSDDLDefaultAccessPermission.SDDL -match $DCOMSDDLDefaultAccessPermision)
     {
       write-host "`t`tCurrent DefaultAccessPermission matches desired value."
     }
     else
     {
       $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission", $DCOMbinarySDDefaultAccessPermission.binarySD)
       if($result.ReturnValue='0'){write-host "  Applied DefaultAccessPermission complete."}

     }
    }
    #----------------------------------------------------------------------------------------------------------
     trap 
     { 
     $exMessage = $_.Exception.Message
     if($exMessage.StartsWith("L:"))
     {write-host "`n" $exMessage.substring(2) "`n" -foregroundcolor white -backgroundcolor darkblue}
     else {write-host "`nError: " $exMessage "`n" -foregroundcolor white -backgroundcolor darkred}
     Exit
     }
    #----------------------------------------------------------------------------------------------------------
}