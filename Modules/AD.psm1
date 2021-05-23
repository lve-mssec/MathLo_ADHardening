Function Install-ADDS
{
    <# 
        .Synopsis
         Configure a new forest on the server.

        .Description
         Perform a new forest installation on the server.

        .Parameter Config
         All settings to configure the new forest.

        .Notes
         Version 01.00: 30/08/2019. 
               History: Function creation.
    #>
    Param(
        # Collect the Bundle to be checked for
        [Parameter(Mandatory=$true)]
        [object]
        $Config
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

   ## Start Debug Trace
   $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
   $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
   $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

   ## Indicates caller and options used
   $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
   $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter CONFIG.........: $Config"

    ## 1.Initialize verbose output for follow-up
    write-logInfo -LogMessage '`(*`) `[.START.`]`(:`)`[ New AD Forest installation`]' -ToScreen
    
    ## 2.Check if the server is not already a domain member (it is a new forest)
    write-logInfo -LogMessage '`(* .......: `)server''s domain membership (checking)' -ToScreen
    $Flag = $false
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter FLAG...........: $Flag"

    Try   { $InstalledForest = Get-ADForest $Config["FOREST"]["ForestName"] }
    Catch { $InstalledForest = $null }
    
	if ($InstalledForest)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> a forest has been detected"
        
        $check = $InstalledForest.Name -eq $Config["DOMAIN"]["DomainName"]
        
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter CHECK..........: $Check"
        
        if (!($check))
        {
            write-logInfo -LogMessage '`(* .......: `)server''s domain membership (`{test''s ko`})' -ToScreen
            $Flag = $true    
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter FLAG...........: $Flag"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> The forest is not the one expected: error."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> debug value: INSTALLEDFOREST.NAME......=" + $InstalledForest.Name
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> debug value: CONFIG[DOMAIN][DOMAINNAME]=" + $Config["DOMAIN"]["DomainName"]
        }
        else
        {
            write-logInfo -LogMessage '`(* .......: `)server''s domain membership (test ok)' -ToScreen
            $test = 0
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter TEST...........: $Test"
        }
    }
    else 
    {
        write-logInfo -LogMessage '`(* .......: `)server''s domain membership (test ok)' -ToScreen    
        $test = 1
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter TEST...........: $Test"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> The forest will be installed."
}

    if (!($Flag))
    {
        write-logInfo -LogMessage '`(* .......: `)run installation command (start)' -ToScreen
        if ($test -gt 0)
        {
            #.Debug Message with ini content to ensure a proper reading was done.
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Start installation."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] [INSTALL]"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] CreateDnsDelegation..........:" + $Config["INSTALL"]["CreateDnsDelegation"] 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] NoRebootOnCompletion.........:" + $Config["INSTALL"]["NoRebootOnCompletion"] 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] SafeModeAdministratorPassword:" + $Config["INSTALL"]["AdminPassword"]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] InstallDns...................:" + $Config["INSTALL"]["InstallDNS"] 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] [FOREST]"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] ForestMode...................: " + $Config["FOREST"]["ForestMode"]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] ForestName...................: " + $Config["FOREST"]["ForestName"]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] [DOMAIN]"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] DomainMode...................: " + $Config["DOMAIN"]["DomainMode"]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] DomainName...................: " + $Config["DOMAIN"]["DomainName"]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] DomainNetbiosName............: " + $Config["DOMAIN"]["NtBiosName"]

            Try     
            {
                
                #PrepareOption
				if ( $Config["INSTALL"]["CreateDnsDelegation"]  -eq "true") { $CDD = $True } else { $CDD = $FALSE }
				if ( $Config["INSTALL"]["InstallDNS"]           -eq "true") { $IDS = $True } else { $IDS = $FALSE }
				if ( $Config["INSTALL"]["NoRebootOnCompletion"] -eq "true") { $NRC = $True } else { $NRC = $FALSE }
								
				$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> [DEBUG] CMD=install-addsForest -CreateDnsDelegation:$" + $CDD `
                                                               + " -DomainMode " + $Config["DOMAIN"]["DomainMode"] `
                                                               + " -DomainName " + $Config["DOMAIN"]["DomainName"] `
                                                               + " -DomainNetbiosName " + $Config["DOMAIN"]["NtBiosName"] `
                                                               + " -ForestMode " + $Config["FOREST"]["ForestMode"] `
                                                               + " -InstallDns:$" + $IDS `
                                                               + " -NoRebootOnCompletion:$" + $NRC `
                                                               + ' -Force:$True' `
                                                               + " -SafeModeAdministratorPassword (ConvertTo-SecureString -string " + $Config["INSTALL"]["AdminPassword"] + " -AsPlainText -Force)" `
                                                               + " -SkipPreChecks"

                
				$NoEcho = install-addsForest -CreateDnsDelegation:$CDD `
                                             -DomainMode $Config["DOMAIN"]["DomainMode"] `
                                             -DomainName $Config["DOMAIN"]["DomainName"] `
                                             -DomainNetbiosName $Config["DOMAIN"]["NtBiosName"] `
                                             -ForestMode $Config["FOREST"]["ForestMode"] `
                                             -InstallDns:$IDS `
                                             -NoRebootOnCompletion:$NRC `
                                             -Force:$True `
                                             -SafeModeAdministratorPassword (ConvertTo-SecureString -String $Config["INSTALL"]["AdminPassword"] -AsPlainText -Force) `
                                             -SkipPreChecks `
											 -WarningAction SilentlyContinue
											 
                write-logInfo -LogMessage '`(* .......: `)command executed with success' -ToScreen
            }#.End Try

            Catch  
            {
				$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> installation has failed."
                write-logInfo -LogMessage '`(* .......: `)command failed to execute' -ToScreen
                $flag = $true
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter FLAG...........: $flag"
            }#.End Catch
        }
        else 
        {
            write-logInfo -LogMessage '`(* .......: `)the requested forest is already installed' -ToScreen
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> The forest is the one expected : no installation to perform."
        }
        write-logInfo -LogMessage '`(* .......: `)run installation command (finish)' -ToScreen
        write-logInfo -LogMessage '`(*`) `[..END..`]`(:`)`[ New AD Forest installation`]' -ToScreen
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> installation done."
    }

    ## Finally append debug log execution to a rotative one. We'll keep only last 1000 lines as history.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    if ($Flag) { $result = $false } else { $result = $true }

    return $result
}

Function Switch-ADRecycleBin
{
    <#
        .Synopsis
         Enable the Recycle Bin, or ensure it is so.
        
        .Description
         Will perform a query to ensure that the AD Recycle Bin is enable. If not, it will do so if requested.
         Return TRUE if the states is as expected, else return FALSE.
        
        .Parameter DesiredState
         choose one of the two values (enable,disable).

        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         history: 19.08.31 Script creation
    #>
    param(
        # State of AD Recycle Bin
        [Parameter(Mandatory=$true)]
        [ValidateSet("ENABLE","DISABLE")]
        [String]
        $DesiredState
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DESIREDSTATE...: $DesiredState"

    ## Test Options current settings
    if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is already enabled"
        $result = $true
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is not enabled yet"
        
        if ($DesiredState -eq "ENABLE")
        {
            Try 
            {
                $NoEchoe = Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -WarningAction SilentlyContinue -Confirm:$false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target " + (Get-ADForest).Name + ' -WarningAction SilentlyContinue -Confirm:$false'
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is enabled"
                $result = $true
            }
            catch 
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while configuring the active directory Recycle Bin"
                $result = $false
            }
        }
    }

    ##Ensure result is as expected
    if ($result -ne $DesiredState)
    {
        switch ($result)
        {
            $true  {$compl = "is enabled" }
            $false {$compl = "is disabled"}
        }
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: the active directory Recycle Bin $compl but the expected status was $DesiredState"
        $result = $false
    }    
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Switch-GpoCentralStore
{
    <#
        .Synopsis
         Enable the Centralized GPO repository (aka Central Store), or ensure it is so.
        
        .Description
         Will perform a query to ensure that the GPO Central Store is enable. If not, it will do so if requested.
         Return TRUE if the states is as expected, else return FALSE.
        
        .Parameter DesiredState
         choose one of the two values (enable,disable).

        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         history: 19.08.31 Script creation
    #>
    param(
        # State of AD Recycle Bin
        [Parameter(Mandatory=$true)]
        [ValidateSet("ENABLE","DISABLE")]
        [String]
        $DesiredState
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DESIREDSTATE...: $DesiredState"
    
    ## Test if already enabled
    if (Test-Path "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions") 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is present"
        ## compare with current state
        if ($DesiredState -eq "ENABLE")
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is enabled as requested"
            $result = $true
        }
        else 
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: Central Store path is enabled but this shouldn't be!"
            $result = $false    
        }
    }
    else 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is not enable yet"
        ## Check if installation is needed
        if ($DesiredState -eq "ENABLE")
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions /MIR (start)"
                       $NoEchoe = Robocopy "C:\Windows\PolicyDefinitions" "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions" /MIR
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions /MIR (finish)"
            if ((Get-ChildItem "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions" -Recurse).count -gt 10)
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Seems copying has worked."
                $result = $true
            }
            else 
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying file."
                $result = $false    
            }
        }

        $result = $true

    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Switch-InstantReplication
{
    <#
        .Synopsis
         Enable the Immediate Replication, or ensure it is so.
        
        .Description
         Enable the Immediate Replication, or ensure it is so.
         Return TRUE if the states is as expected, else return FALSE.
        
        .Parameter DesiredState
         choose one of the two values (enable,disable).

        .Notes
         Version: 
            01.00 -- Loic.veirman@mssec.fr
            01.01 -- Loic.veirman@mssec.fr
         history: 
            01.00 -- Script creation
            01.01 -- Fix replink auto discver
    #>
    param(
        # State of AD Recycle Bin
        [Parameter(Mandatory=$true)]
        [ValidateSet("ENABLE","DISABLE")]
        [String]
        $DesiredState
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DESIREDSTATE...: $DesiredState"
    
    ## Test if already enabled
    if ($DesiredState -eq "ENABLE")
    {
        #.List of rep link
        $RepSiteLinks = Get-ADReplicationSiteLink -Filter * 

        #.For each of them...
        foreach ($RepSiteLink in $RepSiteLinks)
        {
            #.Check if already enabled.
            if ((Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options) 
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options are already enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                $Result = $true
            } 
            Else 
            {
                try
                {
                    $NoEchoe = Set-ADReplicationSiteLink $RepSiteLink -Replace @{'Options'=1} -WarningAction SilentlyContinue
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options is now enabled with value " + (Get-ADReplicationSiteLink DEFAULTIPSITELINK -Properties *).options + " for " + $RepSiteLink.Name
                    $Result = $true
                }
                Catch
                {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Urgent Replication failed to be enabled with value 1 for " + $RepSiteLink.Name
                    $Result = $False
                }
            }
        }
    } 
    Else 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication will not be modified"
        $Result = $true
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function New-ProvisioningOU
{
    <#
        .Synopsis
         Create the an OU to provision new objects.
        
        .Description
         Create the requiered OU to provision new objects and apply them minimal security settings per GPO.
        
        .Parameter RootOU
         Name of the OU to be created at the domain root level.
        
        .Parameter CptrOU
         Name of the child OU under the root provisioning OU that will host new computer objects.
         If empty: the OU will not be created and the default provisioning OU will be the RootOU.
         
        .Parameter UserOU
         Name of the child OU under the root provisioning OU that will host new user objects.
         If empty: the OU will not be created and the default provisioning OU will be the RootOU.

        .Parameter RootDS
         Description to add to the provisioning OU ROOT.        

         .Parameter CptrDS
         Description to add to the provisioning OU COMPUTER.        
         
        .Parameter UserDS
         Description to add to the provisioning OU USER.        

         .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         history: 19.09.06 Script creation
    #>
    param(
        [String]$RootOU,
        [String]$CptrOU,
        [String]$UserOU,
        [String]$RootDS,
        [String]$CptrDS,
        [String]$UserDS
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ROOTOU.........: $RootOU"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ROOTDS.........: $RootDS"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter CPTROU.........: $CptrOU"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter CPTRDS.........: $CptrDS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter USEROU.........: $UserOU"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter USERDS.........: $UserDS"    

    ## Variable to increment at each OU creation
    $Success = 0
    
    ## Begin with Root OU generation
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---[ Begin Root Provisioning OU creation ]"
    if (!($rootOU)) { 
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------! ERROR: the RootOU parameter has no value!"
        $Result = $false 
    } else {
        Try {
            $test = Get-ADOrganizationalUnit ('OU=' + $RootOU + ',' + (Get-ADDomain).DistinguishedName)
        } Catch {
            $test = $null
        }
        if ($test) {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the root OU for provisioning already exists"

            $Success++
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"

            $RootOUDN = 'OU=' + $RootOU + ',' + (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter ROOTOUDN....: $RootOUDN"

        } Else {
            
            try {
                $NoEcho = New-ADOrganizationalUnit -Name $RootOU `
                                                   -Description $RootDS `
                                                   -Path (Get-ADDomain).DistinguishedName `
                                                   -ErrorAction SilentlyContinue `
                                                   -WarningAction SilentlyContinue

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the root OU for provisioning has been created"
                
                $Success++
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"

                $RootOUDN = 'OU=' + $RootOU + ',' + (Get-ADDomain).DistinguishedName
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter ROOTOUDN....: $RootOUDN"

            } Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Failure...............: the root OU for provisioning has not been created"
                $Result = $false 
            }
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---[  End Root Provisioning OU creation  ]"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---[  Begin Child Provisioning creation  ]"

    if ($Success -eq 1) {
        ## Create Computer OU as child.
        if ($CptrOU) {
            Try {
                $test = Get-ADOrganizationalUnit ('OU=' + $CptrOU + ',' + $RootOUDN)
            } Catch {
                $test = $null
            }
            if ($test) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the child OU for provisioning computers already exists"
    
                $Success++
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"
    
                $NewCptrOU = Get-ADOrganizationalUnit ('OU=' + $CptrOU + ',' + $RootOUDN)
                $NoEcho = redircmp $NewCptrOU
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Default Computer OU...: $NewCptrOU"
    
            } Else {
                
                try {
                    $NoEcho = New-ADOrganizationalUnit -Name $CptrOU `
                                                       -Description $CptrDS `
                                                       -Path $RootOUDN `
                                                       -ErrorAction SilentlyContinue `
                                                       -WarningAction SilentlyContinue
    
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the child OU for provisioning computers has been created"
                    
                    $Success++
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"

                    $NewCptrOU = Get-ADOrganizationalUnit ('OU=' + $CptrOU + ',' + $RootOUDN)
                    $NoEcho = redircmp $NewCptrOU
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Default Computer OU...: $NewCptrOU"
    
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Failure...............: the child OU for provisioning computers has not been created"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"
                }
            }
        } else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: no child OU for provisioning computers to be created"
            $Success++
        }

        ## Create User OU as child.
        if ($UserOU) {
            Try {
                $test = Get-ADOrganizationalUnit ('OU=' + $UserOU + ',' + $RootOUDN)
            } Catch {
                $test = $null
            }
            if ($test)  {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the child OU for provisioning users already exists"
    
                $Success++
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"

                $NewUserOU = Get-ADOrganizationalUnit ('OU=' + $UserOU + ',' + $RootOUDN)
                $NoEcho = redirusr $NewUserOU
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Default User OU.......: $NewUserOU"
    
            } Else {
                
                try {
                    $NoEcho = New-ADOrganizationalUnit -Name $UserOU `
                                                       -Description $UserDS `
                                                       -Path $RootOUDN `
                                                       -ErrorAction SilentlyContinue `
                                                       -WarningAction SilentlyContinue
    
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: the child OU for provisioning users has been created"
                    
                    $Success++
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"

                    $NewUserOU = Get-ADOrganizationalUnit ('OU=' + $UserOU + ',' + $RootOUDN)
                    $NoEcho = redirusr $NewUserOU
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Default User OU.......: $NewUserOU"
    
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Failure...............: the child OU for provisioning users has not been created"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"
                }
            }
        } else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Success...............: no child OU for provisioning users to be created"
            $Success++
        }
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------! ERROR: the function could not continue and will break."
        $Success++
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Parameter SUCCESS.....: $Success"
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---[   End Child Provisioning creation   ]"

    if ($Success -eq 3) { $Result = $true } else {$Result = $false }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function New-AdvceOUtree
{
    <#
        .Synopsis
            Create OU tree as specified in the reference inputs.
        
        .Description
            Create OU tree as specified in the reference inputs.
        
        .Parameter OUData
            Array contening the OU list. THe input include an index and a list of OU (name,class and version)

            .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 19.09.21 Script creation
    #>
    param(
        $OUData,
        $BasePath
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUData.........: $OUData"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter BasePath.......: $BasePath"    

    ## Get index to follow OU creation
    [int]$LastIndex = $OUData['Index']
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LastIndex......: $LastIndex"

    ## Import xml file with OU build requierment
    Try { 
        [xml]$xmlSkeleton = Get-Content ("$BasePath\Configs\" + $OUData['xml'])
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: " + $OUData['xml']
        $Result = $true

    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file " + $OUData['xml']
        $Result = $false
    }

    if ($Result) {
        ## The xml file was loaded sucessfully, starting the OU creation loop
        $NoError = $True
        $DomainRootDN = (Get-ADDomain).DistinguishedName
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"
        
        for ($index = 1 ; $index -le $LastIndex ; $index++) {
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> NEW INDEX.............: $index"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU DATA............: " + $OUData["$index"]
            
            $OUName = ($OUData["$index"] -split ",")[0]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Name............: $OUName"
            
            $OUClas = ($OUData["$index"] -split ",")[1]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Class...........: $OUClas"
            
            $OUDesc = ($OUData["$index"] -split ",")[2]
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: $OUDesc"

            ## on retrouve le modele demandé dans le fichier xml
            $xmlData = $xmlSkeleton.ouTree.OU | Where-Object { $_.class -eq $OUClas }

            ## Si le modele est trouvé, on vérifie que l'OU parente n'existe pas, sinon on la créée.
            if ($xmlData) {
                ## Test de présence de l'OU
                Try {
                    $NoEchoe = Get-ADOrganizationalUnit "OU=$OUName,$DomainRootDN"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: Already Exists (skipped)"
                    $NoEchoe = Set-ADOrganizationalUnit "OU=$OUName,$DomainRootDN" -Description $OUDesc
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: Updated to $OUDesc"
                ## Test échoue : création de l'OU
                } Catch {
                    $NoEchoe = New-ADOrganizationalUnit $OUName -Path $DomainRootDN -Description $OUDesc
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: Success"
                }
                ## Une fois l'OU créée, on appelle la fonction récursive qui va créer les OU filles.
                ## Cette fonction est particulière car elle renvoie le log de fonction en retour.
                $MyOUs   = $xmlData.ChildOU

                foreach ($myOU in $myOUs) {
                    Try {
                        $NoEchoe = Get-ADOrganizationalUnit ("OU=" + $myOU.Name + ",OU=$OUName,$DomainRootDN")
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: " + $myOU.Name + ": Already Exists (skipped)"
                        $NoEchoe = Set-ADOrganizationalUnit ("OU=" + $myOU.Name + ",OU=$OUName,$DomainRootDN") -Description $myOU.Description
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: " + $myOU.Name + ": Updated to " + $myOU.Description
                    ## Test échoue : création de l'OU
                    } Catch {
                        $NoEchoe = New-ADOrganizationalUnit $myOU.Name -Path "OU=$OUName,$DomainRootDN" -Description $myOU.Description
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: " + $myOU.Name + ": Success"
                    }

                    ## Hop, here goes the infinite loop!
                    $myChildOUs = $myOU.childOU
                    if ($myChildOUs) {  
                        foreach ($ChildOU in $myChildOUs) {
                            $dbgMess += New-ChildOU -ChildOU $ChildOU -ParentOU ("OU=" + $MyOU.Name + ",OU=$OUName,$DomainRootDN")
                        }
                    }
                }

                #$dbgMess += New-ChildOUTree -OUData $xmlData -PArentOU "OU=$OUName,$DomainRootDN"

            } else {
                ## pas de données ! On quitte et on l'indique dans le log de debug.
                $NoError = $False
                $index = $LastIndex + 10
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------! Error! the requested Class/version isn't present in the xml file."
            }
        }
    } 
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $NoError
}

Function New-ChildOU
{
    <#
        .Synopsis
         Create OU tree as specified in the reference inputs.
            
        .Description
         Create OU tree as specified in the reference inputs.
            
        .Parameter OUData
            Array contening the OU list. THe input include an index and a list of OU (name,class and version)

            .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 19.09.21 Script creation
    #>
    param(
        $ChildOU,
        [string]$ParentOU 
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ChildOU........: $ChildOU"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ParentOU.......: $ParentOU"   

    Try {
        ## on test si l'ou existe deja
        $NoEchoe = Get-ADOrganizationalUnit ("OU=" + $ChildOU.Name + ",$ParentOU")
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OU Creation........: " + $ChildOU.Name + ": Already Exists (skipped)"

        $NoEchoe = Set-ADOrganizationalUnit ("OU=" + $ChildOU.Name + ",$ParentOU") -Description $ChildOU.Description
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OU Description.....: " + $ChildOU.Name + ": Updated to " + $ChildOU.Description

    } Catch {
        ## Test échoue : création de l'OU
        $NoEchoe = New-ADOrganizationalUnit $ChildOU.Name -Path "$ParentOU" -Description $ChildOU.Description
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "----> OU Creation........: " + $ChildOU.Name + ": Success"
    }                
            
    ## On verifie si des sous-ou existent
    $myChildOUs = $ChildOU.childOU
    if ($myChildOUs) {  
        foreach ($myChildOU in $myChildOUs) {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OU Child Tree......: Child Tree detected"
            $DbgMess += New-ChildOU -ChildOU $myChildOU -ParentOU $("OU=" + $ChildOU.Name + ",$ParentOU")
        }
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OU Child Tree......: No Child Tree detected"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    return ((Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Tree Creation.......: " + $myOU.Name + ": Success")
}

Function New-OUtree
{
    <#
        .Synopsis
            Create an OU tree as specified in the reference inputs.
        
        .Description
            Create an OU tree as specified in the reference inputs. Requires Manual input.
        
        .Parameter OUData
            Array contening the OU list. THe input include an index and a list of OU (name,class and version)

            .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 19.09.21 Script creation
    #>
    param(
        [Parameter(mandatory=$true)]
        [String]
        $OUName,

        [Parameter(mandatory=$true)]
        [String]
        $OUClas,

        [Parameter(mandatory=$true)]
        [String]
        $OUDesc,

        [Parameter(mandatory=$true)]
        [String]
        $OUXml,
                
        [Parameter(mandatory=$true)]
        [String]
        $BasePath
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUData.........: $OUName"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUClas.........: $OUClas"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUDesc.........: $OUDesc"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUXml..........: $OUXml"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter BasePath.......: $BasePath"    

    ## Import xml file with OU build requierment
    Try { 
        [xml]$xmlSkeleton = Get-Content ("$BasePath\Configs\" + $OUXml)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: " + $OUXml
        $Result = $true

    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file " + $OUXml
        $Result = $false
    }

    if ($Result) {
        ## The xml file was loaded sucessfully, starting the OU creation loop
        $NoError = $True
        $DomainRootDN = (Get-ADDomain).DistinguishedName
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"
        
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Name............: $OUName"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Class...........: $OUClas"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: $OUDesc"

        ## on retrouve le modele demandé dans le fichier xml
        $xmlData = $xmlSkeleton.ouTree.OU | Where-Object { $_.class -eq $OUClas }

       ## Si le modele est trouvé, on vérifie que l'OU parente n'existe pas, sinon on la créée.
       if ($xmlData) {
            ## Test de présence de l'OU
            Try {
                    $NoEchoe = Get-ADOrganizationalUnit "OU=$OUName,$DomainRootDN"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: Already Exists (skipped)"
                    $NoEchoe = Set-ADOrganizationalUnit "OU=$OUName,$DomainRootDN" -Description $OUDesc
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: Updated to $OUDesc"
            ## Test échoue : création de l'OU
            } Catch {
                    $NoEchoe = New-ADOrganizationalUnit $OUName -Path $DomainRootDN -Description $OUDesc
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: Success"
            }
            ## Une fois l'OU créée, on appelle la fonction récursive qui va créer les OU filles.
            ## Cette fonction est particulière car elle renvoie le log de fonction en retour.
            $MyOUs   = $xmlData.ChildOU

           foreach ($myOU in $myOUs) {
                    Try {
                        $NoEchoe = Get-ADOrganizationalUnit ("OU=" + $myOU.Name + ",OU=$OUName,$DomainRootDN")
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: " + $myOU.Name + ": Already Exists (skipped)"
                        $NoEchoe = Set-ADOrganizationalUnit ("OU=" + $myOU.Name + ",OU=$OUName,$DomainRootDN") -Description $myOU.Description
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Description.....: " + $myOU.Name + ": Updated to " + $myOU.Description
                    ## Test échoue : création de l'OU
                    } Catch {
                        $NoEchoe = New-ADOrganizationalUnit $myOU.Name -Path "OU=$OUName,$DomainRootDN" -Description $myOU.Description
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> OU Creation........: " + $myOU.Name + ": Success"
                    }

                    ## Hop, here goes the infinite loop!
                    $myChildOUs = $myOU.childOU
                    if ($myChildOUs) {  
                        foreach ($ChildOU in $myChildOUs) {
                            $dbgMess += New-ChildOU -ChildOU $ChildOU -ParentOU ("OU=" + $MyOU.Name + ",OU=$OUName,$DomainRootDN")
                        }
                    }
                }

        } else {
            ## pas de données ! On quitte et on l'indique dans le log de debug.
            $NoError = $False
            #$index = $LastIndex + 10
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------! Error! the requested Class/version isn't present in the xml file."
        }
    }
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $NoError
}

function New-AdminAccounts
{
   <#
        .Synopsis
            Create Users based on file input.
        
        .Description
            Required: an ini file with all acounts.
        
        .Parameter accountType
            SA ou A.
        
        .Parameter iniFile
            Name of the ini file with accounts to deal on. the file have to be placed in .\Inputs\.

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.08 Script creation
    #>
    param(
        [Parameter(mandatory=$true)]
        [ValidateSet('SA','A')]
        [String]
        $accountType,

        [Parameter(mandatory=$true)]
        [String]
        $iniFile
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter AccountType....: $AccountType"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter iniFile........: $iniFile"    

    ## Try to load the ini files
    $noError = $true
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> set [noError] to TRUE"    

    Try   {
            $iniData = import-ini .\Inputs\$iniFile
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> inmport iniFile..........: success"    
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> inmport iniFile..........: error"    
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> set [noError] to FALSE"    
            $noError = $false
          }

    ## if ini file loaded successfully, we will start at creating accounts.
    ## Password will be randomly generated and written down to a file.
    if ($noError)
    {
        $index  = $iniData["$AccountType"]["index"]
        $BaseDN = $iniData["$AccountType"]["BaseDN"] + (Get-ADDomain).DistinguishedName
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Begin account loop creation: found $index accounts in ini file"   
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Accounts will be created in $BaseDN"   

        for ($i = 1 ; $i -le $index ; $i++)
        {
            $AccData = $iniData["$AccountType"]["$i"] -split ";"

            ## Test if user exists.
            Try   { 
                    $test = Get-ADUser $AccData[0]
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + ("---> " + $AccData[0] + ": already exists (no action)")
                  }
            Catch {
                    $test = $null
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + ("---> " + $AccData[0] + ": check ok - the user does not exists")
                  }

            ## if user not exist, create it.
            if (!($test))
            {
                Try   {
                        $tmpPwd = New-Password -Length 14
                        $result = New-ADUser -SamAccountName $AccData[0] -GivenName $AccData[1] -Surname $AccData[2] `
                                             -Enabled $true -Description $AccData[3] -DisplayName ($AccData[1] + " " + $AccData[2]) `
                                             -Name ($AccData[1] + " " + $AccData[2]) -AccountNotDelegated $true `
                                             -UserPrincipalName ($AccData[0] + '@' + (Get-ADDomain).DNSRoot) `
                                             -AccountPassword (ConvertTo-SecureString -AsPlainText -Force $tmpPwd) `
                                             -Path $BaseDN -ErrorAction Stop
                        
                        ## This should not be logged in log file.
                        ($AccData[0] + "`t" + $tmpPwd) | out-file .\Outputs\Accounts.txt -Encoding utf8 -Append
            
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + ("---> " + $AccData[0] + ": successfully created")
                      }
                Catch {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + ("---> " + $AccData[0] + ": creation failed. Message: " + $Error[0].Exception )
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> set [noError] to FALSE"  
                        $noError = $false

                      }
            }
        }
    }
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return NOERROR: $noError"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $NoError
}

function New-AADCSyncOU
{
   <#
        .Synopsis
            Create OU named Synchronisation AAD.
        
        .Description
            Search upon OU containing Users, Groups or Computers object: if found, create the OU. Will discard the Administration OU.
        
        .Parameter AdminOUName
            Name of the admin OU: act as a filter to exclude.
        
        .Parameter Simulate
            If specified, the script will output all the OUs it should normally have generated (.\Outputs\AADCSyncOU.csv).

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.08 Script creation
    #>
    param(
        [Parameter(mandatory=$true)]
        [String]
        $AdminOUName,

        [Parameter(mandatory=$false)]
        [String]
        $Simulate
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter AdminOUName....: $AdminOUName"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter Simulate.......: $Simulate"    

    ## Generate Simulate log
    if ($Simulate -ne "") { $simulog = @() ; $Simulate = $true } else { $Simulate = $false }
    
    ## Grab first level OU list and filter admin + dc OUs
    $OULevel1 = Get-ADOrganizationalUnit -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel `
                                         -Filter { Name -ne $AdminOUname -and Name -ne 'Domain Controllers' } 

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> found " + $OULevel1.Count + " to analyze"
    
    ## Parsing OU...
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Begin Parsing:"
    foreach ($OU in $OULevel1)
    {
       $result = Find-OUwithObjects -ObjectClass Any -BaseDN $OU.DistinguishedName
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Find-SpecialObjects
{
       <#
        .Synopsis
            Search specific objects in an OU.
        
        .Description
            Search upon Users, Groups or Computers object: if found, return true.
        
        .Parameter BaseDN
            BaseDN where to look at.

        .Parameter ObjectClass
            User, Computer or Group.
        
        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.08 Script creation
        #>

    param(
        [Parameter(mandatory=$true)]
        [ValidateSet('User','Computer','Group','Any')]
        [String]
        $ObjectClass,

        [Parameter(mandatory=$True)]
        [string]
        $BaseDN
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectClass....: $ObjectClass"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter BaseDN.........: $BaseDN" 

    ## Search object...
    Switch ($ObjectClass)
    {
        'User'     { $test = Get-ADObject -Filter { ObjectClass -eq 'User' } -SearchBase $BaseDN -SearchScope OneLevel }
        'Computer' { $test = Get-ADObject -Filter { ObjectClass -eq 'Computer' } -SearchBase $BaseDN -SearchScope OneLevel }
        'Group'    { $test = Get-ADObject -Filter { ObjectClass -eq 'Group' } -SearchBase $BaseDN -SearchScope OneLevel }
        'Any'      { $test = Get-ADObject -Filter { ObjectClass -eq 'User' -or ObjectClass -eq 'Computer' -or ObjectClass -eq 'Group' } -SearchBase $BaseDN -SearchScope OneLevel }
    }

    if ($test)
    {
        ## Objects found
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Found objects: return TRUE" 
        $result = $true
    }
    else 
    {
        ## Objects not found
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Found objects: return FALSE" 
        $result = $false
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Find-OUwithObjects
{
    <#
        .Synopsis
            Search specific objects in an OU then searcg in OU tree beneath.
        
        .Description
            Search upon Users, Groups or Computers object: if found, return true.
        
        .Parameter BaseDN
            BaseDN where to look at.

        .Parameter ObjectClass
            User, Computer, Group or Any.
        
        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.08 Script creation
    #>

    param(
        [Parameter(mandatory=$true)]
        [ValidateSet('User','Computer','Group','Any')]
        [String]
        $ObjectClass,

        [Parameter(mandatory=$True)]
        [string]
        $BaseDN
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectClass....: $ObjectClass"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter BaseDN.........: $BaseDN" 

    ## Analyzing data
    $curDN = $BaseDN
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Analyzing: " + $curDN
    
    ## Looking for user, computer or group
    $asAnyOfThem = Find-SpecialObjects -BaseDN $curDN -ObjectClass Any
        
    if ($asAnyOfThem)
    {
        ## we found of one them
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Found objects! Creating OU."
        ## check if we are simulating
        if ($Simulate)
        {
            ## simulating: no action
            $simulog += New-Object -TypeName psobject -Property @{ OUName = $OU.Name ; NewChildOU = "OUSynchronisation AAD,$curDN" }
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Simulation: added to SIMULOG data."
        }
        else
        {
            ## not simulating: creating OU
            Try   {
                    New-ADOrganizationalUnit -Name "Synchronisation AAD" -Description "OU pour Synchro AzureAD" -DisplayName "Synchronisation AAD" -Path $curDN
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> OU created successfully."
                    $FlagSuccess = $true
                  }
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> OU creation failed."
                    $FlagFailure = $true
                  }
        }
    }
    ## Looking after childs OU
    $FindChilds = Get-ADOrganizationalUnit -SearchBase $BaseDN -SearchScope OneLevel -filter *

    if ($FindChilds) 
    {
          $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Found child(s) OU!"
          foreach ($Child in $FindChilds)
          {
            $result = Find-OUwithObjects -ObjectClass Any -BaseDN $Child.DistinguishedName
            Switch ($result) 
            { 
                0 { $FlagSuccess = $true } 
                1 { $FlagSuccess = $true ; $FlagFailure = $true }
                2 { $FlagFailure = $true }
            }
          }
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> No child OU."
    }
    ## Analyzing results
    if ($FlagSuccess -and  -not ($FlagFailure)) { $result = 0 }
    if ($FlagSuccess -and        $FlagFailure ) { $result = 1 }
    if (-Not ($FlagSuccess) -and $FlagFailure ) { $result = 2 }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

function New-AdminGroups
{
   <#
        .Synopsis
            Create admin groups in Administration OU.
        
        .Description
            Use files to list and create account. 
            .\inputs\Groupes_SMB.ini        : List of groups to be created
            .\inputs\Groupes-Membres_SMB.ini : List of groups members
        
        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.08 Script creation
    #>
    param(
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

    ## Loading ini file
    Try   {
            $iniGrp = import-ini -FilePath .\Inputs\Groupes_SMB.ini
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Loading Groups INI file..: success" 
            
            $iniMbr = Import-Ini -FilePath .\Inputs\Groupes-Membres_SMB.ini
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Loading Members INI file.: success"
            
            $TrapMe = $True
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Loading INI file has failed!"
            $TrapMe = $false
            $asFailed = $True
          }

     $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [TrapMe]:$TrapMe"

    ## Working if loading ini files was OK.
    if ($TrapMe)
    {
        $DomSID = (Get-ADDomain).DomainSID
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Domain SID: $DomSID"

        ## Creation Tier 0 groups
        $T0index = $iniGrp["GLOBAL"]["INDEXT0"]
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> INDEXT0: $T0index"

        for ($i = 1 ; $i -le $T0index ; $i++)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [i]: $i"
            $GrpData = $iniGrp["TIER0"]["$i"] -split ";"

            ## Test if group exists and, if not, create it.
            Try   {
                    $Grp = Get-ADGroup $GrpData[0] -ErrorAction Stop
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " already exists (skipped)"
                  }
            Catch {
                    New-ADGroup -Name $GrpData[0] -DisplayName $GrpData[0] -Description $GrpData[1] `
                                -GroupCategory Security -GroupScope Global -SamAccountName $GrpData[0]`
                                -Path ($iniGrp["GLOBAL"]["BASEDNT0"] + (Get-ADDomain).DistinguishedName) 

                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[1] + " created"
                  }
            
            ## Check Group Dependency
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group membership for " + $GrpData[2]
            if ($Group)
            {
                foreach ($Group in ($GrpData[2] -split ","))
                {
                    Switch ($Group)
                    {
                        ""      {}
                        Default {
                                    $GrpTranslated = $Group -Replace '%domSid%',$domSID
                                    $isMember = Get-ADGroupMember -Identity $GrpTranslated | Where-Object { $_.Name -eq $GrpData[0] }
                                    if ($isMember)
                                    {
                                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " is already member of $GrpTranslated"
                                    }
                                    else
                                    {
                                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " is not member of $GrpTranslated"
                    
                                        Try   { 
                                                Add-ADGroupMember -Identity $GrpTranslated -Members $GrpData[0]
                                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " has been added to $GrpTranslated"
                                              }
                                        Catch {
                                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + ": failed to add to $GrpTranslated!"
                                                $asFailed = $True
                                              }
                                    }
                                }
                    }
                }
            }
            else
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " has no group membership defined (skipped)."
            }

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> T0 - GroupDependency [asFailed]:$asFailed"

            ## Adding Group Members
            Try   {
                    if ($iniMbr[$GrpData[0]]["MEMBERS"] -ne "") { Add-ADGroupMember -Identity $GrpData[0] -Members ($iniMbr[$GrpData[0]]["MEMBERS"] -split ",") }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " now have for members " + $iniMbr[$GrpData[0]]["MEMBERS"]
                  }
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + ": failed to add members " + $iniMbr[$GrpData[0]]["MEMBERS"]
                    $asFailed = $true
                  }

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> T0 - Add Group Members [asFailed]:$asFailed"
        }

        ## Creation Tier 1 groups
        $T1index = $iniGrp["GLOBAL"]["INDEXT1"]
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> INDEXT1: $T1index"

        for ($i = 1 ; $i -le $T1index ; $i++)
        {
            $GrpData = $iniGrp["TIER1"]["$i"] -split ";"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [i]: $i"

            ## Test if group exists and, if not, create it.
            Try   {
                    $Grp = Get-ADGroup $GrpData[0] -ErrorAction Stop
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " already exists (skipped)"
                  }
            Catch {
                    New-ADGroup -Name $GrpData[0] -DisplayName $GrpData[0] -Description $GrpData[1] `
                                -GroupCategory Security -GroupScope Global -SamAccountName $GrpData[0]`
                                -Path ($iniGrp["GLOBAL"]["BASEDNT1"] + (Get-ADDomain).DistinguishedName) 

                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " created"
                  }
            
            ## Check Group Dependency
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group membership for " + $GrpData[2]
            if ($group) 
            {
                foreach ($Group in ($GrpData[2] -split ","))
                {
                    Switch ($Group)
                    {
                        ""      {}
                        Default {
                                    $isMember = Get-ADGroupMember $Group | Where-Object { $_.Name -eq $GrpData[0] }
                                    if ($isMember)
                                    {
                                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " is already member of $group"
                                    }
                                    else
                                    {
                                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " is not member of $group"
                    
                                        Try   { 
                                                Add-ADGroupMember -Identity $Group -Members $GrpData[0]
                                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " has been added to $Group"
                                              }
                                        Catch {
                                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + ": failed to add to $Group!"
                                                $asFailed = $True
                                              }
                                    }
                                }
                        }
                   }
            }
            else
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " has no group membership defined (skipped)."
            }

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> T1 - Group Dependency [asFailed]:$asFailed"

            ## Adding Group Members
            Try   {
                    if ($iniMbr[$GrpData[0]]["MEMBERS"] -ne "") {Add-ADGroupMember -Identity $GrpData[0] -Members ($iniMbr[$GrpData[0]]["MEMBERS"] -split ",") }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + " now have for members " + $iniMbr[$GrpData[0]]["MEMBERS"]
                  }
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group " + $GrpData[0] + ": failed to add members " + $iniMbr[$GrpData[0]]["MEMBERS"]
                    $asFailed = $true
                  }

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> T1 - Add Group Members [asFailed]:$asFailed"
        }


    }

    ## Managing result
    if ($asFailed) { $result = $false } else { $result = $True }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Set-UsersToGroup
{
    <#
        .Synopsis
            Search users based on a search criteria and add them to a specific group.
        
        .Description
            Use this function to add specific users to known groups, search A-XXX to GRP_ADMIN.
        
        .Parameter BaseDN
            BaseDN where to look at.

        .Parameter ObjectClass
            User, Computer, Group or Any.
        
        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.09 Script creation
    #>

    param(
        [Parameter(mandatory=$true)]
        [String]
        $UserMatchingPatern,

        [Parameter(mandatory=$True)]
        [string]
        $GroupName
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter UserMatchingPatern.: $UserMatchingPatern"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter GroupName..........: $GroupName" 

    ## Search users
    Try   {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Search samAccountName matching pattern $UserMatchingPatern" 
            $Users = Get-ADUser -Filter { samAccountName -like $UserMatchingPatern -and enabled -eq $true } -ErrorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Search samAccountName matching pattern returned " + $Users.count + " account(s)"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Search samAccountName matching pattern has failed!"
            $asFailed = $True
          } 
    
    ## Add users to group
    Try   {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> adding users to group $GroupName" 
            $null = Add-ADGroupMember -Identity $GroupName -Members $Users -ErrorAction Stop
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> adding users to group $GroupName has failed!" 
            $asFailed = $true
          }
    
    ## Manage results
    if ($asFailed) { $result = $false } else { $result = $true }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Function Clear-GroupMembers
{
     <#
        .Synopsis
            Remove all objects present in the Domain Admins group.
        
        .Description
            Security Measure: please modify the Sequence File to make this happen.
        
        .Parameter DsiAgreement
            YES if the DSI is informed and agreed.

        .Parameter GroupName
            Use to specify the group to be cleared.

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.09 Script creation
    #>

    param(
        [Parameter(mandatory=$true)]
        [String]
        $DsiAgreement,

        [Parameter(mandatory=$true)]
        [String]
        $GroupName
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DsiAgreement.......: $DsiAgreement"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter GroupName..........: $GroupName"    

    ## Switch DSI
    if ($DsiAgreement -eq 'YES')
    {
        ## Let's drop...
        Try   {
                $GroupName = $GroupName -replace "%domSid%",(Get-ADDomain).DomainSID.value
                $members = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
                $null = Remove-ADGroupMember -Identity $GroupName -Members $members -ErrorAction Stop -Confirm:$false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $GroupName has been flushed (" + $members.count + "object(s))"    
                $result = 0
              }
        Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $GroupName failed to be flushed!"    
                $result = 2
              }
    }
    else 
    {
        ## No Action, result is a warning
        $result = 1
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result   
}

Function Clear-BuiltinAdmin
{
     <#
        .Synopsis
            Disable builtin admin accounts, remove from all group and add it to enterprise admins.
        
        .Description
            Security Measure: please modify the Sequence File to make this happen.
        
        .Parameter DsiAgreement
            YES if the DSI is informed and agreed.

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.12 Script creation
    #>

    param(
        [Parameter(mandatory=$true)]
        [String]
        $DsiAgreement
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DsiAgreement.......: $DsiAgreement"    

    ## Check for DSI approval
    if ($DsiAgreement -eq 'yes')
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Action start: DSI has validated the change"    

        $noErr = 0

        ## Disable account
        Try   {
                Disable-ADAccount ((Get-ADDomain).DomainSID.value + "-500") -Confirm:$false -ErrorAction Stop
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Account BUILTIN\ADMINISTRATOR has been disabled" 
              }
        Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Account BUILTIN\ADMINISTRATOR could not be disabled!" 
                $noErr = 2
              }

        ## Remove from Domain Admin
        $isMbr = Get-ADGroupMember ((Get-ADDomain).DomainSID.value + "-512") | Where-Object { $_.Sid -eq ((Get-ADDomain).DomainSID.value + "-500") }

        if ($isMbr)
        {
            Try   {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> BUILTIN\ADMINISTRATOR is member of 'domain admins'" 
                    Remove-ADGroupMember ((Get-ADDomain).DomainSID.value + "-512") -Members ((Get-ADDomain).DomainSID.value + "-500") -Confirm:$false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> BUILTIN\ADMINISTRATOR has been removed from 'domain admins'" 
                  }
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> BUILTIN\ADMINISTRATOR failed to be removed from 'domain admins'!"
                    $noErr = 2
                  }
        }
        else
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> BUILTIN\ADMINISTRATOR is not member of 'domain admins' (ok)"
        }
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Action canceled: DSI has not validated the change"    
        $noErr = 1
    }
        
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $noErr"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $noErr
}

Function Set-msDSmachineAccountQuota
{
     <#
        .Synopsis
            Unallow users to add computers to the domain.
        
        .Description
            Security Measure: please modify the Sequence File to make this happen.
        
        .Parameter DsiAgreement
            YES if the DSI is informed and agreed.

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            history: 21.04.12 Script creation
    #>

    param(
        [Parameter(mandatory=$true)]
        [String]
        $DsiAgreement
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DsiAgreement.......: $DsiAgreement"    

    if ($DsiAgreement -eq 'Yes')
    {
      Try   {
                Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="0"}
                $result = 0
            }
      Catch {
                $result = 1
            }
    }
    Else 
    {
        $result = 1
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append

    return $result
}

Export-ModuleMember -Function *