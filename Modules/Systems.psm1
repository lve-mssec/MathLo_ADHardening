## This module contains functions related to Computer's System.

## Module Test-FeaturesBinaries
Function Test-FeaturesBinaries
{
    <# 
        .Synopsis
        Check if a role or feature has its binaries already installed on the system or not.

        .Description
        Check if a role or feature has its binaries already installed on the system or not.

        .Parameter Role
        Name of the binaries set to be checked.

        .Notes
        Version 01.00: 24/08/2019. 
            History: Function creation.
    #>
    Param(
        # Collect the Bundle to be checked for
        [Parameter(Mandatory=$true)]
        [ValidateSet('ADDS and DNS','ADDS and DNS Tools')]
        [String]
        $Role
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ROLE...........: $Role"

    ## BinaryRoles Library
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Building binaries library"
    $LibBinaries = @{
        'ADDS and DNS'=@('DNS','AD-Domain-Services')
        'ADDS and DNS Tools'=@('RSAT-ADDS','RSAT-AD-AdminCenter','RSAT-ADDS-Tools','RSAT-DNS-Server')
    }

    ## Check if roles are present
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Testing if " + ($LibBinaries[$Role] -split ",").count + " role(s) is/are found(s) installed"
    $RoleFound = Get-WindowsFeature -Name $LibBinaries[$Role] | Where-Object { $true -eq $_.installed }
    if (($LibBinaries[$Role] -split ",").count -eq $RoleFound.count)    
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> All role(s) was/were found(s)"
        $result = $true
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> One or more role(s) were missing. Failed."
        $result = $false
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $result #####"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    ## Return result
    return $result
}

Function Test-OSVersion
{
    <# 
        .Synopsis
        Check if the OS is as expected.

        .Description
        Based on input entries, the script will check if the OS version and type is as expected.

        .Parameter OSType
        Array of Regex to match the OS Type as returned by (Get-WindowsEdition -Online).Edition.

        .Parameter OSVersion
        Array of Regex to match the OS Version as returned by (Get-WmiObject Win32_OperatingSystem).Version.

        .Notes
        Version 01.00: 28/08/2019. 
            History: Function creation.
    #>

    Param(
        # OSType Regex
        [Parameter(mandatory=$true,ParameterSetName='OS')]
        [String]
        $OSType,
        # OSVersion Regex
        [Parameter(mandatory=$true,ParameterSetName='Version')]
        [String]
        $OSVersion
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OSTYPE.........: $OSType"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OSVERSION......: $OSVersion"

    ## Check OS Type
    if ($OSType) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Type analysis detected"
        $result = $false
        foreach ($Type in ($OSType -split ","))
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Testing OS type against $Type"
            if ((Get-WindowsEdition -Online).Edition -match $Type)
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Type is compatible with $Type"
                $result = $true
            }
        }
        if (!($result)) { $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Type is not compatible" }
    }

    ## Check OS Version
    if ($OSVersion) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Version analysis detected"
        $result = $false
        foreach ($Vr in ($OSVersion -split ","))
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Testing OS type against $Vr"
            if ((Get-WmiObject Win32_OperatingSystem).Version -match $Vr)
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Version is compatible wtih $Vr"
                $result = $true
            } 
        }
        if (!($result)) { $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS Version is not compatible" }
    }

    if ($null -eq $result) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! No analysis detected! That's a miss!"
        $result = $false
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $result #####"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    ## Return result
    return $result
}

Function Add-FeaturesBinaries
{
    <# 
        .Synopsis
        Add a role or feature binaries to the system.

        .Description
        Add a role or feature to the system.

        .Parameter Role
        Name of the binaries set to be checked.

        .Notes
        Version 01.00: 29/08/2019. 
            History: Function creation.
    #>
    Param(
        # Collect the Bundle to be checked for
        [Parameter(Mandatory=$true)]
        [ValidateSet('ADDS and DNS','ADDS and DNS Tools')]
        [String]
        $Role
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ROLE...........: $Role"

    ## BinaryRoles Library
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Building binaries library"
    $LibBinaries = @{
        'ADDS and DNS'=@('DNS','AD-Domain-Services')
        'ADDS and DNS Tools'=@('RSAT-ADDS','RSAT-AD-AdminCenter','RSAT-ADDS-Tools','RSAT-DNS-Server')
    }

    ## Try to install roles
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Begin: role(s) installation"
    $NoEcho   = install-WindowsFeature -Name $LibBinaries[$Role] -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> End..: role(s) installation"

    ## Check installation status
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Begin: role(s) installation"
    $result   = Test-FeaturesBinaries -Role $Role
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->        installation result is $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> End..: role(s) installation"

    ## Finally append debug log execution to a rotative one. We'll keep only last 1000 lines as history.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $result #####"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    ## Return result
    return $result
}

Function New-Password
{
    <# 
        .Synopsis
            Return a random password.

        .Description
            Return a password as string to the caller.

        .Parameter Length
            Password Length.

        .Notes
            Version 01.00: 08/04/2021. 
            History: Function creation.
    #>
    Param(
        # Collect the Bundle to be checked for
        [Parameter(Mandatory=$True)]
        [int]
        $Length
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter LENGTH.........: $Length"
    
    ## Generate random password
    $result = $null

    Add-Type -AssemblyName System.Web
    $PassComplexCheck = $False
    
    do 
    {
        $newPassword=[System.Web.Security.Membership]::GeneratePassword($Length,1)
        If ( (      $newPassword -cmatch "[A-Z\p{Lu}\s]") `
              -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
              -and ($newPassword -match "[\d]") `
              -and ($newPassword -match "[^\w]"))
        {
            $PassComplexCheck=$True
        }
        
    } While ($PassComplexCheck -eq $false)
    
    ## Finally append debug log execution to a rotative one. We'll keep only last 1000 lines as history.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $newPassword #####"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    ## Return result
    return $newPassword
}

Function install-Laps
{
    <# 
        .Synopsis
            Install LAPS on current computer.

        .Description
            Install binary and management tools, update schema.

        .Notes
            Version 01.00: 12/04/2021 
            Version 01.01: 30/04/2021
            Version 01.02: 14/05/2021
            History: 01.00 - Function creation.
                     01.01 - Removed CSE from install option.
                     01.02 - Fixed prerequesite not filled issue.
    #>
    Param(
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter LENGTH.........: $Length"

    ## Get Current Location
    $curDir = (Get-Location).Path

    $result = 0

    ## Version 01.02:
    ## Checking if the user is schema admin
    if (-not ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ? { $_.Value -like "*-518" }))
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is a Schema Administrator: NO (ERROR)"
        $result = 2
        
        ## Finally append debug log execution to a rotative one. We'll keep only last 1000 lines as history.
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
        if (Test-Path .\Debugs\$DbgFile)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
            $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
            $Backup | Out-File .\Debugs\$DbgFile -Force
        }      
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $newPassword #####"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
        $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
        ## Return result
        return $result
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is a Schema Administrator: YES"

    ## Install binaries
    Try   {
            Start-Process msiexec.exe -Wait -ArgumentList "/i $curDir\Tools\LAPS.x64.msi ADDLOCAL=Management,Management.UI,Management.PS,Management.ADMX /L*v $curDir\Logs\laps.log /qn" -ErrorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Binary deployed with management tools"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Failed to install laps.x64.msi!"
            $result = 2
          }
    
    ## Update PolicyDefinition Repo
    $null = Robocopy.exe C:\Windows\PolicyDefinitions C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions /MIR
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> PolicyDefinition folder has been updated"
    
    ## Update Schema
    Try   {
            #.Version 01.00: replaced AdmPwd.PS by the full path.
            Import-module C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Module AdmPwd.PS loaded successfully"
			$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Module AdmPwd.PS (debug: module count = " + (Get-Module AdmPwd.PS).count + ")"
            $null = Update-AdmPwdADSchema
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Schema updated successfully"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> could not update the schema!"
            $result = 2
          }

    ## Generate deployment batch file
    $null = New-Item -Path ("\\" + (Get-ADDomain).DNSRoot + "\NETLOGON") -Name "LAPS" -ItemType Directory
    $BatchData = "@echo off`nmsiexec /qn /i \\" + (Get-ADDomain).DNSRoot + "\NETLOGON\LAPS\LAPS.x64.msi"

    Try   {
            $BatchData | Out-File C:\Windows\SYSVOL\domain\scripts\laps\laps-x64.bat -Encoding utf8 -Force -ErrorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> file laps-x64.msi successfully created in C:\Windows\SYSVOL\domain\scripts\laps"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> file laps-x64.msi failed to be created in C:\Windows\SYSVOL\domain\scripts\laps"
            $result = 1
          }
    
    ## Add GPO for customisation
    $resul2 = Import-NewGpo -GpoName "Securite - LAPS" -useTranslate No
    if ($resul2 -ne 0) { $result = 1 }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> import new GPO 'Securite - LAPS' ended with code $resul2"

    ## Add right management for computers upon pwd read/change
    $NULL = Set-AdmPwdComputerSelfPermission -OrgUnit (Get-ADDomain).distinguishedName
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Computer are now allowed to reset their password"

    ## Finally append debug log execution to a rotative one. We'll keep only last 1000 lines as history.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Debugs\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Debugs\$DbgFile -Tail 1000 
        $Backup | Out-File .\Debugs\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "#### FUNCTION RETURN: $newPassword #####"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Debugs\$DbgFile -Append
    
    ## Return result
    return $result
}

Function Disable-DCPrintSpooler
{
       <#
        .Synopsis
            Disable Spooler Service.
        
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
        $DCs = Get-ADDomainController -Filter *
    
        $result = 0
    
        foreach ($DC in $DCs)
        {
            Try   { 
                    Get-Service -ComputerName $DC.Hostname Spooler | Stop-Service -PassThru | Set-Service -StartupType Disabled
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Service Spooler disabled on " + $DC.HostName
                  }
            Catch { 
                    $result = 2 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Failed to disable Service Spooler on " + $DC.HostName
                  }
        }
    }
    else
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

Function Set-DcSchedule
{
     <#
        .Synopsis
            Create scheduling on DC.

        .Notes
            Version: 01.00 -- Loic.veirman@mssec.fr
            Version: 01.01 -- Loic.veirman@mssec.fr
            Version: 01.02 -- Loic.veirman@mssec.fr
            history: 
            > 01.00 : 21.04.21 - Script creation
            > 01.01 : 14.05.21 - Modified ScTask creation and use a XML import
            > 01.02 : 23.05.21 - Modified xml import file to adapt to running os
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command

    ## Cleanup GRP_ADMIN_xxx (version 01.00)
    #$cdLine = '-windowstyle hidden -command &{Set-ADGroup -Identity GRP_ADMIN_STATIONS -clear member; Set-ADGroup -Identity GRP_ADMIN_SERVEURS -clear member}'
    #$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cdLine
    #$triggr = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 11:00PM 
    #$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter cdLine.............: $cdLine"
    #$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter action.............: $action"
    #$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter triggr.............: $triggr"

    ## Version 01.01
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> import XML file..............: Purge groupes GRP_ADMIN_xxx.xml"
    
    $result = 0
    
    #.Check if xml file is present
    if (-Not (Test-Path '.\inputs\schedules\Purge groupes GRP_ADMIN_xxx.xml'))
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Task Creation failed: the XML file is missing."
        $result = 2
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

    Try   {
            # Version 01.00
            # $install = Register-ScheduledTask -Action $action -Trigger $triggr -TaskPath "Flexsi" -TaskName "Purge groupes GRP_ADMIN_xxx" `
            #                                   -Description "Retire les membres des groupes GRP_ADMIN_SERVEURS et GRP_ADMIN_STATIONS tous les dimanches a 23h." `
            #                                   -User "NT AUTHORITY\SYSTEM" -ErrorAction Stop

            # Version 01.01
            # $install = Register-ScheduledTask -TaskPath "Flexsi" -TaskName "Purge groupes GRP_ADMIN_xxx" `
            #                                   -Xml (Get-Content '.\Inputs\Schedules\Purge groupes GRP_ADMIN_xxx.xml' | Out-String) `
            #                                   -Force

            $install = Register-ScheduledTask -TaskPath "AdHardening" -TaskName "Purge groupes GRP_ADMIN_xxx" `
                                              -Xml (Get-Content '.\Inputs\Schedules\Purge groupes GRP_ADMIN_xxx.xml' | Out-String) `
                                              -Force 
            # Compatibility Matrix
            $OSVersion = (Get-CimInstance Win32_OperatingSystem).version
            
            Switch($OSVersion.Split('.')[0] + "." + $OSVersion.Split('.')[1])
            {
                '10.0' { $CompatMode = 'Win8' }
                '6.3'  { $CompatMode = 'Win8' }
                '6.2'  { $CompatMode = 'Win8' }
                '6.1'  { $CompatMode = 'Win8' }
                '6.0'  { $CompatMode = 'Vista' }
                '5.2'  { $CompatMode = 'V1' }
            }
            # Setting Up the compatibility ScheduledTask
            $taskSettings = New-ScheduledTaskSettingsSet -Compatibility $CompatMode
            
            $null = Set-ScheduledTask -TaskName 'AdHardening\Purge groupes GRP_ADMIN_xxx' -Settings $taskSettings -ErrorAction SilentlyContinue

            if ($install.State -eq "Ready") 
            { 
                $result = 0 
            } 
            else 
            { 
                $result = 2 
            }
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Task Creation result: $install"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Task Creation failed: probably because it already exists."
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

## Export modules
Export-ModuleMember -Function *