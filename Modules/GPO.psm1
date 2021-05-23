Function Convert-MigTable
{
    <#
        .SYNPOSIS
            This function will replace the specified name in a migTable to the target one.

        .DETAILS
            GPO imported from a dev domain will contains unknowns principal. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function return the XML data.

        .PARAMETER ObjectToTranslate
            Object name to translate.

        .PARAMETER ObjectCategory
            is User, Group, ...

        .PARAMETER XmlData
            Xml file to use for replacement

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $ObjectToTranslate,

        [Parameter(mandatory=$true)]
        [ValidateSet('User','Group','Domain','UNCPath')]
        [String]
        $ObjectCategory,

        [Parameter(mandatory=$true)]
        $xmlData
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller...............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectToTranslate...: $ObjectToTranslate"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectCategory......: $ObjectCategory"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter xmlData.............: [skipped]"


    ## Switch on category
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Switching on ObjectCategory"
    Switch ($ObjectCategory)
    {
        'User'    { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADUser  $ObjectToTranslate).SID 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new User.: " + (Get-ADUser  $ObjectToTranslate).SID 
                  }
        'Group'   { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADGroup $ObjectToTranslate).SID 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new Group: " + (Get-ADGroup $ObjectToTranslate).SID 
                  }
        'Domain'  { $result = $xmlData -replace "%$ObjectToTranslate%",((Get-ADDomain).NetBIOSName + "\$ObjectToTranslate")
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new SName: " + (Get-ADGroup $ObjectToTranslate).SID 
                  }
        'UNCPath' { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADDomain).DNSRoot
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new UNCp.: " + (Get-ADDomain).DNSRoot
                  }
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Switching done"
    
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

    ## Return translated xml
    return $result
}

Function Publish-MigTable
{
    <#
        .SYNPOSIS
            This function generate the .migtable file to be used by GPO.

        .DETAILS
            the .migtable file is generic and contains value to be translated before being used by import-newGpo.

        .PARAMETER SourceMigTable
            Source file to read from.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $SourceMigTable
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller................: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter SourceMigTable.......: $SourceMigTable"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter DestinationMigTable..: $DestinationMigTable"

    ## Loading file
    if (Test-Path .\Inputs\GPOs\$SourceMigTable)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Source File is present"

        Try   {
                $xmlData = Get-Content .\Inputs\GPOs\$SourceMigTable -ErrorAction Stop
                $LoadFile = $true
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Source File loaded to xmlData"
              }
        Catch {
                $LoadFile = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Source File could not be loaeded!"
              }
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Source File is missing!"
        $LoadFile = $false
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadFile.........: $LoadFile"

    ## Loading translation table
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Loading Gpo-Directory.ini file"
    Try   {
            $iniGpo = import-ini .\Inputs\GPOs\Gpo-Directory.ini -errorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini loaded successfully"
            $LoadIni = $true
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini could not be loaded!"
            $LoadIni = $false
          }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadIni..........: $LoadIni"

    ## Translating
    if ($LoadIni -and $LoadFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Begin xml translation."
        for ($i = 1 ; $i -le $iniGpo["GPOTRANSLATE"]["INDEX"] ; $i++)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Translating raw data: " + $iniGpo["GPOTRANSLATE"]["$i"]

            $obj = ($iniGpo["GPOTRANSLATE"]["$i"] -split ";")[0]
            $Cat = ($iniGpo["GPOTRANSLATE"]["$i"] -split ";")[1]

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Object Name.........: $obj"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Object Category.....: $Cat"

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Calling Convert-MigTable: Start"

            $xmlData = Convert-MigTable -ObjectToTranslate $obj -ObjectCategory $Cat -xmlData $xmlData

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Calling Convert-MigTable: Finish"
        }

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> End xml translation."
    }

    ## Exporting
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Exporting file: begin"
    try   {
            $noEchoe  = $xmlData | Out-File .\Inputs\GPOs\translated.migtable -Force 
            $resultat = $true
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Exporting file: success"
          }
    Catch {
            $resultat = $false
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Exporting file: failed!"
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

    ## Return translated xml
    return $resultat
}

Function Import-NewGpo
{
    <#
        .SYNPOSIS
            This function will import a new GPO from a backup file.

        .DETAILS
            To ease at building a secure domain, some GPO are prepared in a lab 
            and backuped; then we import them to the new production domain.

        .PARAMETER GpoName
            Gpo Object Name: used to retrieve the backup ID from Gpo-Directory.ini.

        .PARAMETER useTranslate
            If set to YES, the GPO file will be analyzed from Gpo-Directory.ini through input in [GPOTRANSLATE].

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $GpoName,

        [Parameter(mandatory=$true)]
        [ValidateSet('Yes','No','YES','NO')]
        [String]
        $useTranslate
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller.............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter GpoName...........: $GpoName"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter useTranslate......: $useTranslate"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter xmlData...........: [skipped]"

    ## Get Current Location
    $curDir = (Get-Location).Path
    
    ## Import GPO ini data
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Loading Gpo-Directory.ini file"
    Try   {
            $iniGpo = import-ini .\Inputs\GPOs\Gpo-Directory.ini -errorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini loaded successfully"
            $LoadIni = $true
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini could not be loaded!"
            $LoadIni = $false
          }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadIni..........: $LoadIni"

    ## Look for GPO backup ID
    if ($LoadIni)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO Backup ID: looking at..."
        $BackupID = $iniGpo["GPONAME"]["$GpoName"]
        $BkpFoldr = $iniGpo["BACKUPID"]["$BackupID"]
    
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO Backup ID: $BackupID"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO Backup ID: backup folder $BkpFoldr"

        $iniFlag = $true
    }
    else 
    {
        $iniFlag = $false
    }
        
    ## Creating GPO - This is not mandatory but this will ensure that the GPO is not already present.
    if ($iniFlag)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: start"
        Try   {
                $noEcho = New-GPO -Name $GpoName -Comment $iniGpo["GPODESC"]["$BackupID"] -ErrorAction Stop
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: Skeletton created successfully"
                $gpoFlag = $true
              }
        Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: Skeletton created failed!"
                $gpoFlag = $false
                $result = 1
              }
        if ($gpoFlag)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: import parameters from backup"
            Try   {
                    $noEcho = Import-GPO -BackupGpoName $GpoName `
                                         -TargetName $GpoName `
                                         -MigrationTable $curDir\Inputs\GPOs\translated.migtable `
                                         -Path $curDir\Inputs\GPOs `
                                         -ErrorAction Stop

                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: parameter imported successfully"
                    $gpoFlag = $true
                    $result = 0
                  }
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> GPO import: import parameters has failed!"
                    $gpoFlag = $false
                    $result = 2
                  }
        }
    }
    else
    {
        $result = 2
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

    ## Return translated xml
    return $result
}

Function Deny-ApplyGpo
{
    <#
        .SYNPOSIS
            This function will deny apply to specifics.

        .DETAILS
            To ease at building a secure domain, some GPO are prepared in a lab 
            and backuped; then we import them to the new production domain.

        .PARAMETER GpoName
            Gpo Object Name: used to retrieve the deny from Gpo-Directory.ini.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $GpoName
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller.............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter GpoName...........: $GpoName"

    ## Import ini file
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Loading Gpo-Directory.ini file"
    Try   {
            $iniGpo = import-ini .\Inputs\GPOs\Gpo-Directory.ini -errorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini loaded successfully"
            $LoadIni = $true
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Gpo-Directory.ini could not be loaded!"
            $LoadIni = $false
          }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadIni..........: $LoadIni"

    ## Get GPO index id
    $GpoID = $iniGpo["GPONAME"]["$GpoName"]

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Index for this gpo is $GpoID"

    ## Recover Deny List
    $denyList = ($iniGpo["GPODENY"]["$GpoID"] -replace "%domSid%",(Get-ADDomain).DomainSID.Value) -split ","
    foreach ($Deny in $denyList)
    {
        if ($Deny -match '%domSid%') 
        { 
            $isSid = $true
            $isPri = $false 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> the ID is a SID"
        } 

        if ($Deny -match "%SecPri%")
        {
            $deny = $Deny -replace "%SecPri%","S-1-5"
            $isSid = $false 
            $isPri = $true
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> the ID is a principal security"
        }
        
        if ( -not ($isSid) -and -not ($isPri))
        { 
            $isSid = $false 
            $isPri = $false
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> the ID is a samAccountName"
        }
                
        if ($isSid) 
        { 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Start isSid treatment"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is Deny ? Deny is $deny"
            $DenyID = Get-ADObject -filter { objectsid -eq $Deny } -Properties samAccountName
            $NtAccount = (Get-ADDomain).NetBIOSName + "\" + $DenyID.samAccountName
            $friendlyName = [System.Security.Principal.NTAccount]$NtAccount
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is $Deny ? Deny is $friendlyName"
        }
        
        if ($isPri)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Start isPri treatment"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is Deny ? Deny is $deny"
            $sid = new-object System.Security.Principal.SecurityIdentifier($Deny)
            $friendlyName = $sid.Translate([System.Security.Principal.NTAccount])
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is $Deny ? Deny is " + $friendlyName.value
        }
        
        if (!($isSid) -and !($isPri))
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Start not isPri and not isSid treatment"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is Deny ? Deny is $deny"
            $DenyID = Get-ADObject -filter { SamAccountName -eq $deny } -Properties samAccountName
            $NtAccount = (Get-ADDomain).NetBIOSName + "\" + $DenyID.samAccountName
            $friendlyName = [System.Security.Principal.NTAccount]$NtAccount
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Who is $Deny ? Deny is $friendlyName"
        }

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> ID matched to $friendlyName"
        
        Try   {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Start new ACL rule"
                $gpo    = Get-GPO -Name $GpoName
                $adgpo  = [ADSI]("LDAP://CN=`{$($gpo.Id.guid)`},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName)

                $rule   = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
		                    $friendlyName, 
		                    "ExtendedRight", 
		                    "Deny", 
		                    [Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"
                            )
        
                $acl = $adgpo.ObjectSecurity
                $acl.AddAccessRule($rule)
                $adgpo.CommitChanges()

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Deny Permission has been applied"
                
                $result = $true
              }
        Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Deny Permission failed to applied!"

                $result = $false
              }
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

    ## Return translated xml
    return $result
}

Function Convert-PrefTable
{
    <#
        .SYNPOSIS
            This function will look after XML file in "preference" folder and replace any occurences based on the file.

        .DETAILS
            GPO imported from a dev domain will contains unknowns principal. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function return the XML data.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>
	
	Param (
        [Parameter(mandatory=$true)]
        [string]
        $SourcePrefTable
	)
	
	## Function Log Debug File
	$DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
	$dbgMess = @()
	
	## Start Debug Trace
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
	
	## Indicates caller and options used
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller...............: " + (Get-PSCallStack)[1].Command
	
	## Ensure that a translation table is present
	if (Test-Path .\inputs\gpos\$SourcePrefTable)
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Reference base prefTable......: .\inputs\gpos\$SourcePrefTable is present."
		$refTable = Get-Content .\inputs\gpos\$SourcePrefTable
		$noError  = $true
	}
	else
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Reference base prefTable......: .\inputs\gpos\$SourcePrefTable is missing!"
		$noError = $false
	}
	
	## if no error, generating in memeory a translation table
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> starting translation process..:"
	$newIDs = @()
	foreach ($line in $refTable)
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Raw data: $line"
		
        $rawData  = $line -Split ';'
		$newName  = $rawData[1] -replace ($rawData[1] -split '\\')[0],(Get-ADDomain).NetBIOSName
		
        switch ($rawData[0])
		{
			"Group" { $newSid = (Get-ADGroup -Identity ($rawData[1] -split "\\")[1]).SID}
			"User"  { $newSid = (Get-ADUser -Identity ($rawData[1] -split "\\")[1]).SID }
			Default { $newSid = $null }
		}
		$newIDs += ($line + ";$newName;$newSid") -replace "\\","\\"

		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> New data: $line;$newName;$newSid"
	}
	
	## Begining to look at replacement...
	$BackupGPOs = Get-ChildItem .\inputs\GPOs -Directory

	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Analyzing GPOs:"

    foreach ($GPO in $BackupGPOs)
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Dealing with GPO id " + $GPO.Name + ":"

		$Looking = ".\inputs\gpos\" + $GPO.Name + "\DomainSysvol\GPO\Machine\Preferences"

		if (Test-Path $Looking)
		{
			$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder Machine Preferences is present: looking for XML..."
			
            $xmls = Get-ChildItem $Looking -Recurse -File *.xml
			
            if ($xmls)
			{
				foreach ($xml in $xmls)
				{
					$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> working on " + $xml.FullName
					
					$rawXML = Get-Content $xml.FullName

                    foreach ($line in $newIDs)
					{
						$lineData = $line -split ";"
						
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> replacing " + $lineData[1] + " with " +  $lineData[3] + " and " + $lineData[2] + " with " + $lineData[4]
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Avant: " + $rawXML 
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Apres: " + (($rawXML -replace "\\","\\") -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]

                        #.The '\' is considered as an escapment character and need to be doubled. 
                        #.Once the conversion is done, you'll have to remove the double \\ added.
                        $rawXML = (($rawXML -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]) -replace "\\\\","\"

					}
					$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> rewriting file " + $xml.FullName
					
                    Set-Content -Path $xml.FullName -Value $rawXML 
				}
			}
			else
			{
				$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> no XML found"
			}
		}
		else
		{
			$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder Machine Preferences is not present"
		}
		
		$Looking = ".\inputs\gpos\" + $GPO.Name + "\DomainSysvol\GPO\User\Preferences"

		if (Test-Path $Looking)
		{
			$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder User Preferences is present: looking for XML..."

			$xmls = Get-ChildItem $Looking -Recurse -File *.xml

			if ($xmls)
			{
				foreach ($xml in $xmls)
				{
					$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> working on " + $xml.FullName

					$rawXML = Get-Content $xml.FullName

					foreach ($line in $newIDs)
					{
						$lineData = $line -split ";"
						
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> replacing " + $lineData[1] + " with " + $lineData[3] + " and " + $lineData[2] + " with " + $lineData[4]
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Avant: " + $rawXML 
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Apres: " + (($rawXML -replace "\\","\\") -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]
						
                        #.The '\' is considered as an escapment character and need to be doubled. 
                        #.Once the conversion is done, you'll have to remove the double \\ added.
                        $rawXML = (($rawXML -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]) -replace "\\\\","\"
					}

					$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> rewriting file " + $xml.FullName

                    Set-Content -Path $xml.FullName -Value $rawXML 
				}
			}
			else
			{
				$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> no XML found"
			}
		}
		else
		{
			$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder User Preferences is not present"
		}
		
	}
	$Result = 0
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
	
	## Return translated xml
	return $result
}

Export-ModuleMember -Function * 