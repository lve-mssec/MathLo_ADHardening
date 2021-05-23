<#
    .Synopsis
     Applique le Standard Active Directory de Flexsi sur un domaine.

    .Description
     Le script applique le standard Flexsi sur un domaine. Il est basé sur la version d'Avril 2021.

    .Parameter ConfigFile
     Indique le fichier de configuration à utiliser pour la personnalistion. Par défaut, il utilise le fichier ActiveDirectory-Configuration.ini dans le dossier .\INPUTS.

    .Notes
     ==================================
        Historique des releases :
        -------------------------
        Version....: 01.00.000 - 06/04/2021 - loic.veirman@mssec.fr - creation du script
        Version....: 01.01.000 - 14/05/2021 - loic.veirman@mssec.fr - Correction de bugs
        Version....: 01.01.001 - 15/05/2021 - loic.veirman@mssec.fr - Correction de bugs + refonte du jeu de GPO et de la table de traduction.
        Version....: 01.01.001 - 23/05/2021 - loic.veirman@mssec.fr - Correction du bug 17

        ===============================
        Liste des Bugs :
        ----------------
        > BUG001: Erreur à l'execution - Le terme « #New-AadcSyncOU » n'est pas reconnu.....................................OK (01.01.000)
        > BUG002: Erreur à l'execution - Local Administrator Password Service failed to be installed successfully...........OK (01.01.000)
        > BUG003: L'installation de LAPS ne fonctionne que depuis le dossier c:\_ADM\Flexsi_StandardAD......................OK (01.01.000)
        > BUG004: Seul le lien de site "Default IP SiteLink" est configuré, pas les autres..................................OK (01.01.000)
        > BUG005: Le lancement de l'installation de LAPS affiche un pop-up..................................................OK (01.01.000)
        > BUG006: Le script "LAPS-X64.bat" ne contient pas le bon nom de domaine............................................OK (01.01.000)
        > BUG007: Le script "LAPS-X64.bat" n'est pas correctement copié dans le dossier netlogon............................OK (01.01.000)
        > BUG008: La GPO "Securite - Administrateur Local – stations" ne modifie pas le nom du groupe (mauvais domaine).....OK (01.01.001)
        > BUG009: La GPO "Securite - Administrateur Local – serveurs" ne modifie pas le nom du groupe (mauvais domaine).....OK (01.01.001)
        > BUG010: La tache planifiée de clean-up des groupes n'est pas configurée avec le compte "system"...................OK (01.01.000)
        > BUG011: Le logon script LAPSx64 est absent dans la GPO "Securite - LAPS"..........................................OK (01.01.001)
        > BUG012: Sur Windows Server 2008 R2, le parametre TAIL n'est pas dispo (logging)...................................TO DO
        > BUG013: Le fichier translated.migtable ne se reecrease pas quand utiliser dans un nouveau domaine.................TO DO
        > BUG014: L'activation de la corbeille ne fonctionne pas sur 2012 R2 en Anglais (OS ou langue ?)....................TO DO
        > BUG015: La création des comptes SA ne fonctionne pas sur 2012 R2 en Anglais (OS ou langue ?)......................TO DO
        > BUG016: La création des comptes  A ne fonctionne pas sur 2012 R2 en Anglais (OS ou langue ?)......................TO DO
        > BUG017: La tache planifiée de clean-up des groupes doit être reglé sur le niveau de l'OS l'exécutant..............OK (01.01.002)

        ===============================
        Futures implémentations :
        -------------------------
        > NEW001: Mettre en oeuvre la délégation d'admin....................................................................TO DO
        > NEW002: Ajouter le groupe GRP_ADMIN_TIER_0 dans le groupe "Administrateurs de l’entreprise".......................TO DO
        > NEW003: Ajouter le groupe GRP_ADMIN_TIER_0 dans le groupe "Protected Users".......................................TO DO
        > NEW004: Ajouter le groupe "Administrateurs" dans le groupe "Administrateurs de l’entreprise" .....................TO DO
        > NEW005: Les GPO de sécurités doivent être liées aux bonnes OUs....................................................TO DO
        > NEW006: Ajouter un controle des prerequis sur le compte qui execute l'action......................................TO DO
        > NEW007: Ajouter un controle des prerequis sur le systeme qui execute l'action.....................................TO DO
        > NEW008: REmplacer le chemin statique SYSVOL par un chemin dynamique (au cas ou)...................................TO DO
#>

Param( 
    # Input File for configuration
    [Parameter(Mandatory=$False)]
    [string]
    $ConfigFile='Configuration_SMB.ini' 
)

###
## Generate Global variables
#
$Global:LogFile  = ($MyInvocation.MyCommand.Name -replace '.ps1','') + "_" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss") + ".log"

###
## Check for old log files to cleanup: only keep the last 10.
#
$Loglist = Get-ChildItem .\Logs -Filter (($MyInvocation.MyCommand.Name -replace '.ps1','') + "_*") -Recurse | Sort-Object -Descending
For ($j = 9 ; $j -lt $Loglist.count ; $j++) 
{
    Remove-Item $Loglist[$j].FullName
}

###
## Import modules for this script
#
$Modules = Get-ChildItem .\Modules -Filter '*.psm1' -Recurse

ForEach ($module in $modules) 
{ 
    Import-Module $module.FullName -ErrorAction Stop 
}

###
## Initialize Configuration File for the script
#
$ScriptConfig = Import-Ini -FilePath .\Configs\Version_SMB.ini

###
## Initialize log
#
write-logInfo -LogMessage ('| `[' + $MyInvocation.MyCommand.Name + '`]')                -ToScreen -Scheme 'START and STOP'
write-logInfo -LogMessage ('| Version: `(' + $ScriptConfig["Global"]["Version"] + '`)') -ToScreen -Scheme 'START and STOP'
write-logInfo -LogMessage ('| Author.: `(' + $ScriptConfig["Global"]["Author"] + '`)')  -ToScreen -Scheme 'START and STOP'
write-logInfo -LogMessage ('| Date...: `(' + $ScriptConfig["Global"]["Date"] + '`)`n')  -ToScreen -Scheme 'START and STOP'

###
## Import configuration file(s)
#
$ADconfig = Import-Ini -FilePath .\Inputs\$ConfigFile 

if ($ADconfig) 
{
    write-logInfo -LogMessage ($ScriptConfig["SUCCESS"]["1"] -replace 'ConfigFile',$ConfigFile) -ToScreen -Scheme 'OK and KO'
} 
else 
{
    write-logInfo -LogMessage ($ScriptConfig["FAILURE"]["1"] -replace 'ConfigFile',$ConfigFile) -ToScreen -Scheme 'OK and KO'
    Exit 1
}

###
## Boucle de séquence des actions
#
$FlexsiSequence = Import-Ini -FilePath .\Configs\Sequence-SMB.ini

if ($FlexsiSequence)
{
    write-logInfo -LogMessage ($ScriptConfig["SUCCESS"]["1"] -replace 'ConfigFile','Sequence-SMB.ini') -ToScreen -Scheme 'OK and KO'
}
Else
{
    write-logInfo -LogMessage ($ScriptConfig["FAILURE"]["1"] -replace 'ConfigFile','Sequence-SMB.ini') -ToScreen -Scheme 'OK and KO'
    Exit 1
}

For ($i = 1 ; [int]$i -le $FlexsiSequence["Global"]["MaxAction"] ; $i++)
{
    #. Define if the sequence is to be bypassed or not.
    if ($FlexsiSequence["Actions"]["$i"] -eq "")
    {
        #. Pas d'action, on affiche et hop, au suivant.
        write-logInfo -LogMessage ($FlexsiSequence["GLOBAL"]["NulAction"] + $i) -ToScreen -Scheme 'WARNING'
    }
    Else 
    {
        #. Action à lancer.
        $ActionCommand = ($FlexsiSequence["Actions"]["$i"] -split ";")[0]
        $ActionParamtr = @{}
        foreach ($value in (($FlexsiSequence["Actions"]["$i"] -split ";")[1] -split ","))
        {
            $ActionParamtr.add(($value -split "=")[0] , ($value -split "=")[1])
        }

        $ActionResults = . $ActionCommand @ActionParamtr

        Switch ($ActionResults)
        {
            $true  {write-logInfo -LogMessage $FlexsiSequence["INFOS"]["$i"] -ToScreen -Scheme 'OK and KO' }
            $false {write-logInfo -LogMessage $FlexsiSequence["ERROR"]["$i"] -ToScreen -Scheme 'OK and KO' }
            0      {write-logInfo -LogMessage $FlexsiSequence["INFOS"]["$i"] -ToScreen -Scheme 'OK and KO' }
            1      {write-logInfo -LogMessage $FlexsiSequence["ALERT"]["$i"] -ToScreen -Scheme 'Warning' }
            2      {write-logInfo -LogMessage $FlexsiSequence["ERROR"]["$i"] -ToScreen -Scheme 'OK and KO' }
        }
    }
}


###
## Script ends
#
write-logInfo -LogMessage '`n| `{Script''s done!`}`n' -ToScreen -Scheme 'START and STOP'

ForEach ($module in $modules) 
{ 
    Remove-Module ($module.Name -replace '.psm1','') -ErrorAction SilentlyContinue 
}