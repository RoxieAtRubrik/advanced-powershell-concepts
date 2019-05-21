'  _________                          .__  __          
  /   _____/ ____   ____  __ _________|__|/  |_ ___.__.
  \_____  \_/ __ \_/ ___\|  |  \_  __ \  \   __<   |  |
  /        \  ___/\  \___|  |  /|  | \/  ||  |  \___  |
 /_______  /\___  >\___  >____/ |__|  |__||__|  / ____|
         \/     \/     \/                       \/     '


# Transcription by Profile
'$null = Start-Transcript -Path C:\Transcription\Profile.log -Append' |
Out-File -FilePath (Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1') -Force

# Show how to work around this
Stop-Transcript

# View Transcription log
Invoke-Item -Path 'C:\Transcription\Profile.log'

# Remove PowerShell Profile logging
Remove-Item -Path (Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1') -Force

# Module Transcription
# MMC -> Local Computer Policy
# Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell

# Open PowerShell
Clear-EventLog -LogName 'Windows PowerShell'
Get-WinEvent -LogName 'Windows PowerShell' |
Select-Object -ExpandProperty Message |
Where-Object {$_ -match '"Get-WinEvent"'} |
Select-Object -First 1

# Count the number of lines in output
(Get-WinEvent -LogName 'Windows PowerShell' |
Select-Object -ExpandProperty Message |
Where-Object {$_ -match '"Get-WinEvent"'} |
Select-Object -First 1) -split "`r`n" |
Measure-Object

Get-WinEvent -LogName 'Windows PowerShell' |
Select-Object -ExpandProperty Message |
Where-Object {$_ -match 'CommandLine=Add-PowerShellWinX'} 

# Check LogPipelineExecutionDetails (3.0 feature)
(Get-Module CustomizeWindows10).LogPipelineExecutionDetails

# Disable LogPipelineExecutionDetails 
(Get-Module CustomizeWindows10).LogPipelineExecutionDetails = $false

# Clear EventLog and rerun cmdlet
Clear-EventLog -LogName 'Windows PowerShell'

Add-PowerShellWinX

Get-WinEvent -LogName 'Windows PowerShell' |
Select-Object -ExpandProperty Message |
Where-Object {$_ -match 'CommandLine=Add-PowerShellWinX'} 

# MMC -> Local Computer Policy
# Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell
# Disable Module logging and Enable Transcription to C:\Transcription

# Restart ISE

# Open the log
Get-ChildItem C:\Transcription\20190521 -File | Invoke-Item

# Import Module
Import-Module -Name PS-MotD
Get-MOTD

# Open the log
Get-ChildItem C:\Transcription\20190521 -File | Invoke-Item

# PInvoke C# code and execute it
$Source = @"
using System;

namespace CS
{
    public class Program
    {
        public static void Payload()
        {
            Console.WriteLine("Awesome!");
        }
    }
}
"@
Add-Type -TypeDefinition $Source -Language CSharp
[CS.Program]::Payload()

# Open the log
Get-ChildItem C:\Transcription\20150919 -File |
Sort-Object -Property LastWriteTime | Select-Object -Last 1 |
Invoke-Item

# Another example
$Code = Get-Content -Path C:\Users\JaapBrasser\Desktop\Demo2\Malicious.txt -Raw
Add-Type -TypeDefinition $Code -Language CSharp
[CS.Malicious]::Payload()

# MMC -> Local Computer Policy
# Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell
# Enable Script block logging

# Enable by registry
'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' | ForEach-Object {
    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value 1
}

# Another example
$Code = Get-Content -Path C:\Users\JaapBrasser\Desktop\Demo2\Malicious.txt -Raw
Add-Type -TypeDefinition $Code -Language CSharp
[CS.Malicious]::Payload()

# Open the log
Get-ChildItem C:\Transcription\20151119 -File |
Sort-Object -Property LastWriteTime | Select-Object -Last 1 |
Invoke-Item

# Inspect the deep script logging results
Get-WinEvent -FilterHashtable @{ 
    ProviderName='Microsoft-Windows-PowerShell'
    Id = 4104
} | Select-Object -First 3 -ExpandProperty Message

# Encoded string
iex (-join (echo 91 109 97 116 104 93 58 58 80 73 | % {[char]$_}))

# Inspect the deep script logging results
Get-WinEvent -FilterHashtable @{ 
    ProviderName='Microsoft-Windows-PowerShell'
    Id = 4104
} | Select-Object -First 3 -ExpandProperty Message


'     ____.___________   _____    __________                       __  .__                
     |    |\_   _____/  /  _  \   \______   \ ____   _____   _____/  |_|__| ____    ____  
     |    | |    __)_  /  /_\  \   |       _// __ \ /     \ /  _ \   __\  |/    \  / ___\ 
 /\__|    | |        \/    |    \  |    |   \  ___/|  Y Y  (  <_> )  | |  |   |  \/ /_/  >
 \________|/_______  /\____|__  /  |____|_  /\___  >__|_|  /\____/|__| |__|___|  /\___  / 
                   \/         \/          \/     \/      \/                    \//_____/  '

                   Install-Module -Name xJea

C:\RubrikBuild\JEA\Demo1\RubrikBuildDemo1-Prep.ps1
C:\RubrikBuild\JEA\Demo1\RubrikBuildDemo2-Prep.ps1

code 'C:\RubrikBuild\JEA\Demo1\RubrikBuildDemo1-Prep.ps1'

ConvertFrom-SDDL 'O:NSG:BAD:P(A;;GX;;;WD)' | Select-Object -ExpandProperty Access

Get-PSSessionConfiguration RubrikBuildDemo*

Get-PSSessionConfiguration RubrikBuildDemo1 | Select-Object *

$StartupScript = (Get-PSSessionConfiguration RubrikBuildDemo1).StartupScript

code $StartupScript

code 'C:\Program Files\Jea\Toolkit\RubrikBuildDemo1-ToolKit.psm1'

ConvertFrom-SDDL 'O:NSG:BAD:P(A;;GA;;;S-1-5-21-3752796473-1610122376-121573805-1013)' |
Select-Object -ExpandProperty Access

Enter-PSSession -ComputerName . -ConfigurationName RubrikBuildDemo1

Get-Command

1+1

whoami
whoami /priv

Get-Command whoami | Format-List ScriptBlock

Get-Process

Get-Process | Format-List
Get-Process | Get-Member
$Variable = Get-Process

Get-Command -Module RubrikBuildDemo1-Toolkit

Get-Command -Name Get-CimInstance
Get-CimInstance -ClassName win32_bios

Exit-PSSession

$SessionCred = Import-Clixml -Path C:\RubrikBuild\JEA\Demo2\ExchangeVMAdmin.cred

Enter-PSSession -ComputerName . -Credential $SessionCred

$VMSes = New-PSSession -ComputerName . -ConfigurationName RubrikBuildDemo2 -Credential $SessionCred

Get-PSSessionConfiguration RubrikBuildDemo2

Enter-PSSession -Session $VMSes

Get-Command

Get-Command -Module RubrikBuildDemo2-Toolkit
Get-Command -Module RubrikBuildDemo2-Toolkit | Measure-Object

Get-VM 

Get-VM -Name NanoServer01 | Start-VM

Start-VM -Name NanoServer02

Exit-PSSession

psedit 'C:\Program Files\Jea\Toolkit\RubrikBuildDemo2-ToolKit.psm1'

$LineToReplace = @'
        $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('hyper-v\Get-VM', [System.Management.Automation.CommandTypes]::Cmdlet)
'@
$Replace       = "`r`n$LineToReplace        `$PSBoundParameters.Name = 'Exchange*'"
$RegEx         = ([regex]::Escape($LineToReplace))

(Get-Content 'C:\Program Files\Jea\Toolkit\RubrikBuildDemo2-ToolKit.psm1') -replace $Regex,$Replace |
Set-Content 'C:\Program Files\Jea\Toolkit\RubrikBuildDemo2-ToolKit.psm1'

Enter-PSSession -ComputerName . -ConfigurationName RubrikBuildDemo2 -Credential $SessionCred

Get-VM

$SessionCred = Import-Clixml -Path C:\RubrikBuild\JEA\Demo2\ExchangeVMAdmin.cred

$VMSes = New-PSSession -ComputerName . -ConfigurationName RubrikBuildDemo2 -Credential $SessionCred

Get-VM -CimSession $VMSes

# Start-VM
Invoke-Command -Session $VMSes -ScriptBlock {Get-VM} |
Out-GridView -Title 'Select VM to Start' -PassThru   |
ForEach-Object {Start-VM -Name $_.Name}

# Stop-VM
Invoke-Command -Session $VMSes -ScriptBlock {Get-VM} |
Out-GridView -Title 'Select VM to Stop'  -PassThru   |
ForEach-Object {Stop-VM  -Name $_.Name -Force}

'   _____       .___                                     .___
   /  _  \    __| _/__  _______    ____   ____  ____   __| _/
  /  /_\  \  / __ |\  \/ /\__  \  /    \_/ ___\/ __ \ / __ | 
 /    |    \/ /_/ | \   /  / __ \|   |  \  \__\  ___// /_/ | 
 \____|__  /\____ |  \_/  (____  /___|  /\___  >___  >____ | 
         \/      \/            \/     \/     \/    \/     \/ '

#region Pre-check
Set-Location 'C:\Users\Jaap Brasser\OneDrive\Documents\Events\2018-09-23 Ignite\session\Demo'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure VPN is disconnected
# Ensure Windows Defender is disabled for last demo

#endregion

#region Aliases and Help

# Alarm clock
Start-Sleep -Seconds 600

# Help and information about parameter order
Get-Help Start-Sleep
Get-Help Start-Sleep -Parameter Seconds

# Find alias 
Get-Alias -Definition Start-Sleep

sleep 3

sleep 3;[console]::Beep()

sleep 3; while(1){[console]::Beep()}

code alarmclock.ps1

.\AlarmClock.ps1
#endregion

#region Functions

function Start-AlarmClock {
    Start-Sleep -Seconds 3
    while ($true) {
        [console]::Beep()
    }
}

dir Function:\*alarm*
dir function:\*alarm* | Select-Object -ExpandProperty Definition

Start-AlarmClock

function Start-AlarmClock {
    param(
        [int] $Seconds
    )

    Start-Sleep -Seconds $Seconds
    while ($true) {
        [console]::Beep()
    }
}

Start-AlarmClock -Seconds 3
Start-AlarmClock -Seconds 2
function Start-AlarmClock {
 <#
 .SYNOPSIS
 After a set number of seconds this function will beep until switched off with <CTRL> + C
 #>
    param(
        [int] $Seconds
    )
    
    Start-Sleep -Seconds $Seconds
    while ($true) {
        [console]::Beep()
    }
}

Get-Help Start-AlarmClock

code Start-AlarmClock.ps1

.\Start-AlarmClock.ps1

. .\Start-AlarmClock.ps1

Start-AlarmClock -Seconds 30
#endregion

#region Modules
New-Item -Path AlarmClock -ItemType Directory
Copy-Item -Path .\Start-AlarmClock.ps1 -Destination .\AlarmClock\AlarmClock.psm1

Import-Module .\AlarmClock\AlarmClock.psm1 -Verbose

$Splat = @{
        Path              = '.\AlarmClock\AlarmClock.psd1'
        Author            = 'Jaap Brasser'
        ModuleVersion     = '1.0.0.0'
        FunctionsToExport = 'Start-AlarmClock'
        Description       = 'Ignite 2018 - AlarmClock module'
        RootModule        = '.\AlarmClock\AlarmClock.psm1'
}
New-ModuleManifest @Splat

code .\AlarmClock\AlarmClock.psd1

Import-Module .\AlarmClock\AlarmClock.psd1 -Verbose
#endregion

#region modules
Find-Module AzureRM
Find-Module VMware.PowerCLI
Find-Module AWSPowerShell

Install-Module Rubrik -Verbose
#endregion

<#
Next steps:
    * Publish to PowerShell Gallery
    * Push to Git
    * Create Azure DevOps module pipeline
#>

'__________               _____                                                
 \______   \ ____________/ ____\___________  _____ _____    ____   ____  ____  
  |     ___// __ \_  __ \   __\/  _ \_  __ \/     \\__  \  /    \_/ ___\/ __ \ 
  |    |   \  ___/|  | \/|  | (  <_> )  | \/  Y Y  \/ __ \|   |  \  \__\  ___/ 
  |____|    \___  >__|   |__|  \____/|__|  |__|_|  (____  /___|  /\___  >___  >
                \/                               \/     \/     \/     \/    \/ '

# Strings and Arrays
$String = 'Hello'
$String

$String += 'World'
$String

$Array = @('Hello')
$Array

$Array += 'World'
$Array

[array]$Array = 'hello'
$Array += 'World'
$Array

$NewArray = Get-Process
$NewArray.GetType().FullName
$NewArray.GetType().BaseType

# Different methods of creating PowerShell custom objects

$OrderedHash = [ordered]@{
    Property1 = 'Hello'
}
$Object = New-Object -TypeName PSCustomObject -Property $OrderedHash
$Object

$Object | Add-Member -MemberType NoteProperty -Name 'Property2' -Value 'World'
$Object | Add-Member -MemberType NoteProperty -Name 'Property2' -Value 'World'
$Object | Add-Member -MemberType NoteProperty -Name 'Property2' -Value 'World'
$Object



$Object = [pscustomobject]@{
    Property1 = 'Hello'
    Date      = Get-Date
    Ticks     = (Get-Date).Ticks    
}

# Demo different method of foreach .ForEach for |ForEach
# For loop
Measure-Command {
    for ($i = 0; $i -lt 100KB; $i++) {
        $null = [math]::pow(2,10)
    }
} | Select-Object @{
    Name = 'Name'
    Expression = {'For loop'}
}, TotalMilliseconds

# ForEach-Object
Measure-Command {
    1..100KB | ForEach-Object {
        $null = [math]::pow(2,10)
    }
} | Select-Object @{
    Name = 'Name'
    Expression = {'Pipeline ForEach-Object'}
}, TotalMilliseconds

# ForEach keyword
Measure-Command {
    foreach ($item in 1..100KB) {
        $null = [math]::pow(2,10)
    }
} | Select-Object @{
    Name = 'Name'
    Expression = {'ForEach keyword'}
}, TotalMilliseconds

# ForEach keyword
Measure-Command {
    @(1..100KB).ForEach{
        $null = [math]::pow(2,10)
    }
} | Select-Object @{
    Name = 'Name'
    Expression = {'.ForEach array method'}
}, TotalMilliseconds

###
# Working with files
###

# Get-ChildItem
(Get-ChildItem C:\Temp -Recurse -force -erroraction SilentlyContinue | Measure-Object length -Sum).sum 
 
#Good old Dir, recursively
((cmd /c dir C:\Temp /-C /S /A:-D-L)[-2] -split '\s+')[3]
 
#RoboCopy in list only mode: 
(robocopy.exe C:\Temp c:\thisdoesnotexist /L /XJ /R:0 /W:1 /NP /E /BYTES /NFL /NDL /NJH /MT:64)[-4] -replace '\D+(\d+).*','$1'

# Measure performance of different methods
Measure-Command {
    (Get-ChildItem C:\Temp -Recurse -force -erroraction SilentlyContinue | Measure-Object length -Sum).sum 
} | Select-Object @{
    Name = 'Name'
    Expression = {'Only PowerShell'}
}, TotalMilliseconds

Measure-Command {
    ((cmd /c dir C:\Temp /-C /S /A:-D-L)[-2] -split '\s+')[3]
} | Select-Object @{
    Name = 'Name'
    Expression = {'dir command'}
}, TotalMilliseconds

Measure-Command {
    (robocopy.exe C:\Temp c:\thisdoesnotexist /L /XJ /R:0 /W:1 /NP /E /BYTES /NFL /NDL /NJH /MT:64)[-4] -replace '\D+(\d+).*','$1'
} | Select-Object @{
    Name = 'Name'
    Expression = {'robocopy'}
}, TotalMilliseconds


# Have some fun with operators
Get-ChildItem -Path 'C:\Users\Jaap Brasser'

Get-ChildItem -Path 'C:\Users\Jaap Brasser' | ? FullName -match 'C:\\Users\\Jaap Brasser\\Documents'
Get-ChildItem -Path 'C:\Users\Jaap Brasser' | ? FullName -match "$([regex]::Escape('C:\Users\Jaap Brasser\Documents'))"

# Using regular expressions to match around 
@'
???
###
!!!
We want this 1
We want this 2
Pattern
We want this 3
We want this 4
???
###
!!!
'@ -match '(?<c1>.*)\n(?<c2>.*)\n(?<p>Pattern).*?\n(?<c3>.*)\n(?<c4>.*)\n'
$null = $Matches.Remove(0)
[PSCustomObject]$Matches

# Create PSObjects with [pscustomobject] / ::New
Measure-Command {1..50000 | ForEach-Object {
    [pscustomobject]@{
        Property1 = 'Hello'
        Date      = Get-Date
        Ticks     = (Get-Date).Ticks
        'Object#' = $_    
    }
}} | Select-Object @{
    Name = 'Name'
    Expression = {'without new'}
}, TotalMilliseconds

Measure-Command {1..50000 | ForEach-Object {
    [pscustomobject]::new([ordered]@{
        Property1 = 'Hello'
        Date      = Get-Date
        Ticks     = (Get-Date).Ticks
        'Object#' = $_    
    })
}} | Select-Object @{
    Name = 'Name'
    Expression = {'with new'}
}, TotalMilliseconds

# Splatting

New-AdUser -SamAccountName jbrasser `
           -UserPrincipalName jbrasser.rubrik.com `
           -Name JBrasser `
           -DisplayName 'Jaap Brasser' `
           -GivenName Jaap `
           -SurName Brasser `
           -Department IT `
           -Path "CN=Users,DC=rubrik,DC=com" `
           -AccountPassword (ConvertTo-SecureString "PSDayIsAwesome!" -AsPlainText -force) `
           -Enabled $True `
           -PasswordNeverExpires $True

$Splat = @{
    SamAccountName = 'jbrasser'
    UserPrincipalName = 'jbrasser.rubrik.com'
    Name = 'JBrasser'
    DisplayName = 'Jaap Brasser'
    GivenName = 'Jaap'
    SurName = 'Brasser'
    Department = 'IT'
    Path = 'CN=Users,DC=rubrik,DC=com'
    AccountPassword = (ConvertTo-SecureString "PSDayIsAwesome!" -AsPlainText -force)
    Enabled = $True
    PasswordNeverExpires = $True
}

$Splat

New-ADUser @Splat