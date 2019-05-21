Get-PSReadLineOption | Select-Object HistorySavePath

$basePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty $basePath -Name OutputDirectory -Value C:\Transcription
Set-ItemProperty $basePath -Name IncludeInvocationHeader -Value 1

Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value 1