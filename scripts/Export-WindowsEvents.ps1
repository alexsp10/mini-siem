<#
.SYNOPSIS
    Export Windows event logs to JSON lines that mini-siem can ingest.

.DESCRIPTION
    Reads events with Get-WinEvent and writes one JSON object per line with the
    named EventData fields (taken from the event XML, so field names are kept).
    Reading the Security log needs an elevated (Administrator) PowerShell.
    Sysmon must be installed for the Sysmon channel to exist; missing or
    inaccessible logs are skipped with a warning.

.EXAMPLE
    .\scripts\Export-WindowsEvents.ps1 -Hours 24 -OutFile my-events.jsonl
    minisiem run my-events.jsonl --fresh
#>
[CmdletBinding()]
param(
    [string[]] $LogName = @('Security', 'System', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational'),
    [int] $Hours = 24,
    [int] $MaxEvents = 50000,
    [string] $OutFile = 'windows-events.jsonl'
)

$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$Hours)
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
$writer = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
$total = 0

try {
    foreach ($log in $LogName) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -MaxEvents $MaxEvents
        }
        catch {
            Write-Warning "Skipping '$log': $($_.Exception.Message)"
            continue
        }
        $count = 0
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $data = [ordered]@{}
            if ($xml.Event.EventData) {
                foreach ($item in $xml.Event.EventData.Data) {
                    if ($item -is [System.Xml.XmlElement] -and $item.HasAttribute('Name')) {
                        $data[$item.GetAttribute('Name')] = $item.InnerText
                    }
                }
            }
            if ($xml.Event.UserData) {
                # e.g. 1102 (log cleared) keeps its fields under UserData/LogFileCleared
                foreach ($child in $xml.Event.UserData.ChildNodes) {
                    foreach ($node in $child.ChildNodes) { $data[$node.LocalName] = $node.InnerText }
                }
            }
            $record = [ordered]@{
                TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
                Id          = $event.Id
                Channel     = $event.LogName
                Computer    = $event.MachineName
                EventData   = $data
            }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 4))
            $count++
        }
        Write-Host "$log : $count events"
        $total += $count
    }
}
finally {
    $writer.Close()
}
Write-Host "Wrote $total events to $path"
