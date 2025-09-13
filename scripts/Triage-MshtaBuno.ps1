<#
.SYNOPSIS
  Triage rápido (solo lectura) para investigar abuso de mshta.exe y el dominio s.buno8.ru.

.DESCRIPTION
  - No elimina ni modifica nada. Solo recolecta evidencia y la comprime en un ZIP.
  - Revisa: eventos (Defender/Security), detecciones Defender, tareas programadas,
    Run/RunOnce, WMI subscriptions, carpetas de Inicio, Prefetch de mshta, HOSTS,
    DNS cache y logs de Defender/Offline Scan (si existen).
#>

[CmdletBinding()]
param(
  [int]$DaysBack = 14,
  [string]$TargetDomain = "s.buno8.ru"
)

function Test-Admin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
  Write-Error "Ejecuta PowerShell como Administrador."
  exit 1
}

$Base = Join-Path $env:ProgramData "MshtaCleanup"
$Ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$Out = Join-Path $Base "Triage-$Ts"
$Evidence = $Out
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null

# Utilidad de guardado seguro
function Save-Text($text, $path) {
  $dir = Split-Path $path -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $text | Out-File -LiteralPath $path -Encoding UTF8
}

$startTime = (Get-Date).AddDays(-$DaysBack)

# 0) Version info
Save-Text ("Hostname: {0}`nUser: {1}`nOS: {2}`nTime: {3}" -f $env:COMPUTERNAME,$env:USERNAME,(Get-ComputerInfo | Select-Object OsName,OsVersion | Out-String),(Get-Date)) (Join-Path $Evidence '00_system_info.txt')

# 1) Procesos mshta (si hay)
try {
  Get-CimInstance Win32_Process -Filter "name='mshta.exe'" |
    Select ProcessId, ParentProcessId, CreationDate, CommandLine |
    Export-Csv -LiteralPath (Join-Path $Evidence '01_mshta_processes.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 2) Detecciones Defender
try {
  Get-MpThreatDetection | Export-Csv -LiteralPath (Join-Path $Evidence '02_defender_threat_detections.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  Get-MpThreat | Export-Csv -LiteralPath (Join-Path $Evidence '02b_defender_threats.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# Copia logs de Defender si existen
$defLogs = @(
  "C:\ProgramData\Microsoft\Windows Defender\Support",
  "C:\Windows\Microsoft Antimalware\Support",
  "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
)
foreach ($p in $defLogs) {
  if (Test-Path $p) {
    $dst = Join-Path $Evidence ("02_logs" + ($p -replace '[:\\]','_'))
    robocopy $p $dst /E /NFL /NDL /NJH /NJS /NP | Out-Null
  }
}

# 3) Eventos de Defender (últimos $DaysBack días)
try {
  $defEv = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$startTime} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'mshta|buno8\.ru' -or $_.Id -in 1006,1007,1008,1015,1116,1121 } |
    Select TimeCreated, Id, ProviderName, LevelDisplayName, Message
  $defEv | Export-Csv -LiteralPath (Join-Path $Evidence '03_events_defender_filtered.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 4) Eventos de Seguridad (si auditing habilitado) buscando mshta
try {
  $secEv = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)mshta\.exe|buno8\.ru' -or $_.Id -in 4688,5156,5157 } |
    Select TimeCreated, Id, ProviderName, LevelDisplayName, Message
  $secEv | Export-Csv -LiteralPath (Join-Path $Evidence '04_events_security_filtered.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 5) Tareas Programadas sospechosas y export
try {
  $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
  $sus = $tasks | Where-Object { (($_ | Export-ScheduledTask) | Out-String) -match 'mshta|buno8\.ru' }
  $tDir = Join-Path $Evidence '05_scheduled_tasks'
  if ($sus) {
    New-Item -ItemType Directory -Path $tDir -Force | Out-Null
    foreach ($t in $sus) {
      ($t | Export-ScheduledTask) | Set-Content -LiteralPath (Join-Path $tDir (("{0}_{1}.xml" -f ($t.TaskPath -replace '[\\/:"*?<>|]','_').Trim('_'), ($t.TaskName -replace '[\\/:"*?<>|]','_').Trim('_')))) -Encoding UTF8
    }
  }
  $tasks | Select TaskPath, TaskName, State |
    Export-Csv -LiteralPath (Join-Path $Evidence '05b_all_tasks_list.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 6) Run/RunOnce
$runPaths = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)
$runOut = @()
foreach ($p in $runPaths) {
  if (Test-Path $p) {
    $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    if ($props) {
      $props.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
        $runOut += [pscustomobject]@{ Path=$p; Name=$_.Name; Value=$_.Value }
      }
    }
  }
}
$runOut | Export-Csv -LiteralPath (Join-Path $Evidence '06_run_keys.csv') -NoTypeInformation -Encoding UTF8

# 7) WMI Subscriptions
try {
  $ns='root\subscription'
  $consCmd = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Select Name, CommandLineTemplate
  $consScr = Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select Name, ScriptingEngine
  $filters = Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue | Select Name, Query
  $binds = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select Filter, Consumer
  $consCmd | Export-Csv -LiteralPath (Join-Path $Evidence '07_wmi_CommandLineEventConsumer.csv') -NoTypeInformation -Encoding UTF8
  $consScr | Export-Csv -LiteralPath (Join-Path $Evidence '07_wmi_ActiveScriptEventConsumer.csv') -NoTypeInformation -Encoding UTF8
  $filters | Export-Csv -LiteralPath (Join-Path $Evidence '07_wmi___EventFilter.csv') -NoTypeInformation -Encoding UTF8
  $binds | Export-Csv -LiteralPath (Join-Path $Evidence '07_wmi___FilterToConsumerBinding.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 8) Carpetas de Inicio + targets de LNK
try {
  $startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  )
  $rows = @()
  foreach ($s in $startupDirs) {
    if (-not (Test-Path $s)) { continue }
    $files = Get-ChildItem -Path $s -File -Include *.lnk,*.url,*.hta,*.js,*.vbs,*.cmd,*.bat,*.ps1 -ErrorAction SilentlyContinue
    foreach ($f in $files) {
      $targetDetail = ""
      if ($f.Extension -ieq ".lnk") {
        try {
          $wsh = New-Object -ComObject WScript.Shell
          $sc = $wsh.CreateShortcut($f.FullName)
          $targetDetail = "$($sc.TargetPath) $($sc.Arguments)"
        } catch {}
      } elseif ($f.Extension -ieq ".url") {
        try {
          $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
          $targetDetail = (($content -split "`n") -match '^URL=') -join ';'
        } catch {}
      } else {
        try {
          $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
          $targetDetail = ($content.Substring(0, [Math]::Min(300, $content.Length))).Replace("`r"," ").Replace("`n"," ")
        } catch {}
      }
      $rows += [pscustomobject]@{ Path=$f.FullName; Target=$targetDetail }
    }
  }
  $rows | Export-Csv -LiteralPath (Join-Path $Evidence '08_startup_files.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# 9) Prefetch de mshta
try {
  $pf = "$env:SystemRoot\Prefetch"
  if (Test-Path $pf) {
    $dst = Join-Path $Evidence '09_prefetch'
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    Copy-Item -Path (Join-Path $pf 'MSHTA*.pf') -Destination $dst -ErrorAction SilentlyContinue
  }
} catch {}

# 10) HOSTS y DNS
try {
  $hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
  if (Test-Path $hosts) { Copy-Item -LiteralPath $hosts -Destination (Join-Path $Evidence '10_hosts_copy') -Force }
  cmd /c ipconfig /displaydns > (Join-Path $Evidence '10_dns_cache.txt') 2>&1
} catch {}

# 11) Netstat actual (puede no reflejar el pasado)
try {
  cmd /c netstat -ano > (Join-Path $Evidence '11_netstat.txt') 2>&1
} catch {}

# 12) Schtasks complet
try {
  cmd /c schtasks /query /fo LIST /v > (Join-Path $Evidence '12_schtasks_verbose.txt') 2>&1
} catch {}

# ZIP final
$zipPath = Join-Path $Base ("Triage-" + $Ts + ".zip")
Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
[System.IO.Compression.ZipFile]::CreateFromDirectory($Evidence, $zipPath)

Write-Host "Listo. Evidencia: $Evidence"
Write-Host "ZIP: $zipPath"
