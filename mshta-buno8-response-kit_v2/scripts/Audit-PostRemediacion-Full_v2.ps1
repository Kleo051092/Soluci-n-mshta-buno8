<#
.SYNOPSIS
  POST-REMEDIATION FULL AUDIT (READ-ONLY).
  Verify that no weak points remain after remediation of mshta/buno8/Wacatac/OfferCore incident.
  Collects evidence across persistence, services/drivers, proxy/network, Defender posture, and browser remnants.

.DESCRIPTION
  - Read-only: only collects evidence to C:\ProgramData\MshtaCleanup\PostAudit-YYYYMMDD-HHMMSS\
  - Checks: Scheduled Tasks, Run/RunOnce, WMI subscriptions, Startup, INetCache traces,
            Services and Drivers, IFEO hijacks, Script Host status, AppInit_DLLs,
            Proxy/WinHTTP, HOSTS, Firewall rules (program paths), Defender status/events,
            Browser remnants (Chrome/Edge) including policies/tasks/services,
            Network snapshot (netstat), Certificates recent additions (System/CurrentUser).
  - Produces a PASS/WARN style summary in PostAudit_Summary.txt with key findings.

.PARAMETER Days
  Time window for Defender and recent certificates/events. Default 30.

.PARAMETER RegexSuspicious
  Custom regex for suspicious command-lines (default targets mshta/hta/wscript/cscript/powershell -enc/bitsadmin/rundll32 javascript/certutil/curl).

.EXAMPLE
  PowerShell (Admin):
  Set-ExecutionPolicy Bypass -Scope Process -Force; .\Audit-PostRemediacion-Full_v2.ps1 -Days 45
#>

[CmdletBinding()]
param(
  [int]$Days = 30,
  [string]$RegexSuspicious = 'mshta|\.hta\b|buno8\.ru|wscript\.exe|cscript\.exe|powershell\.exe\s+-enc|bitsadmin|rundll32\.exe.*(javascript|_)|certutil(\.exe)?\s+-urlcache|-split\s+invoke|iwr\s+http|curl\s+http'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function New-Dir([string]$p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
function Log { param([string]$Message)
  $line = "[{0}] {1}" -f (Get-Date -Format 'u'), $Message
  Write-Host $line
  Add-Content -Path $Global:LogFile -Value $line
}

# Root output
$Root = Join-Path $env:ProgramData "MshtaCleanup"
New-Dir $Root
$TS = Get-Date -Format 'yyyyMMdd-HHmmss'
$Out = Join-Path $Root ("PostAudit-{0}" -f $TS)
New-Dir $Out
$Global:LogFile = Join-Path $Out "post_audit.log"

Log "==== POST-REMEDIATION AUDIT START ===="
Log ("Params: Days={0}" -f $Days)

# 0) System and network baseline
try {
  $sysDir = Join-Path $Out "System"; New-Dir $sysDir
  systeminfo | Out-File -FilePath (Join-Path $sysDir 'systeminfo.txt') -Encoding UTF8
  Get-ComputerInfo | Out-File -FilePath (Join-Path $sysDir 'computerinfo.txt') -Encoding UTF8
  gwmi Win32_OperatingSystem | select CSName,Version,BuildNumber,LastBootUpTime | Export-Csv -LiteralPath (Join-Path $sysDir 'os_basic.csv') -NoTypeInformation -Encoding UTF8
} catch { Log ("WARN System baseline: {0}" -f $_.Exception.Message) }

try {
  $netDir = Join-Path $Out "Network"; New-Dir $netDir
  ipconfig /all | Out-File -FilePath (Join-Path $netDir 'ipconfig_all.txt') -Encoding UTF8
  route print | Out-File -FilePath (Join-Path $netDir 'route_print.txt') -Encoding UTF8
  netstat -ano | Out-File -FilePath (Join-Path $netDir 'netstat_ano.txt') -Encoding UTF8
  netsh winhttp show proxy | Out-File -FilePath (Join-Path $netDir 'winhttp_proxy.txt') -Encoding UTF8
  foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings','HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings')) {
    try { reg query ($k -replace 'HKCU:\\','HKCU\') | Out-File -FilePath (Join-Path $netDir ((Split-Path $k -Leaf) + '.txt')) -Encoding UTF8 } catch {}
  }
  $hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
  if (Test-Path $hosts) { Copy-Item -LiteralPath $hosts -Destination (Join-Path $netDir "hosts.snapshot") -Force }
  Log "Network/proxy/HOSTS captured."
} catch { Log ("WARN Network snapshot: {0}" -f $_.Exception.Message) }

# 1) Scheduled Tasks (by Actions)
try {
  $tasksDir = Join-Path $Out 'ScheduledTasks'; New-Dir $tasksDir
  $all = Get-ScheduledTask -ErrorAction SilentlyContinue
  $sus = foreach ($t in $all) {
    $hit = $false
    foreach ($a in @($t.Actions)) {
      $exec = $null; $args = $null
      try { $exec = $a.Execute } catch {}
      try { $args = $a.Arguments } catch {}
      if (("$exec $args") -match $RegexSuspicious) { $hit = $true; break }
    }
    if ($hit) { $t }
  }
  $sus |
    Select TaskPath, TaskName, State,
           @{n='Actions';e={ (@($_.Actions) | % { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | ' }} |
    Export-Csv -LiteralPath (Join-Path $tasksDir 'suspicious_tasks.csv') -NoTypeInformation -Encoding UTF8
  Log ("Suspicious tasks: {0}" -f (@($sus).Count))
} catch { Log ("WARN tasks: {0}" -f $_.Exception.Message) }

# 2) Run/RunOnce
try {
  $runDir = Join-Path $Out 'RunKeys'; New-Dir $runDir
  $paths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  )
  $rows = @()
  foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    foreach ($pp in $props.PSObject.Properties) {
      if ($pp.MemberType -ne 'NoteProperty') { continue }
      $val = [string]$pp.Value
      if ($val -and ($val -match $RegexSuspicious)) {
        $rows += [pscustomobject]@{ Path=$p; Name=$pp.Name; Value=$val }
      }
    }
  }
  $rows | Export-Csv -LiteralPath (Join-Path $runDir 'run_suspicious.csv') -NoTypeInformation -Encoding UTF8
  Log ("Run/RunOnce hits: {0}" -f (@($rows).Count))
} catch { Log ("WARN Run/RunOnce: {0}" -f $_.Exception.Message) }

# 3) WMI subscriptions
try {
  $wmiDir = Join-Path $Out 'WMI'; New-Dir $wmiDir
  $ns='root\subscription'
  $consCmd = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
  $consScr = Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
  $filters = Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue
  $binds  = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
  $consCmd | Select Name, CommandLineTemplate | Export-Csv -LiteralPath (Join-Path $wmiDir 'CommandLineEventConsumer.csv') -NoTypeInformation -Encoding UTF8
  $consScr | Select Name, ScriptingEngine | Export-Csv -LiteralPath (Join-Path $wmiDir 'ActiveScriptEventConsumer.csv') -NoTypeInformation -Encoding UTF8
  $filters | Select Name, Query | Export-Csv -LiteralPath (Join-Path $wmiDir '__EventFilter.csv') -NoTypeInformation -Encoding UTF8
  $binds  | Select Filter, Consumer | Export-Csv -LiteralPath (Join-Path $wmiDir '__FilterToConsumerBinding.csv') -NoTypeInformation -Encoding UTF8
  $susWmi = @()
  $regexWmi = $RegexSuspicious
  $susWmi += $consCmd | ? { $_.CommandLineTemplate -match $regexWmi }
  $susWmi += $consScr | ? { $_.ScriptText -match $regexWmi }
  $susWmi += $filters | ? { $_.Query -match $regexWmi }
  $susWmi | Select * | Export-Csv -LiteralPath (Join-Path $wmiDir 'suspicious_wmi.csv') -NoTypeInformation -Encoding UTF8
  Log ("Suspicious WMI items: {0}" -f (@($susWmi).Count))
} catch { Log ("WARN WMI: {0}" -f $_.Exception.Message) }

# 4) Startup and INetCache traces
try {
  $startDir = Join-Path $Out 'Startup'; New-Dir $startDir
  $startupDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
  $rowsS = @()
  foreach ($s in $startupDirs) {
    if (-not (Test-Path $s)) { continue }
    Get-ChildItem -Path $s -File -Include *.lnk,*.url,*.hta,*.js,*.vbs,*.cmd,*.bat,*.ps1 -ErrorAction SilentlyContinue | ForEach-Object {
      $detail = ""
      if ($_.Extension -ieq ".lnk") {
        try { $w = New-Object -ComObject WScript.Shell; $sc = $w.CreateShortcut($_.FullName); $detail = "$($sc.TargetPath) $($sc.Arguments)" } catch {}
      } else {
        try { $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue; $detail = $c.Substring(0,[Math]::Min(200,$c.Length)) } catch {}
      }
      if ($detail -match $RegexSuspicious) {
        $rowsS += [pscustomobject]@{ File=$_.FullName; Detail=$detail }
      }
    }
  }
  $rowsS | Export-Csv -LiteralPath (Join-Path $startDir 'startup_suspicious.csv') -NoTypeInformation -Encoding UTF8

  $inetDir = Join-Path $Out 'INetCache'; New-Dir $inetDir
  $inet = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
  if (Test-Path $inet) {
    Get-ChildItem $inet -Recurse -ErrorAction SilentlyContinue | ? { $_.FullName -match 'buno8\.ru|\.hta$' } |
      Select FullName, Length, LastWriteTime | Export-Csv -LiteralPath (Join-Path $inetDir 'inetcache_hits.csv') -NoTypeInformation -Encoding UTF8
  }
} catch { Log ("WARN Startup/INetCache: {0}" -f $_.Exception.Message) }

# 5) Services and Drivers
try {
  $svcDir = Join-Path $Out 'ServicesDrivers'; New-Dir $svcDir
  $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
  $svcs | Select Name, DisplayName, State, StartMode, PathName |
    Export-Csv -LiteralPath (Join-Path $svcDir 'services_all.csv') -NoTypeInformation -Encoding UTF8
  $svcSus = $svcs | ? {
    $_.PathName -match $RegexSuspicious -or
    $_.PathName -match '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\'
  }
  $svcSus | Select Name, DisplayName, State, StartMode, PathName |
    Export-Csv -LiteralPath (Join-Path $svcDir 'services_suspicious.csv') -NoTypeInformation -Encoding UTF8

  $drv = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
  $drv | Select Name, State, PathName, StartMode |
    Export-Csv -LiteralPath (Join-Path $svcDir 'drivers_all.csv') -NoTypeInformation -Encoding UTF8
  $drvSus = $drv | ? { $_.PathName -match $RegexSuspicious -or $_.Name -match 'FL2000|Fresco|Wacatac|OfferCore' }
  $drvSus | Select Name, State, PathName, StartMode |
    Export-Csv -LiteralPath (Join-Path $svcDir 'drivers_suspicious.csv') -NoTypeInformation -Encoding UTF8
} catch { Log ("WARN Services/Drivers: {0}" -f $_.Exception.Message) }

# 6) IFEO, Script Host, AppInit_DLLs
try {
  $secDir = Join-Path $Out 'SecurityPosture'; New-Dir $secDir
  $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
  $ifeoRows = @()
  foreach ($exe in @('mshta.exe','wscript.exe','cscript.exe')) {
    $k = Join-Path $ifeo $exe
    $dbg = $null; if (Test-Path $k) { try { $dbg = (Get-ItemProperty -Path $k -Name Debugger -ErrorAction SilentlyContinue).Debugger } catch {} }
    $ifeoRows += [pscustomobject]@{ EXE=$exe; Debugger=$dbg }
  }
  $ifeoRows | Export-Csv -LiteralPath (Join-Path $secDir 'IFEO_status.csv') -NoTypeInformation -Encoding UTF8

  $wshKey = 'HKLM:\Software\Microsoft\Windows Script Host\Settings'
  $wshEnabled = $null
  if (Test-Path $wshKey) { try { $wshEnabled = (Get-ItemProperty -Path $wshKey -Name Enabled -ErrorAction SilentlyContinue).Enabled } catch {} }
  [pscustomobject]@{ WSH_Enabled=$wshEnabled } | Export-Csv -LiteralPath (Join-Path $secDir 'WSH_status.csv') -NoTypeInformation -Encoding UTF8

  $appInitKey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
  $appInit = $null; $loadAppInit = $null
  try {
    $p = Get-ItemProperty -Path $appInitKey -ErrorAction SilentlyContinue
    $appInit = $p.AppInit_DLLs; $loadAppInit = $p.LoadAppInit_DLLs
  } catch {}
  [pscustomobject]@{ AppInit_DLLs=$appInit; LoadAppInit_DLLs=$loadAppInit } |
    Export-Csv -LiteralPath (Join-Path $secDir 'AppInit_status.csv') -NoTypeInformation -Encoding UTF8
} catch { Log ("WARN IFEO/WSH/AppInit: {0}" -f $_.Exception.Message) }

# 7) Firewall rules
try {
  $fwDir = Join-Path $Out 'Firewall'; New-Dir $fwDir
  netsh advfirewall firewall show rule name=all verbose | Out-File -FilePath (Join-Path $fwDir 'rules_all.txt') -Encoding UTF8
  $rules = Select-String -Path (Join-Path $fwDir 'rules_all.txt') -Pattern 'Program:\s*(.*)$' | % {
    $m = [regex]::Match($_.Line, 'Program:\s*(.*)$')
    if ($m.Success) { $m.Groups[1].Value.Trim() }
  } | Where-Object { $_ -match '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\' }
  $rules | Set-Content -LiteralPath (Join-Path $fwDir 'rules_programs_userpaths.txt') -Encoding UTF8
} catch { Log ("WARN Firewall: {0}" -f $_.Exception.Message) }

# 8) Defender posture and events
try {
  $defDir = Join-Path $Out 'Defender'; New-Dir $defDir
  try { Get-MpComputerStatus | Export-Csv -LiteralPath (Join-Path $defDir 'MpComputerStatus.csv') -NoTypeInformation -Encoding UTF8 } catch {}
  try { Get-MpPreference | Export-Csv -LiteralPath (Join-Path $defDir 'MpPreference.csv') -NoTypeInformation -Encoding UTF8 } catch {}
  try { Get-MpThreat | Export-Csv -LiteralPath (Join-Path $defDir 'Get-MpThreat.csv') -NoTypeInformation -Encoding UTF8 } catch {}
  try { Get-MpThreatDetection | Export-Csv -LiteralPath (Join-Path $defDir 'Get-MpThreatDetection.csv') -NoTypeInformation -Encoding UTF8 } catch {}
  try {
    $from = (Get-Date).AddDays(-[math]::Abs($Days))
    $ev = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue |
      Where-Object { $_.TimeCreated -ge $from }
    $ev | Select TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      Export-Csv -LiteralPath (Join-Path $defDir 'Defender_Operational_Events.csv') -NoTypeInformation -Encoding UTF8
  } catch {}
} catch { Log ("WARN Defender: {0}" -f $_.Exception.Message) }

# 9) Browser remnants (Chrome/Edge)
try {
  $brDir = Join-Path $Out 'Browser'; New-Dir $brDir
  $chromePaths = @(
    "$env:ProgramFiles\Google\Chrome",
    "$env:ProgramFiles(x86)\Google\Chrome",
    "$env:LOCALAPPDATA\Google\Chrome",
    "$env:LOCALAPPDATA\Google\Chrome\User Data"
  )
  $chromePaths | % { [pscustomobject]@{ Path=$_; Exists=(Test-Path $_) } } |
    Export-Csv -LiteralPath (Join-Path $brDir 'chrome_paths_exists.csv') -NoTypeInformation -Encoding UTF8
  $pols = @('HKLM:\Software\Policies\Google\Chrome','HKCU:\Software\Policies\Google\Chrome','HKLM:\Software\Policies\Google','HKCU:\Software\Policies\Google')
  $polRows = @()
  foreach ($k in $pols) {
    if (Test-Path $k) {
      try {
        $props = Get-ItemProperty -Path $k
        foreach ($pp in $props.PSObject.Properties) {
          if ($pp.MemberType -eq 'NoteProperty') { $polRows += [pscustomobject]@{ HiveKey=$k; Name=$pp.Name; Value=$pp.Value } }
        }
      } catch {}
    }
  }
  $polRows | Export-Csv -LiteralPath (Join-Path $brDir 'chrome_policies.csv') -NoTypeInformation -Encoding UTF8
  $gtasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ? { $_.TaskName -match '^GoogleUpdate' -or $_.TaskPath -match '\\Google\\' }
  $gtasks | Select TaskPath, TaskName, State | Export-Csv -LiteralPath (Join-Path $brDir 'google_tasks.csv') -NoTypeInformation -Encoding UTF8
  $gsvc = foreach ($svc in @('gupdate','gupdatem')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { [pscustomobject]@{ Name=$s.Name; Status=$s.Status; StartType=$s.StartType } }
  }
  $gsvc | Export-Csv -LiteralPath (Join-Path $brDir 'google_services.csv') -NoTypeInformation -Encoding UTF8
} catch { Log ("WARN Browser remnants: {0}" -f $_.Exception.Message) }

# 10) Certificates (recent additions)
try {
  $certDir = Join-Path $Out 'Certificates'; New-Dir $certDir
  $from = (Get-Date).AddDays(-[math]::Abs($Days))
  $stores = @(
    'Cert:\LocalMachine\Root','Cert:\LocalMachine\CA',
    'Cert:\CurrentUser\Root','Cert:\CurrentUser\CA'
  )
  foreach ($st in $stores) {
    try {
      $rows = Get-ChildItem -Path $st -ErrorAction SilentlyContinue |
        Select Subject, Issuer, NotBefore, NotAfter, Thumbprint, PSParentPath, EnhancedKeyUsageList, FriendlyName |
        Where-Object { $_.NotBefore -ge $from }
      $safe = ($st -replace '[:\\]','_')
      $rows | Export-Csv -LiteralPath (Join-Path $certDir ("recent_{0}.csv" -f $safe)) -NoTypeInformation -Encoding UTF8
    } catch {}
  }
} catch { Log ("WARN Certificates: {0}" -f $_.Exception.Message) }

# 11) Associations
try {
  $assocDir = Join-Path $Out 'Associations'; New-Dir $assocDir
  $keys = @(
    'HKCR:\.hta','HKCR:\.js','HKCR:\.vbs','HKCR:\.cmd','HKCR:\.bat','HKCR:\.ps1',
    'HKCR:\htafile\shell\open\command','HKCR:\jsfile\shell\open\command','HKCR:\vbsfile\shell\open\command'
  )
  $rows = @()
  foreach ($k in $keys) {
    if (Test-Path $k) {
      try {
        $props = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).PSObject.Properties | ? { $_.MemberType -eq 'NoteProperty' }
        foreach ($p in $props) { $rows += [pscustomobject]@{ Key=$k; Name=$p.Name; Value=$p.Value } }
        $rows += [pscustomobject]@{ Key=$k; Name='(Default)'; Value=(Get-Item -Path $k).GetValue('') }
      } catch {}
    }
  }
  $rows | Export-Csv -LiteralPath (Join-Path $assocDir 'associations_snapshot.csv') -NoTypeInformation -Encoding UTF8
} catch { Log ("WARN Associations: {0}" -f $_.Exception.Message) }

# 12) PASS/WARN summary (no ternary operator; WinPS 5.1 compatible)
try {
  $sum = @()
  $sum += "POST-REMEDIATION SUMMARY (indicators only, not confirmation)"
  $sum += ""
  function CountCsv($p) { if (Test-Path $p) { try { return (Import-Csv -LiteralPath $p).Count } catch { return 0 } } else { return 0 } }
  $cTasks = CountCsv (Join-Path (Join-Path $Out 'ScheduledTasks') 'suspicious_tasks.csv')
  $cRun   = CountCsv (Join-Path (Join-Path $Out 'RunKeys') 'run_suspicious.csv')
  $cWmi   = CountCsv (Join-Path (Join-Path $Out 'WMI') 'suspicious_wmi.csv')
  $cStart = CountCsv (Join-Path (Join-Path $Out 'Startup') 'startup_suspicious.csv')
  $cSvc   = CountCsv (Join-Path (Join-Path $Out 'ServicesDrivers') 'services_suspicious.csv')
  $cDrv   = CountCsv (Join-Path (Join-Path $Out 'ServicesDrivers') 'drivers_suspicious.csv')
  $fwFile = Join-Path (Join-Path $Out 'Firewall') 'rules_programs_userpaths.txt'
  $cFW = 0
  if (Test-Path $fwFile) { $cFW = (Get-Content -LiteralPath $fwFile).Count }
  $cChromePaths = CountCsv (Join-Path (Join-Path $Out 'Browser') 'chrome_paths_exists.csv')
  $cChromePols  = CountCsv (Join-Path (Join-Path $Out 'Browser') 'chrome_policies.csv')
  $cGTasks      = CountCsv (Join-Path (Join-Path $Out 'Browser') 'google_tasks.csv')
  $cGSvc        = CountCsv (Join-Path (Join-Path $Out 'Browser') 'google_services.csv')

  $sum += ("Suspicious Tasks: {0}" -f $cTasks)
  $sum += ("Run/RunOnce suspicious: {0}" -f $cRun)
  $sum += ("WMI suspicious: {0}" -f $cWmi)
  $sum += ("Startup suspicious: {0}" -f $cStart)
  $sum += ("Services suspicious: {0}" -f $cSvc)
  $sum += ("Drivers suspicious: {0}" -f $cDrv)
  $sum += ("Firewall rules with user-writable program paths: {0}" -f $cFW)
  $sum += ""
  $sum += ("Chrome paths present entries: {0} (0 means fully removed)" -f $cChromePaths)
  $sum += ("Chrome policies rows: {0} (0 means none)" -f $cChromePols)
  $sum += ("GoogleUpdate tasks: {0}" -f $cGTasks)
  $sum += ("GoogleUpdate services: {0}" -f $cGSvc)
  $sum += ""
  try {
    $mp = Import-Csv -LiteralPath (Join-Path (Join-Path $Out 'Defender') 'MpPreference.csv') -ErrorAction SilentlyContinue
    if ($mp) {
      $row = $mp | Select-Object -First 1
      $sum += ("Defender: PUAProtection={0}. Check MpComputerStatus.csv for full posture." -f $row.PUAProtection)
    }
  } catch {}
  $sumPath = Join-Path $Out 'PostAudit_Summary.txt'
  $sum | Set-Content -LiteralPath $sumPath -Encoding UTF8
  Log ("Summary written: {0}" -f $sumPath)
} catch { Log ("WARN summary: {0}" -f $_.Exception.Message) }

Log "==== POST-REMEDIATION AUDIT END ===="
Write-Host ("Evidence: {0}" -f $Out)
