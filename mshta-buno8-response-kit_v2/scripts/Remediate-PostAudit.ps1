<#
.SYNOPSIS
  Post-audit remediation and hardening:
  - Removes persistence and artifacts found (Tasks, Run/RunOnce, WMI, Startup, INetCache).
  - Full cleanup of Google Chrome remnants (folders, tasks, services, policies, classes).
  - Restores Internet connectivity (proxy direct, Winsock/IP reset) if requested.
  - Hardens system to block mshta and common script abuse (optional).
  - Enables Microsoft Defender protections and runs a scan.
  - (Optional) Repairs system files (SFC/DISM).

.DESCRIPTION
  Use after running the audit scripts. You can pass -AuditRoot to target a specific audit folder
  (e.g. C:\ProgramData\MshtaCleanup\Audit-YYYYMMDD-HHMMSS). If omitted, the script will also
  perform live scanning and cleanup using the same indicators.

.PARAMETER AuditRoot
  Path to a prior audit folder to remove exactly what was found (CSV-driven cleanup).

.PARAMETER DryRun
  Simulate actions without making changes (logs only).

.PARAMETER DeepCleanChrome
  Remove Google Chrome remnants: folders, GoogleUpdate tasks/services, policies, registry classes.

.PARAMETER ResetNetwork
  Reset WinHTTP/IE proxy to direct, reset Winsock/IP, flush DNS (reboot recommended).

.PARAMETER DisableMshta
  Set IFEO to intercept mshta.exe (Debugger=notepad.exe). Reversible with -EnableMshta.

.PARAMETER EnableMshta
  Remove IFEO Debugger for mshta.exe (re-enable mshta).

.PARAMETER HardenScripts
  Extra hardening: IFEO for wscript.exe and cscript.exe; disable Windows Script Host (global).
  WARNING: This breaks VBS/JS script execution. Reversible with -UnhardenScripts.

.PARAMETER UnhardenScripts
  Revert HardenScripts changes (remove IFEO, re-enable WSH).

.PARAMETER FullScan
  Run Microsoft Defender FullScan (otherwise QuickScan).

.PARAMETER SfcDismRepair
  Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth.

.PARAMETER KeepHostsBlocks
  Keep/add HOSTS blocks for malicious domains (default). Use -RemoveHostsBlocks to purge them.

.PARAMETER RemoveHostsBlocks
  Remove HOSTS entries for TargetDomains.

.PARAMETER TargetDomains
  Extra domains to block (in addition to s.buno8.ru). Example: -TargetDomains bad1.com,bad2.net

.EXAMPLE
  PowerShell (Admin):
  Set-ExecutionPolicy Bypass -Scope Process -Force;
  .\Remediate-PostAudit.ps1 -AuditRoot "C:\ProgramData\MshtaCleanup\Audit-20250912-163039" `
    -DeepCleanChrome -ResetNetwork -DisableMshta -HardenScripts -FullScan -SfcDismRepair

.NOTES
  Run as Administrator.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string]$AuditRoot = "",
  [switch]$DryRun,
  [switch]$DeepCleanChrome,
  [switch]$ResetNetwork,
  [switch]$DisableMshta,
  [switch]$EnableMshta,
  [switch]$HardenScripts,
  [switch]$UnhardenScripts,
  [switch]$FullScan,
  [switch]$SfcDismRepair,
  [switch]$KeepHostsBlocks,
  [switch]$RemoveHostsBlocks,
  [string[]]$TargetDomains = @("s.buno8.ru")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Test-Admin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
  Write-Error "Run this script as Administrator."
  exit 1
}

# --- Logging ---
$RootLogDir = Join-Path $env:ProgramData "MshtaCleanup"
if (-not (Test-Path $RootLogDir)) { New-Item -ItemType Directory -Path $RootLogDir -Force | Out-Null }
$TS = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $RootLogDir ("Remediate-{0}.log" -f $TS)
$OutDir = Join-Path $RootLogDir ("Remediate-Evidence-{0}" -f $TS)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Log { param([string]$Message)
  $line = "[{0}] {1}" -f (Get-Date -Format 'u'), $Message
  Write-Host $line
  Add-Content -Path $LogFile -Value $line
}

Log "==== Remediation start ===="
Log ("Params: DryRun={0} DeepCleanChrome={1} ResetNetwork={2} DisableMshta={3} EnableMshta={4} HardenScripts={5} UnhardenScripts={6} FullScan={7} SfcDismRepair={8}" -f $DryRun,$DeepCleanChrome,$ResetNetwork,$DisableMshta,$EnableMshta,$HardenScripts,$UnhardenScripts,$FullScan,$SfcDismRepair)
if ($AuditRoot) { Log ("AuditRoot: {0}" -f $AuditRoot) }

$Regex = 'mshta|buno8\.ru|\.hta\b|wscript\.exe|cscript\.exe|powershell\.exe\s+-enc|bitsadmin|rundll32\.exe.*(javascript|_)'

# --- 0) Kill active mshta ---
try {
  $p = Get-Process mshta -ErrorAction SilentlyContinue
  if ($p) {
    Log "Stopping running mshta.exe..."
    if ($PSCmdlet.ShouldProcess("mshta.exe","Stop-Process")) {
      if (-not $DryRun) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
    }
  }
} catch { Log ("WARN stop mshta: {0}" -f $_.Exception.Message) }

# Helper: remove scheduled task safely with evidence
function Remove-TaskSafe([string]$TaskPath, [string]$TaskName, [string]$EvidenceDir) {
  $safe = (('{0}_{1}' -f ($TaskPath -replace '[\\/:"*?<>|]','_').Trim('_'), ($TaskName -replace '[\\/:"*?<>|]','_').Trim('_')))
  try {
    Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath |
      Set-Content -LiteralPath (Join-Path $EvidenceDir "$safe.xml") -Encoding UTF8
  } catch {
    try { schtasks /query /tn "$TaskPath$TaskName" /fo LIST /v |
      Out-File -FilePath (Join-Path $EvidenceDir "$safe.txt") -Encoding UTF8 } catch {}
  }
  if ($PSCmdlet.ShouldProcess("Task $TaskPath$TaskName","Unregister")) {
    if (-not $DryRun) {
      Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
      Log ("Removed task: {0}{1}" -f $TaskPath,$TaskName)
    }
  }
}

# --- 1) Cleanup using Audit CSVs (if provided) ---
if ($AuditRoot) {
  try {
    $evTasks = Join-Path (Join-Path $AuditRoot 'ScheduledTasks') 'suspicious_tasks.csv'
    if (Test-Path $evTasks) {
      Log "Removing tasks from audit CSV..."
      $Evd = Join-Path $OutDir 'ScheduledTasks'; New-Item -ItemType Directory -Path $Evd -Force | Out-Null
      $csv = Import-Csv -LiteralPath $evTasks
      foreach ($row in $csv) { Remove-TaskSafe -TaskPath $row.TaskPath -TaskName $row.TaskName -EvidenceDir $Evd }
    }
  } catch { Log ("WARN audit tasks: {0}" -f $_.Exception.Message) }

  try {
    $evRun = Join-Path (Join-Path $AuditRoot 'RunKeys') 'run_suspicious.csv'
    if (Test-Path $evRun) {
      Log "Removing Run/RunOnce values from audit CSV..."
      $csv = Import-Csv -LiteralPath $evRun
      foreach ($row in $csv) {
        if ($PSCmdlet.ShouldProcess(("Reg {0}::{1}" -f $row.Path,$row.Name),"Remove-ItemProperty")) {
          if (-not $DryRun) { Remove-ItemProperty -Path $row.Path -Name $row.Name -Force -ErrorAction SilentlyContinue }
        }
      }
    }
  } catch { Log ("WARN audit runkeys: {0}" -f $_.Exception.Message) }

  try {
    $evWmi = Join-Path (Join-Path $AuditRoot 'WMI') 'suspicious_wmi.csv'
    if (Test-Path $evWmi) {
      Log "Removing suspicious WMI (live scan by regex)..."
      # Live removal driven by regex (CSV is for evidence only)
      $ns='root\subscription'
      $consCmd = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ? { $_.CommandLineTemplate -match $Regex }
      $consScr = Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ? { $_.ScriptText -match $Regex }
      $filters = Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue | ? { $_.Query -match $Regex }
      $bindings = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
      $susNames = @(); $susNames += $consCmd.Name; $susNames += $consScr.Name; $susNames += $filters.Name
      foreach ($b in $bindings) {
        $isSus = $false
        foreach ($n in $susNames) { if ($b.Filter -match [Regex]::Escape($n) -or $b.Consumer -match [Regex]::Escape($n)) { $isSus=$true; break } }
        if ($isSus -or ("$($b.Filter) $($b.Consumer)" -match $Regex)) {
          if ($PSCmdlet.ShouldProcess("WMI binding","Delete")) { if (-not $DryRun) { try { $b.Delete() | Out-Null } catch {} } }
        }
      }
      foreach ($c in $consCmd) { if ($PSCmdlet.ShouldProcess("WMI consumer CMD $($c.Name)","Delete")) { if (-not $DryRun) { try { $c.Delete() | Out-Null } catch {} } } }
      foreach ($c in $consScr){ if ($PSCmdlet.ShouldProcess("WMI consumer Script $($c.Name)","Delete")) { if (-not $DryRun) { try { $c.Delete() | Out-Null } catch {} } } }
      foreach ($f in $filters) { if ($PSCmdlet.ShouldProcess("WMI filter $($f.Name)","Delete")) { if (-not $DryRun) { try { $f.Delete() | Out-Null } catch {} } } }
    }
  } catch { Log ("WARN audit wmi: {0}" -f $_.Exception.Message) }

  try {
    $evStart = Join-Path (Join-Path $AuditRoot 'Startup') 'startup_suspicious.csv'
    if (Test-Path $evStart) {
      Log "Removing Startup files from audit CSV..."
      $csv = Import-Csv -LiteralPath $evStart
      foreach ($row in $csv) {
        if (Test-Path $row.File) {
          if ($PSCmdlet.ShouldProcess($row.File,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $row.File -Force -ErrorAction SilentlyContinue } }
        }
      }
    }
  } catch { Log ("WARN audit startup: {0}" -f $_.Exception.Message) }
}

# --- 2) Live cleanup (in case audit path not provided or new items appeared) ---
# 2a) Scheduled Tasks by Actions regex
try {
  Log "Scanning Scheduled Tasks (live)..."
  $Evd = Join-Path $OutDir 'ScheduledTasks'; New-Item -ItemType Directory -Path $Evd -Force | Out-Null
  $all = Get-ScheduledTask -ErrorAction SilentlyContinue
  foreach ($t in $all) {
    $sus = $false
    foreach ($a in @($t.Actions)) {
      $exec = $null; $args = $null
      try { $exec = $a.Execute } catch {}
      try { $args = $a.Arguments } catch {}
      if (("$exec $args") -match $Regex) { $sus = $true; break }
    }
    if ($sus) { Remove-TaskSafe -TaskPath $t.TaskPath -TaskName $t.TaskName -EvidenceDir $Evd }
  }
} catch { Log ("WARN tasks live: {0}" -f $_.Exception.Message) }

# 2b) Run/RunOnce purge by regex
try {
  Log "Purging Run/RunOnce by regex..."
  $runPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  )
  foreach ($p in $runPaths) {
    if (-not (Test-Path $p)) { continue }
    $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    foreach ($pp in $props.PSObject.Properties) {
      if ($pp.MemberType -ne 'NoteProperty') { continue }
      $val = [string]$pp.Value
      if ($val -and ($val -match $Regex)) {
        Log ("Removing Run value: {0}::{1}" -f $p,$pp.Name)
        if ($PSCmdlet.ShouldProcess(("Reg {0}::{1}" -f $p,$pp.Name),"Remove-ItemProperty")) {
          if (-not $DryRun) { Remove-ItemProperty -Path $p -Name $pp.Name -Force -ErrorAction SilentlyContinue }
        }
      }
    }
  }
} catch { Log ("WARN Run/RunOnce live: {0}" -f $_.Exception.Message) }

# 2c) WMI Subscriptions live
try {
  Log "Purging suspicious WMI (live)..."
  $ns='root\subscription'
  $consCmd = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ? { $_.CommandLineTemplate -match $Regex }
  $consScr = Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ? { $_.ScriptText -match $Regex }
  $filters = Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue | ? { $_.Query -match $Regex }
  $bindings = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
  $susNames = @(); $susNames += $consCmd.Name; $susNames += $consScr.Name; $susNames += $filters.Name
  foreach ($b in $bindings) {
    $isSus = $false
    foreach ($n in $susNames) { if ($b.Filter -match [Regex]::Escape($n) -or $b.Consumer -match [Regex]::Escape($n)) { $isSus=$true; break } }
    if ($isSus -or ("$($b.Filter) $($b.Consumer)" -match $Regex)) {
      if ($PSCmdlet.ShouldProcess("WMI binding","Delete")) { if (-not $DryRun) { try { $b.Delete() | Out-Null } catch {} } }
    }
  }
  foreach ($c in $consCmd) { if ($PSCmdlet.ShouldProcess("WMI consumer CMD $($c.Name)","Delete")) { if (-not $DryRun) { try { $c.Delete() | Out-Null } catch {} } } }
  foreach ($c in $consScr){ if ($PSCmdlet.ShouldProcess("WMI consumer Script $($c.Name)","Delete")) { if (-not $DryRun) { try { $c.Delete() | Out-Null } catch {} } } }
  foreach ($f in $filters) { if ($PSCmdlet.ShouldProcess("WMI filter $($f.Name)","Delete")) { if (-not $DryRun) { try { $f.Delete() | Out-Null } catch {} } } }
} catch { Log ("WARN WMI live: {0}" -f $_.Exception.Message) }

# 2d) Startup folders
try {
  Log "Cleaning Startup folders..."
  $startupDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
  foreach ($s in $startupDirs) {
    if (-not (Test-Path $s)) { continue }
    Get-ChildItem -Path $s -File -Include *.lnk,*.url,*.hta,*.js,*.vbs,*.cmd,*.bat,*.ps1 -ErrorAction SilentlyContinue | ForEach-Object {
      $detail = ""
      $sus = $false
      if ($_.Extension -ieq ".lnk") {
        try { $w = New-Object -ComObject WScript.Shell; $sc = $w.CreateShortcut($_.FullName); $detail = "$($sc.TargetPath) $($sc.Arguments)"; if ($detail -match $Regex) { $sus=$true } } catch {}
      } else {
        try { $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue; $detail = $c.Substring(0,[Math]::Min(200,$c.Length)); if ($detail -match $Regex) { $sus=$true } } catch {}
      }
      if ($sus) {
        Log ("Removing Startup item: {0}" -f $_.FullName)
        if ($PSCmdlet.ShouldProcess($_.FullName,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } }
      }
    }
  }
} catch { Log ("WARN Startup: {0}" -f $_.Exception.Message) }

# 2e) INetCache and Prefetch traces
try {
  $inet = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
  if (Test-Path $inet) {
    Log "Removing INetCache .hta and buno8.ru traces..."
    Get-ChildItem $inet -Recurse -ErrorAction SilentlyContinue | ? { $_.FullName -match 'buno8\.ru|\.hta$' } | ForEach-Object {
      if ($PSCmdlet.ShouldProcess($_.FullName,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } }
    }
  }
  $pf = "$env:SystemRoot\Prefetch"
  if (Test-Path $pf) {
    Log "Optional: listing MSHTA*.pf (no delete) ..."
    Get-ChildItem -Path $pf -Filter "MSHTA*.pf" -ErrorAction SilentlyContinue |
      Select Name, Length, LastWriteTime |
      Export-Csv -LiteralPath (Join-Path $OutDir 'mshta_prefetch_snapshot.csv') -NoTypeInformation -Encoding UTF8
  }
} catch { Log ("WARN Cache/Prefetch: {0}" -f $_.Exception.Message) }

# --- 3) HOSTS blocks for malicious domains ---
try {
  $hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
  if (Test-Path $hosts) {
    $current = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue
    if ($RemoveHostsBlocks) {
      Log "Removing HOSTS blocks for TargetDomains..."
      $pat = ($TargetDomains | ForEach-Object { [Regex]::Escape($_) }) -join "|"
      $filtered = $current | Where-Object { $_ -notmatch $pat }
      if ($PSCmdlet.ShouldProcess($hosts,"Purge TargetDomains")) { if (-not $DryRun) { $filtered | Set-Content -LiteralPath $hosts -Encoding UTF8 } }
    } else {
      foreach ($d in $TargetDomains) {
        if (-not ($current -match [Regex]::Escape($d))) {
          $line = ("0.0.0.0 {0}" -f $d)
          Log ("Adding HOSTS block: {0}" -f $line)
          if ($PSCmdlet.ShouldProcess($hosts,"Append block")) { if (-not $DryRun) { Add-Content -LiteralPath $hosts -Value "`n$line" } }
        } else {
          Log ("HOSTS already contains: {0}" -f $d)
        }
      }
    }
    try { ipconfig /flushdns | Out-Null; Log "Flushed DNS cache." } catch {}
  } else {
    Log "WARN HOSTS file not found."
  }
} catch { Log ("WARN HOSTS: {0}" -f $_.Exception.Message) }

# --- 4) Deep Chrome cleanup ---
if ($DeepCleanChrome) {
  try {
    Log "Deep cleaning Google Chrome remnants..."
    $paths = @(
      "$env:ProgramFiles\Google\Chrome",
      "$env:ProgramFiles(x86)\Google\Chrome",
      "$env:LOCALAPPDATA\Google\Chrome",
      "$env:LOCALAPPDATA\Google\Chrome\User Data",
      "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk"
    )
    foreach ($p in $paths) {
      if (Test-Path $p) {
        Log ("Removing path: {0}" -f $p)
        if ($PSCmdlet.ShouldProcess($p,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }
      }
    }
    # Google Update scheduled tasks
    $gtasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ? { $_.TaskName -match '^GoogleUpdate' -or $_.TaskPath -match '\\Google\\' }
    foreach ($t in $gtasks) {
      Log ("Removing Google task: {0}{1}" -f $t.TaskPath,$t.TaskName)
      if ($PSCmdlet.ShouldProcess(("Task " + $t.TaskPath + $t.TaskName),"Unregister")) { if (-not $DryRun) { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue } }
    }
    # Google Update services
    foreach ($svc in @("gupdate","gupdatem")) {
      $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
      if ($s) {
        Log ("Stopping and deleting service: {0}" -f $svc)
        if (-not $DryRun) {
          try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
          try { sc.exe delete $svc | Out-Null } catch {}
        }
      }
    }
    # Chrome policies
    $pols = @(
      'HKLM:\Software\Policies\Google\Chrome',
      'HKCU:\Software\Policies\Google\Chrome',
      'HKLM:\Software\Policies\Google',
      'HKCU:\Software\Policies\Google'
    )
    foreach ($k in $pols) {
      if (Test-Path $k) {
        Log ("Removing policy key: {0}" -f $k)
        if ($PSCmdlet.ShouldProcess($k,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue } }
      }
    }
    # Chrome classes (file associations)
    $classes = @(
      'HKLM:\Software\Classes\ChromeHTML',
      'HKCU:\Software\Classes\ChromeHTML'
    )
    foreach ($k in $classes) {
      if (Test-Path $k) {
        Log ("Removing class key: {0}" -f $k)
        if ($PSCmdlet.ShouldProcess($k,"Remove-Item")) { if (-not $DryRun) { Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue } }
      }
    }
  } catch { Log ("WARN Chrome cleanup: {0}" -f $_.Exception.Message) }
}

# --- 5) Defender protections and scan ---
try {
  Log "Enabling Microsoft Defender protections..."
  if (-not $DryRun) {
    try { Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -CloudDeliveredProtectionEnabled 1 -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -MAPSReporting 2 -ErrorAction SilentlyContinue } catch {}
    # Network protection (may require Enterprise; will ignore on error)
    try { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue } catch {}
  }
  Log "Updating signatures and scanning..."
  if ($DryRun) {
    Log "DryRun: skipping Update-MpSignature and Start-MpScan"
  } else {
    try { Update-MpSignature -ErrorAction Continue | Out-Null } catch { Log ("WARN Update-MpSignature: {0}" -f $_.Exception.Message) }
    $st = if ($FullScan) { 'FullScan' } else { 'QuickScan' }
    try { Start-MpScan -ScanType $st -ErrorAction Continue } catch { Log ("WARN Start-MpScan: {0}" -f $_.Exception.Message) }
  }
} catch { Log ("WARN Defender setup/scan: {0}" -f $_.Exception.Message) }

# --- 6) Harden / Unharden scripts and mshta ---
$IFEOBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
function Set-IFEO([string]$Exe, [switch]$Enable) {
  $key = Join-Path $IFEOBase $Exe
  if ($Enable) {
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Debugger' -Value "$env:SystemRoot\System32\notepad.exe" -PropertyType String -Force | Out-Null
    Log ("IFEO set for {0}" -f $Exe)
  } else {
    if (Test-Path $key) { Remove-ItemProperty -Path $key -Name 'Debugger' -ErrorAction SilentlyContinue; Log ("IFEO removed for {0}" -f $Exe) }
  }
}

try {
  if ($DisableMshta -and $EnableMshta) { Log "WARN: both -DisableMshta and -EnableMshta set; ignoring." }
  elseif ($DisableMshta) { if ($PSCmdlet.ShouldProcess("IFEO mshta.exe","Enable")) { if (-not $DryRun) { Set-IFEO -Exe 'mshta.exe' -Enable } } }
  elseif ($EnableMshta)  { if ($PSCmdlet.ShouldProcess("IFEO mshta.exe","Disable")) { if (-not $DryRun) { Set-IFEO -Exe 'mshta.exe' } } }

  if ($HardenScripts -and $UnhardenScripts) { Log "WARN: both -HardenScripts and -UnhardenScripts set; ignoring." }
  elseif ($HardenScripts) {
    Log "Applying script hardening (IFEO wscript/cscript + disable WSH)..."
    if ($PSCmdlet.ShouldProcess("Script Hardening","Apply")) {
      if (-not $DryRun) {
        Set-IFEO -Exe 'wscript.exe' -Enable
        Set-IFEO -Exe 'cscript.exe' -Enable
        # Disable Windows Script Host
        New-Item -Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -PropertyType DWord -Value 0 -Force | Out-Null
      }
    }
  } elseif ($UnhardenScripts) {
    Log "Reverting script hardening..."
    if ($PSCmdlet.ShouldProcess("Script Hardening","Revert")) {
      if (-not $DryRun) {
        Set-IFEO -Exe 'wscript.exe'
        Set-IFEO -Exe 'cscript.exe'
        # Enable Windows Script Host
        if (Test-Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings') {
          New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
        }
      }
    }
  }
} catch { Log ("WARN IFEO/WSH: {0}" -f $_.Exception.Message) }

# --- 7) Network reset (optional) ---
if ($ResetNetwork) {
  try {
    Log "Resetting WinHTTP/IE proxy to direct and Winsock/IP..."
    if ($PSCmdlet.ShouldProcess("winhttp","reset proxy")) { if (-not $DryRun) { netsh winhttp reset proxy | Out-Null } }
    $isHKCU = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $isHKLM = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    foreach ($k in @($isHKCU,$isHKLM)) {
      if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
      if ($PSCmdlet.ShouldProcess($k,"Proxy OFF/AutoDetect ON")) {
        if (-not $DryRun) {
          New-ItemProperty -Path $k -Name ProxyEnable -PropertyType DWord -Value 0 -Force | Out-Null
          New-ItemProperty -Path $k -Name AutoDetect -PropertyType DWord -Value 1 -Force | Out-Null
          Remove-ItemProperty -Path $k -Name ProxyServer -ErrorAction SilentlyContinue
          Remove-ItemProperty -Path $k -Name AutoConfigURL -ErrorAction SilentlyContinue
        }
      }
    }
    if ($PSCmdlet.ShouldProcess("netsh winsock","reset")) { if (-not $DryRun) { netsh winsock reset | Out-Null } }
    if ($PSCmdlet.ShouldProcess("netsh int ip","reset")) { if (-not $DryRun) { netsh int ip reset | Out-Null } }
    if ($PSCmdlet.ShouldProcess("ipconfig","/flushdns")) { if (-not $DryRun) { ipconfig /flushdns | Out-Null } }
    Log "Network reset completed. Reboot recommended."
  } catch { Log ("WARN ResetNetwork: {0}" -f $_.Exception.Message) }
}

# --- 8) System file repair (optional) ---
if ($SfcDismRepair) {
  try {
    Log "Running SFC and DISM (may take a while)..."
    if ($PSCmdlet.ShouldProcess("SFC","/scannow")) { if (-not $DryRun) { sfc /scannow | Out-Null } }
    if ($PSCmdlet.ShouldProcess("DISM","/RestoreHealth")) { if (-not $DryRun) { DISM /Online /Cleanup-Image /RestoreHealth | Out-Null } }
  } catch { Log ("WARN SFC/DISM: {0}" -f $_.Exception.Message) }
}

Log "==== Remediation complete ===="
Write-Host ("Log: {0}" -f $LogFile)
Write-Host ("Evidence: {0}" -f $OutDir)
if ($ResetNetwork -and -not $DryRun) { Write-Host "*** Reboot Windows to complete network reset. ***" }
