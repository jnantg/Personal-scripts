<# 
.SYNOPSIS
  windows_assessment.ps1 — Portable Windows Server assessment (no external deps).

.USAGE
  # Default: 300s duration, 5s interval, DNS lookups on, PDF attempt on
  powershell -ExecutionPolicy Bypass -File .\windows_assessment.ps1

  # Env knobs (same spirit as your Linux script)
  $env:DURATION=300        # [60..3600] total sampling seconds for net top-talkers
  $env:INTERVAL=5          # seconds between samples
  $env:DNS_LOOKUP=1        # 0 to disable reverse DNS on top-talkers
  $env:ENCRYPT=1           # 1 to AES-256-CBC encrypt the .zip into .zip.enc (requires PASS)
  $env:PASS='X'            # passphrase for encryption (if unset and ENCRYPT=1, script will skip)
  $env:NO_PDF=1            # 1 to skip PDF attempt (HTML is always produced)

.OUTPUT
  assessment_<HOST>_<YYYYMMDD_HHMMSS>\  (with csv/, net/, logs/, etc/, services/, software/, security/, login/ …)
  SUMMARY.txt, report.html (+ optional .pdf), and a .zip (or .zip.enc)

.NOTES
  - Designed to be self-contained (PowerShell 5+).
  - Optional PDF uses 'wkhtmltopdf' if in PATH.
  - Encryption is native via .NET (PBKDF2 + AES-256-CBC).
#>


param(
    [int]$Duration  = 300,
    [int]$Interval  = 5,
    [int]$DnsLookup = 1,
    [int]$Encrypt   = 0,
    [int]$NoPdf     = 0,
    [string]$Pass,
    [string]$OutDir = "C:\Temp"
)


Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# -------------------- tiny helpers --------------------
function NowIso { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Log([string]$msg) { Write-Host $msg }
function Ensure-Dir([string]$p){ if(-not (Test-Path -LiteralPath $p)){ New-Item -ItemType Directory -Path $p | Out-Null } }
function Cap([string]$outfile, [scriptblock]$block) {
  try {
    & {
      & $block *>&1
    } | Out-File -FilePath $outfile -Encoding UTF8 -Force
  } catch {
    "[ERROR] $($_.Exception.Message)" | Out-File -FilePath $outfile -Encoding UTF8 -Force
  }
}
function Cat-IfExists([string]$path){ if(Test-Path $path){ Get-Content -Raw -LiteralPath $path } }
function HtmlEscape([string]$s){ ($s -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;' }

# -------------------- setup --------------------
$HOSTN = $env:COMPUTERNAME
$TS    = Get-Date -Format 'yyyyMMdd_HHmmss'

# resolve output dir from param
$OUT = Join-Path $OutDir ("assessment_${HOSTN}_$TS")

# materialize folders
$subs  = @('files','csv','logs','etc','find','services','net','agents','security','scheduled','login','software','system')
Ensure-Dir $OUT
$subs | ForEach-Object { Ensure-Dir (Join-Path $OUT $_) }

# bind knobs from params (PS 5.1-safe)
$DURATION   = $Duration
$INTERVAL   = $Interval
$DNS_LOOKUP = $DnsLookup
$NO_PDF     = $NoPdf
$ENCRYPT    = $Encrypt
$PASS       = $Pass

Log "[+] Output dir: $OUT"
Log "[+] Sampling network for ${DURATION}s (interval ${INTERVAL}s)"


# -------------------- basic system info --------------------
Cap "$OUT\system\os.txt" {
  $os  = Get-CimInstance Win32_OperatingSystem
  $cs  = Get-CimInstance Win32_ComputerSystem
  $cpu = Get-CimInstance Win32_Processor
  $mem = Get-CimInstance Win32_OperatingSystem
  $obj = [ordered]@{
    Hostname           = $HOSTN
    NowUTC             = NowIso
    Caption            = $os.Caption
    Version            = $os.Version
    BuildNumber        = $os.BuildNumber
    InstallDate        = $os.InstallDate
    LastBootUpTime     = $os.LastBootUpTime
    UptimeSeconds      = [int]((Get-Date)-$os.LastBootUpTime).TotalSeconds
    Manufacturer       = $cs.Manufacturer
    Model              = $cs.Model
    Domain             = $cs.Domain
    CPU_Name           = ($cpu | Select-Object -ExpandProperty Name) -join ' | '
    CPU_Cores          = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
    CPU_Logical        = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    MemTotal_MB        = [int]($mem.TotalVisibleMemorySize/1024)
    MemFree_MB         = [int]($mem.FreePhysicalMemory/1024)
  }
  $obj.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key,$_.Value }
}

Cap "$OUT\system\time.txt" {
  Get-Date
  w32tm /query /status
}

Cap "$OUT\system\disks.txt" {
  "== Get-Disk =="; Get-Disk | Format-Table -AutoSize | Out-String
  "`n== Get-Partition =="; Get-Partition | Format-Table -AutoSize | Out-String
  "`n== Get-Volume =="; Get-Volume | Sort-Object DriveLetter | Format-Table -AutoSize | Out-String
  "`n== Logical Disks =="; Get-CimInstance Win32_LogicalDisk | Format-Table -AutoSize | Out-String
}

Cap "$OUT\system\processes.txt" { Get-Process | Sort-Object CPU -Descending | Format-Table -AutoSize | Out-String }
Cap "$OUT\system\services_all.txt" { Get-Service | Sort-Object Status,DisplayName | Format-Table -AutoSize | Out-String }

# -------------------- networking --------------------
Cap "$OUT\net\ipconfig.txt" { Get-NetIPConfiguration | Format-List * | Out-String }
Cap "$OUT\net\routes_v4.txt" { Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix,RouteMetric | Format-Table -AutoSize | Out-String }
Cap "$OUT\net\routes_v6.txt" { Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix,RouteMetric | Format-Table -AutoSize | Out-String }
Cap "$OUT\net\arp.txt" { arp -a }
Cap "$OUT\net\listeners.txt" { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table -AutoSize | Out-String }
Cap "$OUT\net\connections_now.txt" { Get-NetTCPConnection | Sort-Object State,LocalPort | Format-Table -AutoSize | Out-String }
Cap "$OUT\net\dns_resolvers.txt" {
  "== NIC DNS Servers =="; Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String
  "`n== hosts file =="; Cat-IfExists "$env:SystemRoot\System32\drivers\etc\hosts"
}

# Firewall + Defender
Cap "$OUT\security\firewall_profiles.txt" { Get-NetFirewallProfile | Format-List * | Out-String }
Cap "$OUT\security\firewall_rules.txt" { Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile | Sort-Object DisplayName | Format-Table -AutoSize | Out-String }
Cap "$OUT\security\defender_status.txt" {
  if (Get-Command Get-MpComputerStatus -ErrorAction Ignore) { Get-MpComputerStatus | Format-List * | Out-String }
  else { "Windows Defender module not available." }
}
Cap "$OUT\security\rdp_remoting.txt" {
  $rdpEnabled = $false
  try {
    $val = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpEnabled = ($val -eq 0)
  } catch {}

  $winrmStatus = 'NotInstalled'
  try {
    $svc = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
    if ($svc) { $winrmStatus = $svc.Status }
  } catch {}

  "RDP Enabled: $rdpEnabled"
  "WinRM Service: $winrmStatus"
}


# -------------------- users / groups / ssh --------------------
Cap "$OUT\etc\local_users.txt" { Get-LocalUser | Format-Table -AutoSize | Out-String }
Cap "$OUT\etc\local_groups.txt" { Get-LocalGroup | Format-Table -AutoSize | Out-String }
Cap "$OUT\etc\administrators_members.txt" { Get-LocalGroupMember -Group 'Administrators' | Format-Table -AutoSize | Out-String }
Cap "$OUT\etc\ssh_config.txt" {
  $d="$env:ProgramData\ssh"
  if(Test-Path $d){
    "## $d\sshd_config"; Cat-IfExists (Join-Path $d 'sshd_config')
    "`n## $d\ssh_config";  Cat-IfExists (Join-Path $d 'ssh_config')
  } else { "OpenSSH not found." }
}

# -------------------- software inventory --------------------
$SW = Join-Path $OUT 'software'
Ensure-Dir $SW

function Get-UninstallEntries {
  param([string]$Hive)
  $path = if ($Hive -eq 'HKLM') { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' } else { 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
  if (Test-Path $path) {
    Get-ChildItem $path | ForEach-Object {
      $p = Get-ItemProperty $_.PSPath
      [pscustomobject]@{
        DisplayName  = $p.DisplayName
        DisplayVersion = $p.DisplayVersion
        Publisher    = $p.Publisher
        InstallDate  = $p.InstallDate
        UninstallString = $p.UninstallString
        RegistryKey  = $_.PSChildName
      }
    } | Where-Object { $_.DisplayName }
  }
}

Cap "$SW\installed_64.txt" { Get-UninstallEntries -Hive HKLM | Sort-Object DisplayName | Format-Table -AutoSize | Out-String }
Cap "$SW\installed_32.txt" { Get-UninstallEntries -Hive WOW64 | Sort-Object DisplayName | Format-Table -AutoSize | Out-String }
Cap "$SW\packages.txt"     { Get-Package | Sort-Object Name | Format-Table -AutoSize | Out-String }

# -------------------- certificates (expiry) --------------------
Cap "$OUT\find\certificates.txt" {
  "## LocalMachine\My"; Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject,Issuer,NotAfter,Thumbprint | Format-Table -AutoSize | Out-String
  "`n## LocalMachine\Root"; Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject,NotAfter,Thumbprint | Format-Table -AutoSize | Out-String
}

# -------------------- scheduled tasks --------------------
Cap "$OUT\scheduled\tasks.txt" { Get-ScheduledTask | Sort-Object TaskName | Format-Table -AutoSize | Out-String }

# -------------------- detect common agents --------------------
Cap "$OUT\agents\agents.txt" {
  $paths = @(
    'C:\Program Files\Datadog\Datadog Agent','C:\Program Files\Zabbix Agent','C:\Program Files\SplunkUniversalForwarder',
    'C:\Program Files\Veeam','C:\Program Files\Elastic\Agent','C:\Program Files\Filebeat',
    'C:\Program Files\Amazon\SSM','C:\Program Files\Google\OsConfig','C:\Program Files\New Relic',
    'C:\Program Files\AzureMonitorAgent','C:\Program Files\Microsoft Monitoring Agent'
  )
  foreach($p in $paths){ if(Test-Path $p){ "[FOUND] $p" } }
}

# -------------------- cloud footprints --------------------
Cap "$OUT\cloud_footprints.txt" {
  $homes = @( 'C:\Users' ) + (Get-ChildItem 'C:\Users' -Directory | Select-Object -Expand FullName)
  foreach($h in $homes){
    foreach($d in @('.aws','.azure','.config\gcloud','.docker','.kube','.terraform.d','.gnupg','.azure-devops','.minikube','.rclone')){
      $p = Join-Path $h $d
      if(Test-Path $p){ $p }
    }
  }
}

# -------------------- network sampler (top talkers) --------------------
$SAMPLES_CSV = Join-Path (Join-Path $OUT 'csv') 'netconn_samples.csv'
$TOP_CSV     = Join-Path (Join-Path $OUT 'csv') 'net_top_talkers.csv'
"timestamp,remote_ip,remote_port" | Out-File -FilePath $SAMPLES_CSV -Encoding UTF8 -Force

# Build IANA service map from %SystemRoot%\System32\drivers\etc\services
$servicesMap = @{}
try {
  $svcFile = "$env:SystemRoot\System32\drivers\etc\services"
  if(Test-Path $svcFile){
    Get-Content $svcFile | ForEach-Object {
      if($_ -match '^\s*#'){return}
      if($_ -match '^\s*(\S+)\s+(\d+)\/(tcp|udp)'){
        $servicesMap["$($Matches[2])/$($Matches[3])"] = $Matches[1]
      }
    }
  }
} catch {}

$endTime = (Get-Date).AddSeconds($DURATION)
while((Get-Date) -lt $endTime){
  $now = NowIso
  try {
    Get-NetTCPConnection -State Established | ForEach-Object {
      $rip = $_.RemoteAddress
      $rpt = $_.RemotePort
      if($rip -and $rpt -and $rip -ne '::' -and $rip -ne '0.0.0.0'){
        "$now,$rip,$rpt" | Out-File -FilePath $SAMPLES_CSV -Append -Encoding UTF8
      }
    }
  } catch {}
  Start-Sleep -Seconds $INTERVAL
}

# Aggregate to top talkers
$rows = Import-Csv -Path $SAMPLES_CSV
$agg  = $rows | Group-Object remote_ip,remote_port | Sort-Object Count -Descending
$dnsOn = ($DNS_LOOKUP -eq 1)

"remote_ip,remote_port,count,service,reverse_dns" | Out-File -FilePath $TOP_CSV -Encoding UTF8 -Force
foreach($g in $agg){
  $ip,$port = $g.Name -split ','
  $svc = $servicesMap["$port/tcp"]
  $rdns = ''
  if($dnsOn){
    try { $rdns = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
  }
  "$ip,$port,$($g.Count),$svc,$rdns" | Out-File -FilePath $TOP_CSV -Append -Encoding UTF8
}

# -------------------- login activity (14 days) --------------------
$LOGDIR    = Join-Path $OUT 'login'
$ACCEPTS   = Join-Path $LOGDIR 'login_raw_accepts.csv'
$FAILS     = Join-Path $LOGDIR 'login_raw_fails.csv'
$SUM_SUCC  = Join-Path $LOGDIR 'summary_success_by_user_source.csv'
$SUM_FAIL  = Join-Path $LOGDIR 'summary_failed_by_source.csv'
Ensure-Dir $LOGDIR
"timestamp,user,source_ip,logon_type" | Out-File $ACCEPTS -Encoding UTF8 -Force
"timestamp,user,source_ip,logon_type" | Out-File $FAILS   -Encoding UTF8 -Force

$since = (Get-Date).AddDays(-14)
try {
  $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4625); StartTime=$since}
  foreach($e in $evts){
    # Event schema: Properties vary; use XML to be robust
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach($n in $xml.Event.EventData.Data){ $data[$n.Name] = $n.'#text' }
    $ts   = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $user = $data['TargetUserName']
    $ip   = $data['IpAddress']
    $lt   = $data['LogonType']
    if($e.Id -eq 4624){ "$ts,$user,$ip,$lt" | Out-File -FilePath $ACCEPTS -Append -Encoding UTF8 }
    elseif($e.Id -eq 4625){ "$ts,$user,$ip,$lt" | Out-File -FilePath $FAILS   -Append -Encoding UTF8 }
  }
} catch {}

# Summaries
if (Test-Path $ACCEPTS){ 
  (Import-Csv $ACCEPTS | Group-Object user,source_ip | ForEach-Object {
    $u,$s = $_.Name -split ','
    [pscustomobject]@{ user=$u; source_ip=$s; count=$_.Count }
  }) | Export-Csv -Path $SUM_SUCC -NoTypeInformation -Encoding UTF8
}
if (Test-Path $FAILS){
  (Import-Csv $FAILS | Group-Object source_ip | ForEach-Object {
    [pscustomobject]@{ source_ip=$_.Name; failed_count=$_.Count }
  }) | Export-Csv -Path $SUM_FAIL -NoTypeInformation -Encoding UTF8
}

# -------------------- quick SUMMARY.txt --------------------
$SUM = Join-Path $OUT 'SUMMARY.txt'
Cap $SUM {
  "Host: $HOSTN"
  "When: $(NowIso)"
  ""
  "Default routes:"
  (Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | Format-Table -AutoSize | Out-String)
  ""
  "DNS:"
  (Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique) -join "`n"
  ""
  "Top talkers (sampled ${DURATION}s @ ${INTERVAL}s):"
  if(Test-Path $TOP_CSV){
    Import-Csv $TOP_CSV | Sort-Object count -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String
  } else { "N/A" }
  ""
  "Successful logons (14d) by user,source:"
  if(Test-Path $SUM_SUCC){ Import-Csv $SUM_SUCC | Sort-Object count -Descending | Format-Table -AutoSize | Out-String } else { "none" }
  ""
  "Listening ports:"
  (Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table -AutoSize | Out-String)
}

# -------------------- HTML report --------------------
$HTML = Join-Path $OUT 'report.html'
function Add-Pre([string]$title,[string]$file){
  $content = if(Test-Path $file){ HtmlEscape ((Get-Content -Raw -LiteralPath $file)) } else { '(missing)' }
  "<section><h2>$([string](HtmlEscape $title))</h2><pre>$content</pre></section>" | Out-File -FilePath $HTML -Append -Encoding UTF8
}

@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<title>Assessment Report</title>
<style>
  body{font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;padding:24px;}
  header{margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #eee}
  h1{font-size:22px;margin:0}
  h2{font-size:18px;margin-top:24px;border-left:4px solid #444;padding-left:8px}
  pre{background:#f9f9f9;border:1px solid #e5e5e5;border-radius:6px;padding:10px;overflow:auto;white-space:pre-wrap}
  .small{color:#666;font-size:12px}
</style>
</head><body>
<header><h1>System Assessment Report</h1>
<div class="small">Host: $(HtmlEscape $HOSTN) — Generated: $(NowIso)</div></header>
<section><h2>Summary</h2><pre>$(HtmlEscape (Get-Content -Raw -LiteralPath $SUM))</pre></section>
"@ | Out-File -FilePath $HTML -Encoding UTF8

Add-Pre "OS"                "$OUT\system\os.txt"
Add-Pre "Time"              "$OUT\system\time.txt"
Add-Pre "Disks"             "$OUT\system\disks.txt"
Add-Pre "Processes"         "$OUT\system\processes.txt"
Add-Pre "All Services"      "$OUT\system\services_all.txt"
Add-Pre "IP Config"         "$OUT\net\ipconfig.txt"
Add-Pre "Routes IPv4"       "$OUT\net\routes_v4.txt"
Add-Pre "Routes IPv6"       "$OUT\net\routes_v6.txt"
Add-Pre "Listening Ports"   "$OUT\net\listeners.txt"
Add-Pre "Current Connections" "$OUT\net\connections_now.txt"
Add-Pre "ARP"               "$OUT\net\arp.txt"
Add-Pre "DNS Resolvers"     "$OUT\net\dns_resolvers.txt"
Add-Pre "Firewall Profiles" "$OUT\security\firewall_profiles.txt"
Add-Pre "Firewall Rules"    "$OUT\security\firewall_rules.txt"
Add-Pre "Defender Status"   "$OUT\security\defender_status.txt"
Add-Pre "RDP/WinRM"         "$OUT\security\rdp_remoting.txt"
Add-Pre "Local Users"       "$OUT\etc\local_users.txt"
Add-Pre "Local Groups"      "$OUT\etc\local_groups.txt"
Add-Pre "Administrators Group" "$OUT\etc\administrators_members.txt"
Add-Pre "OpenSSH Configs"   "$OUT\etc\ssh_config.txt"
Add-Pre "Software x64 (HKLM)" "$SW\installed_64.txt"
Add-Pre "Software x86 (WOW64)" "$SW\installed_32.txt"
Add-Pre "Packages (Get-Package)" "$SW\packages.txt"
Add-Pre "Certificates"      "$OUT\find\certificates.txt"
Add-Pre "Scheduled Tasks"   "$OUT\scheduled\tasks.txt"
Add-Pre "Agents/Monitors"   "$OUT\agents\agents.txt"
Add-Pre "Cloud footprints"  "$OUT\cloud_footprints.txt"
Add-Pre "Top talkers (CSV)" "$TOP_CSV"
Add-Pre "Raw samples (CSV)" "$SAMPLES_CSV"
Add-Pre "Logon accepts (CSV)" "$ACCEPTS"
Add-Pre "Logon failures (CSV)" "$FAILS"
Add-Pre "Success by user+source (CSV)" "$SUM_SUCC"
Add-Pre "Failed by source (CSV)" "$SUM_FAIL"
"</body></html>" | Out-File -FilePath $HTML -Append -Encoding UTF8

# Optional PDF
if($NO_PDF -ne 1){
  $wk = Get-Command wkhtmltopdf -ErrorAction Ignore
  if($wk){ & $wk $HTML ($HTML -replace '\.html$','.pdf') | Out-Null }
}

# -------------------- bundle + optional encryption --------------------
$zip = Join-Path (Split-Path -Path $OUT -Parent) ("$OUT.zip")
if(Test-Path $zip){ Remove-Item $zip -Force }
Compress-Archive -Path $OUT -DestinationPath $zip -Force

# AES-256-CBC encrypt $zip to $zip.enc if requested
if($ENCRYPT -eq 1 -and (Test-Path $zip) -and $PASS){
  function Protect-AES256File {
    param([string]$InFile,[string]$OutFile,[string]$Password)
    $salt = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $iv   = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Fill($iv)
    $kdf  = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password,[byte[]]$salt,100000,[Security.Cryptography.HashAlgorithmName]::SHA256)
    $key  = $kdf.GetBytes(32)
    $aes  = [Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv
    $fsIn  = [IO.File]::OpenRead($InFile)
    $fsOut = [IO.File]::Create($OutFile)
    try{
      # Magic header: "AES256" + salt + iv for decryption later
      $magic = [Text.Encoding]::ASCII.GetBytes('AES256')
      $fsOut.Write($magic,0,$magic.Length)
      $fsOut.Write($salt,0,$salt.Length)
      $fsOut.Write($iv,0,$iv.Length)
      $cs = New-Object Security.Cryptography.CryptoStream($fsOut,$aes.CreateEncryptor(),[IO.CryptoStreamMode]::Write)
      $fsIn.CopyTo($cs)
      $cs.FlushFinalBlock()
      $cs.Dispose()
    } finally {
      $fsIn.Dispose(); $fsOut.Dispose(); $aes.Dispose()
    }
  }
  $enc = "$zip.enc"
  Protect-AES256File -InFile $zip -OutFile $enc -Password $PASS
  if(Test-Path $enc){ Remove-Item $zip -Force }
}

Log "[+] Done. See $OUT\ (and $([IO.Path]::GetFileName($zip)) or .zip.enc if created)."
