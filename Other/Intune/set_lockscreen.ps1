
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SCRIPT                                                              ║
# ║  Name     : set_lockscreen.ps1                                       ║
# ║  Version  : 1.5                                                      ║     
# ║  Date     : 2025-10-20                                               ║  
# ║  Author   : Jonathan Neerup-Andersen  ·  jna@ntg.com                 ║
# ║  License  : Free for non-commercial use (no warranty)                ║
# ╚══════════════════════════════════════════════════════════════════════╝


<# 
Script should be configured as a detection script to be able to run multiple times. No remediation should be added.
The script will detect the aspect ratio of the active screen and configure the lockscreen there after.
#>


# Add public URLs to the images in the respective aspect ratio to be applied as lock screens
# ===== CONFIG: SAS URLs =====
$Uri_16by9  = ""
$Uri_16by10 = ""
$Uri_21by9  = ""
$Uri_32by9  = ""

# ===== TARGETS & POLICY =====
$OutDir    = "C:\ProgramData\Company\LockScreen"
$TargetFile= Join-Path $OutDir "lockscreen.png"   # use PNG directly
$MetaFile  = Join-Path $OutDir "base.meta.json"   # {ETag, LastModified, Source}
$LogFile   = Join-Path $OutDir "lockscreen.log"
$PersKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

# ===== Setup =====
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
function Log([string]$m){ $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); "$ts`t$m" | Out-File -FilePath $LogFile -Append -Encoding UTF8 }

# prune >7 days
if (Test-Path $LogFile) {
  $cutoff=(Get-Date).AddDays(-7)
  $kept = Get-Content $LogFile | Where-Object {
    if ($_ -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}') {
      try { [datetime]::ParseExact($Matches[0],'yyyy-MM-dd HH:mm:ss',$null) -ge $cutoff } catch { $false }
    } else { $false }
  }
  $kept | Set-Content -Path $LogFile -Encoding UTF8
}

# ===== Helpers =====
function Get-Res {
  $v = Get-WmiObject Win32_VideoController | Where-Object { $_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution } | Select-Object -First 1
  if ($v) { [pscustomobject]@{W=[int]$v.CurrentHorizontalResolution; H=[int]$v.CurrentVerticalResolution} } else { [pscustomobject]@{W=0;H=0} }
}
function Get-Aspect([int]$w,[int]$h){
  if ($w -le 0 -or $h -le 0) { return '16:9' }
  switch ([math]::Round($w/$h,2)) { 1.6{'16:10'} 2.33{'21:9'} 3.56{'32:9'} default{'16:9'} }
}
function Get-Uri([string]$a){ switch($a){'16:10'{$Uri_16by10} '21:9'{$Uri_21by9} '32:9'{$Uri_32by9} default{$Uri_16by9}} }

try {
  $r = Get-Res
  $aspect = Get-Aspect -w $r.W -h $r.H
  $src = Get-Uri $aspect
  Log ("Aspect={0} Res={1}x{2}" -f $aspect,$r.W,$r.H)
  if ([string]::IsNullOrWhiteSpace($src)) { throw "Missing SAS URL for $aspect" }

  # Load previous meta
  $prev = $null
  if (Test-Path $MetaFile) { try { $prev = Get-Content $MetaFile -Raw | ConvertFrom-Json } catch {} }

  $forceDownload = $false
  if (-not $prev) { $forceDownload = $true }
  elseif ($prev.Source -ne $src) { $forceDownload = $true }  # aspect/source changed

  $downloaded = $false

  if ($forceDownload) {
    # Unconditional GET
    $tmp = Join-Path $env:TEMP ("ls_"+[guid]::NewGuid()+".png")
    Invoke-WebRequest -Uri $src -OutFile $tmp -UseBasicParsing -TimeoutSec 180
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -lt 10240) { throw "Bootstrap download too small" }
    Move-Item -Force $tmp $TargetFile
    # Record fresh HEAD meta for next time
    try {
      $h1 = Invoke-WebRequest -Uri $src -Method Head -UseBasicParsing -TimeoutSec 60
      @{ETag=$h1.Headers.ETag; LastModified=$h1.Headers.'Last-Modified'; Source=$src} | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding UTF8
    } catch {
      @{ETag=$null; LastModified=$null; Source=$src} | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding UTF8
    }
    $downloaded = $true
    Log "Downloaded base (first run or source changed)"
  }
  else {
    # Conditional GET using previous meta
    $hdrs=@{}
    if ($prev.ETag) { $hdrs['If-None-Match'] = $prev.ETag }
    elseif ($prev.LastModified) { $hdrs['If-Modified-Since'] = $prev.LastModified }

    try {
      $tmp = Join-Path $env:TEMP ("ls_"+[guid]::NewGuid()+".png")
      $resp = Invoke-WebRequest -Uri $src -OutFile $tmp -UseBasicParsing -TimeoutSec 180 -Headers $hdrs -ErrorAction Stop
      if ((Test-Path $tmp) -and ((Get-Item $tmp).Length -gt 10240)) {
        Move-Item -Force $tmp $TargetFile
        # Update meta (prefer response headers; if missing, grab HEAD)
        $newE = $resp.Headers.ETag
        $newM = $resp.Headers.'Last-Modified'
        if (-not $newE -or -not $newM) {
          try { $h2 = Invoke-WebRequest -Uri $src -Method Head -UseBasicParsing -TimeoutSec 60; if(-not $newE){$newE=$h2.Headers.ETag}; if(-not $newM){$newM=$h2.Headers.'Last-Modified'} } catch {}
        }
        @{ETag=$newE; LastModified=$newM; Source=$src} | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding UTF8
        $downloaded = $true
        Log "Downloaded new base (changed on server)"
      } else {
        Log "Not modified (304)"
      }
    } catch {
      $respObj = $_.Exception.Response
      if ($respObj -and ($respObj.StatusCode.value__ -eq 304)) {
        Log "304 Not Modified"
      } else {
        throw
      }
    }
  }

  if (-not (Test-Path $TargetFile)) { throw "No lockscreen image present after download attempt" }

  # Apply HKLM policy every run (cheap, idempotent)
  if (-not (Test-Path $PersKey)) { New-Item $PersKey -Force | Out-Null }
  New-ItemProperty -Path $PersKey -Name "LockScreenImage"      -PropertyType String -Value $TargetFile -Force | Out-Null
  New-ItemProperty -Path $PersKey -Name "NoChangingLockScreen" -PropertyType DWord  -Value 1 -Force | Out-Null

  Log ("Policy applied -> {0} (downloaded={1})" -f $TargetFile,$downloaded)
  exit 0
}
catch {
  Log ("ERROR: {0}" -f $_.Exception.Message)
  exit 1
}
