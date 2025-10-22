# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SCRIPT                                                              ║
# ║  Name     : set_wallpaper.ps1                                       ║
# ║  Version  : 1.4                                                      ║     
# ║  Date     : 2025-10-20                                               ║  
# ║  Author   : Jonathan Neerup-Andersen  ·  jna@ntg.com                 ║
# ║  License  : Free for non-commercial use (no warranty)                ║
# ╚══════════════════════════════════════════════════════════════════════╝


﻿
<# This script should be run as a detection script to ensure continious application
   - The script checks the date of the file in the blob storage using Etag to ensure no download is happening if a newer version is already downloaded
   - A log is placed in $env:LOCALAPPDATA "Company\Wallpaper. Entries into the log older than 7 days are removed to prevent bloated log files
   - info overlay is added with hostname, username, serial, etc.
   - The script supports the following monitor aspect ratios: 16:9,16:10,21:9 and 32:9. It will download the wallpaper in the correct ratio when running.
#>


# Replace the placeholders with public links to the images in the respective aspect ratios. SAS urls are recommended with a long expiry.


# ===== CONFIG: SAS URLs =====
$Uri_16by9  = "{16-9.png}"
$Uri_16by10 = "{16-10.png}"
$Uri_21by9  = "{21-9.png}"
$Uri_32by9  = "{32-9.png}"
# ===== Paths =====
$OutDir    = Join-Path $env:LOCALAPPDATA "Company\Wallpaper"
$BaseFile  = Join-Path $OutDir "base.png"
$FinalFile = Join-Path $OutDir "wallpaper.jpg"
$MetaFile  = Join-Path $OutDir "base.meta.json"
$LogFile   = Join-Path $OutDir "wallpaper.log"
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }

# ===== Log helper (rotates older than 7 days) =====
function Log($msg) {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$ts`t$msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}
# Trim log entries >7 days old
if (Test-Path $LogFile) {
    $cutoff = (Get-Date).AddDays(-7)
    $lines = Get-Content $LogFile | Where-Object {
        if ($_ -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}') {
            [datetime]::ParseExact($Matches[0], 'yyyy-MM-dd HH:mm:ss', $null) -ge $cutoff
        } else { $false }
    }
    $lines | Set-Content -Path $LogFile -Encoding UTF8
}

# ===== Determine aspect =====
$video = Get-WmiObject Win32_VideoController | Where-Object { $_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution } | Select-Object -First 1
$w=[int]$video.CurrentHorizontalResolution; $h=[int]$video.CurrentVerticalResolution
if ($w -le 0 -or $h -le 0) { $w=1920; $h=1080 }
$r=[math]::Round($w/$h,2)
switch ($r) {
    1.6  { $src=$Uri_16by10; $bucket="16:10" }
    2.33 { $src=$Uri_21by9;  $bucket="21:9"  }
    3.56 { $src=$Uri_32by9;  $bucket="32:9"  }
    default { $src=$Uri_16by9; $bucket="16:9" }
}
Log "Aspect=$bucket (${w}x${h})"

# ===== Conditional download using ETag/Last-Modified =====
$prev = $null
if (Test-Path $MetaFile) { try { $prev = Get-Content $MetaFile -Raw | ConvertFrom-Json } catch {} }
$needDownload = $true
try {
    $head = Invoke-WebRequest -Uri $src -Method Head -UseBasicParsing -TimeoutSec 60
    $etag = $head.Headers.ETag
    $lastMod = $head.Headers.'Last-Modified'
    Log "HEAD: ETag=$etag LastMod=$lastMod"

    if ($prev -and ($prev.ETag -or $prev.LastModified)) {
        if ($etag -and ($prev.ETag -eq $etag)) { $needDownload = $false }
        elseif (($null -eq $etag) -and $lastMod -and ($prev.LastModified -eq $lastMod)) { $needDownload = $false }
    }

    if ($needDownload) {
        $hdrs = @{}
        if ($etag) { $hdrs['If-None-Match'] = $etag }
        elseif ($lastMod) { $hdrs['If-Modified-Since'] = $lastMod }

        try {
            $tmp = Join-Path $env:TEMP ("wp_"+[guid]::NewGuid()+".png")
            $resp = Invoke-WebRequest -Uri $src -OutFile $tmp -UseBasicParsing -TimeoutSec 180 -Headers $hdrs -ErrorAction Stop
            if ((Test-Path $tmp) -and ((Get-Item $tmp).Length -gt 10240)) {
                Move-Item -Force $tmp $BaseFile
                $newE = $resp.Headers.ETag; if (-not $newE) { $newE = $etag }
                $newM = $resp.Headers.'Last-Modified'; if (-not $newM) { $newM = $lastMod }
                @{ETag=$newE; LastModified=$newM; Source=$src} | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding UTF8
                Log "Downloaded new base image"
            } else {
                $needDownload = $false
                Log "No new body returned (304)"
            }
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 304) {
                $needDownload = $false
                Log "304 Not Modified"
            } else { throw }
        }
    } else { Log "Blob unchanged" }
}
catch { Log "HEAD failed: $($_.Exception.Message)" }

if (-not (Test-Path $BaseFile)) {
    $tmp = Join-Path $env:TEMP ("wp_"+[guid]::NewGuid()+".png")
    Invoke-WebRequest -Uri $src -OutFile $tmp -UseBasicParsing -TimeoutSec 180
    if ((Get-Item $tmp).Length -lt 10240) { throw "Download too small" }
    Move-Item -Force $tmp $BaseFile
    @{ETag=$null; LastModified=$null; Source=$src} | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding UTF8
    Log "Initial base downloaded"
}

# ===== Info overlay data =====
$serviceDesk = "https://servicedesk.ntg.com/"
$hostname = $env:COMPUTERNAME
$rawUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$userName = ($rawUser -split '\\')[-1]
$serial   = (Get-CimInstance Win32_BIOS).SerialNumber
$labels = @("Servicedesk:", "Computer Name:", "User Name:", "Serial Number:")
$values = @($serviceDesk, $hostname, $userName, $serial)

if (-not (Test-Path $BaseFile)) { Log "No base found, abort"; exit 0 }

# ===== Render overlay =====
Add-Type -AssemblyName System.Drawing
$img  = [System.Drawing.Image]::FromFile($BaseFile)
$bmp  = New-Object System.Drawing.Bitmap $img.Width, $img.Height
$g    = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = "HighQuality"; $g.InterpolationMode = "HighQualityBicubic"; $g.PixelOffsetMode = "HighQuality"
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
$g.DrawImage($img, 0, 0, $img.Width, $img.Height); $img.Dispose()

$ff = New-Object System.Drawing.FontFamily "Segoe UI"
try {
  $fontLabel = New-Object System.Drawing.Font($ff, [single]16, [System.Drawing.FontStyle]::Bold,    [System.Drawing.GraphicsUnit]::Pixel)
  $fontValue = New-Object System.Drawing.Font($ff, [single]16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
} catch {
  $ff = New-Object System.Drawing.FontFamily "Arial"
  $fontLabel = New-Object System.Drawing.Font($ff, [single]16, [System.Drawing.FontStyle]::Bold,    [System.Drawing.GraphicsUnit]::Pixel)
  $fontValue = New-Object System.Drawing.Font($ff, [single]16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
}
$white  = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
$shadow = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(120,0,0,0))
$bg     = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(140,20,20,20))

$padding = [int]([math]::Max($bmp.Width,$bmp.Height) * 0.01)
$taskbarMargin = [int]([math]::Round($bmp.Height * 0.05))
$labelWidths   = $labels | ForEach-Object { ($g.MeasureString($_, $fontLabel)).Width }
$maxLabelWidth = [int][math]::Ceiling(($labelWidths | Measure-Object -Maximum).Maximum)
$lineHeight    = [int][math]::Ceiling(($g.MeasureString("Ag", $fontLabel)).Height)
$valueWidths   = $values | ForEach-Object { ($g.MeasureString($_, $fontValue)).Width }
$maxValueWidth = [int][math]::Ceiling(($valueWidths | Measure-Object -Maximum).Maximum)

$blockWidth  = $maxLabelWidth + 10 + $maxValueWidth + (2*$padding)
$blockHeight = ($lineHeight * $labels.Count) + (2*$padding)
$blockX = $bmp.Width  - $blockWidth  - $padding
$blockY = $bmp.Height - $blockHeight - $padding - $taskbarMargin

$g.FillRectangle($bg, $blockX, $blockY, $blockWidth, $blockHeight)

for ($i=0; $i -lt $labels.Count; $i++) {
  $label  = $labels[$i]; $value = $values[$i]
  $xLabel = $blockX + $padding
  $xValue = $xLabel + $maxLabelWidth + 10
  $y      = $blockY + $padding + ($i * $lineHeight)
  $g.DrawString($label, $fontLabel, $shadow, $xLabel+1, $y+1)
  $g.DrawString($value, $fontValue, $shadow, $xValue+1, $y+1)
  $g.DrawString($label, $fontLabel, $white,  $xLabel,   $y)
  $g.DrawString($value, $fontValue, $white,  $xValue,   $y)
}

$jpeg = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq "image/jpeg" }
$enc  = New-Object System.Drawing.Imaging.EncoderParameters 1
$enc.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, 90L)
$bmp.Save($FinalFile, $jpeg, $enc)

$fontLabel.Dispose(); $fontValue.Dispose(); $white.Dispose(); $shadow.Dispose(); $bg.Dispose()
$g.Dispose(); $bmp.Dispose()

# ===== Apply wallpaper =====
New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $FinalFile
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value "10"
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name TileWallpaper -Value "0"
rundll32.exe user32.dll, UpdatePerUserSystemParameters 1, True | Out-Null

Log "Wallpaper refreshed ($bucket)"
exit 0
