#requires -version 5.1
<#
    Install-Dota684.ps1

    One-click installer for Dota 2 Classic 6.84 (Source 1, Windows).

    What this script does:
    - Elevates to Administrator
    - Downloads the 6.84 repack (Google Drive, large-file confirm handled)
      or uses a local archive next to the script (ZIP/7z supported if 7-Zip installed)
    - Extracts to C:\Games\Dota_6.84 (default) or -InstallDir
    - Creates/updates autoexec.cfg with common settings
    - Adds Windows Firewall allow rule for the game executable
    - Optionally blocks www.dota2.com in hosts (recommended to reduce lag) with -BlockDota2Site
    - Optionally installs DirectX June 2010 + VC++ x86/x64 silently with -InstallPrereqs
    - Creates a Desktop launcher batch (Launch Dota 6.84.bat)
    - Optionally opens the queue/sign-in page with -OpenQueue

    Usage examples (run as Administrator):
      powershell -ExecutionPolicy Bypass -File .\Install-Dota684.ps1 -OpenQueue -BlockDota2Site -InstallPrereqs
      powershell -ExecutionPolicy Bypass -File .\Install-Dota684.ps1 -InstallDir "D:\Games\Dota_6.84"

    Notes:
    - If a local archive exists in the same folder as this script named like:
        Dota_6.84.zip or Dota_2_6.84_Source_1_(1504).7z
      it will be preferred over downloading.
    - 7z extraction requires 7-Zip on PATH (7z.exe). ZIP uses built-in Expand-Archive.
    - Steam must be running before launching the game.
#>

param(
    [string]$InstallDir = "C:\\Program Files\\classicdota",
    [switch]$BlockDota2Site,
    [switch]$InstallPrereqs,
    [switch]$OpenQueue,
    [switch]$NoAdmin,
    [string]$LocalArchive,
    [switch]$FromSteamDepot,
    [string]$Patch = 's1-684c',
    [string]$Manifest571,
    [string]$Manifest573,
    [string]$Manifest575,
    [string]$SteamUsername,
    [switch]$RememberPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    $script:UseHttpClient = $true
} catch {
    $script:UseHttpClient = $false
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step($message) {
    Write-Host "[+] $message" -ForegroundColor Cyan
}

function Write-Warn($message) {
    Write-Host "[!] $message" -ForegroundColor Yellow
}

function Write-Err($message) {
    Write-Host "[x] $message" -ForegroundColor Red
}

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if ($NoAdmin) {
        Write-Warn "Running in NoAdmin mode: firewall/hosts/prereqs steps will be skipped."
        return
    }
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires Administrator privileges. Elevating..." -ForegroundColor Yellow
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', '"' + $PSCommandPath + '"', '"-InstallDir=' + $InstallDir + '"')
        if ($BlockDota2Site) { $args += '-BlockDota2Site' }
        if ($InstallPrereqs) { $args += '-InstallPrereqs' }
        if ($OpenQueue) { $args += '-OpenQueue' }
        if ($PreferTorrent) { $args += '-PreferTorrent' }
        if ($PreferMega) { $args += '-PreferMega' }
        if ($NoAdmin) { $args += '-NoAdmin' }
        $psi.Arguments = ($args -join ' ')
        $psi.Verb = 'runas'
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        } catch {
            Write-Err "Elevation cancelled. Exiting."
        }
        exit
    }
}

function Ensure-Directory($path) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Get-ScriptDirectory {
    if ($PSCommandPath) {
        return (Split-Path -Path $PSCommandPath -Parent)
    }
    if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
        return (Split-Path -Path $MyInvocation.MyCommand.Path -Parent)
    }
    return (Get-Location).Path
}

function Get-LocalArchive {
    $dir = Get-ScriptDirectory
    $repoRoot = (Resolve-Path (Join-Path $dir '..')).Path
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    $desktop = [Environment]::GetFolderPath('Desktop')

    $dirs = @($dir, $repoRoot, $downloads, $desktop) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    # Common exact names first
    $names = @(
        'Dota_6.84.zip',
        'Dota 6.84.zip',
        'Dota_2_6.84_Source_1_(1504).7z',
        'Dota 2 6.84 Source 1 (1504).7z',
        'Dota_6.84.7z',
        'Dota 6.84.7z'
    )
    foreach ($d in $dirs) {
        foreach ($n in $names) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }

    # Fuzzy search by pattern (largest first)
    foreach ($d in $dirs) {
        $candidate = Get-ChildItem -Path $d -Recurse -File -Include *.zip,*.7z -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'dota.*6\.84' -or $_.Name -match '6\.84.*dota' } |
            Sort-Object Length -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    return $null
}

function Get-LocalTorrent {
    $dir = Get-ScriptDirectory
    $repoRoot = (Resolve-Path (Join-Path $dir '..')).Path
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    $candidates = @()
    $candidates += (Join-Path $dir 'Dota_6.84.zip.torrent')
    $candidates += (Join-Path $repoRoot 'Dota_6.84.zip.torrent')
    $candidates += (Join-Path $downloads 'Dota_6.84.zip.torrent')
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    # Fuzzy search in Downloads
    if (Test-Path -LiteralPath $downloads) {
        $cand = Get-ChildItem -Path $downloads -Recurse -File -Include *.torrent -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'dota.*6\.84' -or $_.Name -match '6\.84.*dota' } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($cand) { return $cand.FullName }
    }
    return $null
}

# Generic streamed downloader with a clear console progress bar
function Download-FileWithProgress {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination,
        $WebSession
    )
    if ($script:UseHttpClient) {
        $handler = New-Object System.Net.Http.HttpClientHandler
        if ($WebSession -and $WebSession.Cookies) {
            $handler.UseCookies = $true
            $handler.CookieContainer = New-Object System.Net.CookieContainer
            foreach ($cookie in $WebSession.Cookies.GetCookies($Url)) { $handler.CookieContainer.Add($cookie) }
        }
        $client = New-Object System.Net.Http.HttpClient($handler)
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
        if (-not $response.IsSuccessStatusCode) { throw "Download failed: $($response.StatusCode) $($response.ReasonPhrase)" }
        $total = $response.Content.Headers.ContentLength
        $inStream = $response.Content.ReadAsStreamAsync().Result
        Ensure-Directory (Split-Path -Path $Destination -Parent)
        $fs = New-Object System.IO.FileStream($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 81920
            $totalRead = 0L
            while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fs.Write($buffer, 0, $read)
                $totalRead += $read
                if ($total -gt 0) {
                    $percent = [int](($totalRead * 100.0) / $total)
                    $status = ('{0:N2} MB / {1:N2} MB' -f ($totalRead/1MB), ($total/1MB))
                    Write-Progress -Activity 'Downloading' -Status $status -PercentComplete $percent
                } else {
                    $status = ('{0:N2} MB' -f ($totalRead/1MB))
                    Write-Progress -Activity 'Downloading' -Status $status -PercentComplete -1
                }
            }
        } finally {
            Write-Progress -Activity 'Downloading' -Completed
            $fs.Dispose(); $inStream.Dispose(); $client.Dispose(); $handler.Dispose()
        }
    } else {
        # PS 5.1 fallback: Invoke-WebRequest shows native progress
        $ProgressPreference = 'Continue'
        Ensure-Directory (Split-Path -Path $Destination -Parent)
        if ($WebSession) {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -WebSession $WebSession -UseBasicParsing
        } else {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
        }
    }
}

# Downloads large Google Drive files handling the confirm token
function Download-GDriveLargeFile {
    param(
        [Parameter(Mandatory=$true)][string]$FileId,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    $base = 'https://drive.google.com/uc?export=download&id='
    $url = "$base$FileId"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    Write-Step "Initiating Google Drive download..."
    $resp = Invoke-WebRequest -Uri $url -WebSession $session -UseBasicParsing

    # If a confirm token is required, it appears in a href with confirm= or as a form input
    $confirm = $null
    if ($resp.Content -match 'confirm=([0-9A-Za-z_\-]+)') {
        $confirm = $Matches[1]
    } elseif ($resp.Content -match 'name="confirm"\s+value="([0-9A-Za-z_\-]+)"') {
        $confirm = $Matches[1]
    }

    if ($confirm) {
        Write-Step "Confirm token acquired. Continuing download..."
        $downloadUrl = "https://drive.google.com/uc?export=download&confirm=$confirm&id=$FileId"
        Download-FileWithProgress -Url $downloadUrl -Destination $Destination -WebSession $session
    } else {
        # Sometimes direct download works
        Write-Warn "No confirm token found. Attempting direct download..."
        Download-FileWithProgress -Url $url -Destination $Destination -WebSession $session
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "Failed to download file from Google Drive."
    }
}

function Expand-ArchiveSmart {
    param(
        [Parameter(Mandatory=$true)][string]$ArchivePath,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    Ensure-Directory $Destination
    $ext = [System.IO.Path]::GetExtension($ArchivePath).ToLowerInvariant()

    if ($ext -eq '.zip') {
        Write-Step "Extracting ZIP with Expand-Archive (this may take a few minutes)..."
        # If destination has files already, attempt to extract content to the destination
        Expand-Archive -Path $ArchivePath -DestinationPath $Destination -Force
        Write-Step "ZIP extraction completed."
    } elseif ($ext -eq '.7z') {
        if (-not (Test-Command '7z')) {
            throw "7z.exe not found on PATH. Please install 7-Zip or provide a ZIP archive."
        }
        Write-Step "Extracting 7z with 7-Zip (live progress below)..."
        # Show 7z progress in the same console
        & 7z x -y "-o$Destination" "$ArchivePath" -bso1 -bsp1
        if ($LASTEXITCODE -ne 0) { throw "7-Zip exited with code $LASTEXITCODE during extraction." }
        Write-Step "7z extraction completed."
    } else {
        throw "Unsupported archive extension: $ext"
    }
}

function Ensure-Aria2 {
    $ariaTemp = Join-Path $env:TEMP 'aria2_portable'
    $exe = Join-Path $ariaTemp 'aria2c.exe'
    if (Test-Path -LiteralPath $exe) { return $exe }
    Ensure-Directory $ariaTemp
    $zipUrl = 'https://github.com/aria2/aria2/releases/download/release-1.36.0/aria2-1.36.0-win-64bit-build1.zip'
    $zipPath = Join-Path $ariaTemp 'aria2.zip'
    Write-Step "Downloading portable aria2c..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    Write-Step "Extracting aria2c..."
    Expand-Archive -Path $zipPath -DestinationPath $ariaTemp -Force
    $exeFound = Get-ChildItem -Path $ariaTemp -Recurse -Filter 'aria2c.exe' -File | Select-Object -First 1
    if (-not $exeFound) { throw "Failed to prepare aria2c.exe" }
    return $exeFound.FullName
}

function Download-ByTorrent {
    param(
        [Parameter(Mandatory=$true)][string]$TorrentPath,
        [Parameter(Mandatory=$true)][string]$OutDir
    )
    $aria2 = Ensure-Aria2
    Ensure-Directory $OutDir
    Write-Step "Starting torrent download with aria2c (live log)..."
    $trackers = @(
        'udp://tracker.opentrackr.org:1337/announce',
        'udp://tracker.openbittorrent.com:6969/announce',
        'udp://tracker.dler.org:6969/announce',
        'udp://explodie.org:6969/announce'
    ) -join ','

    $logPath = Join-Path $OutDir 'aria2.log'
    if (Test-Path -LiteralPath $logPath) { Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue }

    $args = @(
        "--dir=$OutDir",
        '--seed-time=0',
        '--summary-interval=1',
        '--console-log-level=notice',
        '--enable-dht=true',
        '--bt-enable-lpd=true',
        '--continue=true',
        '--check-integrity=true',
        "--bt-tracker=$trackers",
        "--log=$logPath",
        '--log-level=notice',
        $TorrentPath
    ) -join ' '

    $proc = Start-Process -FilePath $aria2 -ArgumentList $args -PassThru -NoNewWindow

    # Tail log with simple progress
    $fileStream = $null
    $reader = $null
    try {
        while (-not (Test-Path -LiteralPath $logPath)) { Start-Sleep -Milliseconds 200 }
        $fileStream = [System.IO.File]::Open($logPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($fileStream)
        while (-not $proc.HasExited -or -not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($null -ne $line) {
                if ($line -match 'DL:') { Write-Host $line }
            } else {
                # lightweight progress: show largest partial file size
                $f = Get-ChildItem -Path $OutDir -Recurse -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
                if ($f) {
                    $mb = [math]::Round($f.Length/1MB,2)
                    Write-Progress -Activity 'Torrent download' -Status ("Largest file: {0} MB - {1}" -f $mb, $f.Name) -PercentComplete -1
                }
                Start-Sleep -Milliseconds 300
            }
        }
        Write-Progress -Activity 'Torrent download' -Completed
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
    }

    $proc.Refresh()
    if ($proc.ExitCode -ne 0) { throw "aria2c exited with code $($proc.ExitCode)" }
    $archive = Get-ChildItem -Path $OutDir -Recurse -Include *.zip,*.7z -File | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $archive) { throw "Torrent finished but archive not found in $OutDir" }
    return $archive.FullName
}

function Try-Download-Mega {
    param(
        [Parameter(Mandatory=$true)][string]$MegaUrl,
        [Parameter(Mandatory=$true)][string]$OutDir
    )
    Ensure-Directory $OutDir
    $megaGet = Get-Command 'mega-get' -ErrorAction SilentlyContinue
    if (-not $megaGet) {
        Write-Warn "MEGAcmd not found (mega-get). Skipping Mega download."
        return $null
    }
    Write-Step "Downloading via Mega (MEGAcmd)..."
    $args = '"' + $MegaUrl + '" "' + $OutDir + '"'
    $p = Start-Process -FilePath $megaGet.Source -ArgumentList $args -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) {
        Write-Warn "mega-get exited with code $($p.ExitCode)"
        return $null
    }
    $archive = Get-ChildItem -Path $OutDir -Recurse -Include *.zip,*.7z -File | Sort-Object Length -Descending | Select-Object -First 1
    return ($archive?.FullName)
}

function Ensure-Autoexec {
    param(
        [Parameter(Mandatory=$true)][string]$GameRoot
    )
    $cfgDir = Join-Path $GameRoot 'dota\\cfg'
    Ensure-Directory $cfgDir
    $autoexec = Join-Path $cfgDir 'autoexec.cfg'
    if (-not (Test-Path -LiteralPath $autoexec)) {
        Write-Step "Creating autoexec.cfg with common settings..."
        @(
            '// Common Autoexec Commands',
            'dota_minimap_hero_size 1300',
            'dota_force_right_click_attack 1',
            'dota_player_auto_repeat_right_mouse 1',
            'dota_camera_disable_zoom 1',
            'bind "a" "mc_attack; +sixense_left_click; -sixense_left_click"'
        ) | Set-Content -Encoding ASCII -LiteralPath $autoexec
    } else {
        Write-Warn "autoexec.cfg already exists. Leaving as-is."
    }
}

function Write-SteamFixups {
    param(
        [Parameter(Mandatory=$true)][string]$GameRoot
    )
    # steam_appid.txt next to dota.exe
    $appidFile = Join-Path $GameRoot 'steam_appid.txt'
    if (-not (Test-Path -LiteralPath $appidFile)) {
        # As per community instructions, write hex bytes representation
        Set-Content -LiteralPath $appidFile -Value '3537 300a 00' -Encoding ASCII
    }
    # Modify dota/steam.inf
    $steamInf = Join-Path $GameRoot 'dota\steam.inf'
    if (Test-Path -LiteralPath $steamInf) {
        $lines = Get-Content -LiteralPath $steamInf -ErrorAction SilentlyContinue
        $kv = @{}
        foreach ($l in $lines) {
            if ($l -match '^(?<k>[^=]+)=(?<v>.*)$') { $kv[$matches.k] = $matches.v }
        }
        $kv['ClientVersion'] = 'https://api.steampowered.com/IGCVersion_570/GetClientVersion/v1?format=xml'
        $kv['ServerVersion'] = 'https://api.steampowered.com/IGCVersion_570/GetClientVersion/v1?format=xml'
        ($kv.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) | Set-Content -LiteralPath $steamInf -Encoding ASCII
    }
}

function Merge-SteamDepots {
    param(
        [Parameter(Mandatory=$true)][string]$DepotsRoot,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    $required = @('571','573','575')
    foreach ($d in $required) {
        $path = Join-Path $DepotsRoot ("depot_{0}" -f $d)
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Warn "Depot $d not found at $path"
            continue
        }
        Write-Step "Merging depot $d..."
        Ensure-Directory $Destination
        Copy-Item -Path (Join-Path $path '*') -Destination $Destination -Recurse -Force -ErrorAction Stop
    }
}

function Get-PatchDefinition {
    param([string]$Patch)
    $presets = @{
        's1-684c' = @{ AppId = 316570; Depots = @(
            @{ DepotId = 571; ManifestId = '23442636256031311' },
            @{ DepotId = 573; ManifestId = '7613852565918547628' },
            @{ DepotId = 575; ManifestId = '1660329391753369241' }
        ) }
    }
    if ($presets.ContainsKey($Patch)) { return $presets[$Patch] }
    if ($Patch -eq 'custom') {
        if (-not ($Manifest571 -and $Manifest573 -and $Manifest575)) { throw 'For custom patch, provide -Manifest571, -Manifest573, -Manifest575.' }
        return @{ AppId = 316570; Depots = @(
            @{ DepotId = 571; ManifestId = $Manifest571 },
            @{ DepotId = 573; ManifestId = $Manifest573 },
            @{ DepotId = 575; ManifestId = $Manifest575 }
        ) }
    }
    throw "Unknown patch preset: $Patch"
}

function Ensure-DepotDownloader {
    $root = Join-Path $env:TEMP 'DepotDownloader_portable'
    Ensure-Directory $root
    $exe = Join-Path $root 'DepotDownloader.exe'
    $dll = Join-Path $root 'DepotDownloader.dll'
    if ((Test-Path -LiteralPath $exe) -or (Test-Path -LiteralPath $dll)) { return $root }
    Write-Step "Downloading DepotDownloader..."
    $zip = Join-Path $root 'depotdownloader.zip'
    $url = 'https://github.com/SteamRE/DepotDownloader/releases/download/DepotDownloader_2.5.0/DepotDownloader-2.5.0.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $root -Force
    return $root
}

function __RunDepotDownload {
    param(
        [Parameter(Mandatory=$true)][int]$AppId,
        [Parameter(Mandatory=$true)][int]$DepotId,
        [Parameter(Mandatory=$true)][string]$ManifestId,
        [Parameter(Mandatory=$true)][string]$OutDir
    )
    $ddRoot = Ensure-DepotDownloader
    $exe = Join-Path $ddRoot 'DepotDownloader.exe'
    $dll = Join-Path $ddRoot 'DepotDownloader.dll'
    Ensure-Directory $OutDir
    $argList = "-app $AppId -depot $DepotId -manifest $ManifestId -os windows -dir `"$OutDir`" -validate"
    if (Test-Path -LiteralPath $exe) {
        $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -Wait -NoNewWindow
        if ($p.ExitCode -ne 0) { throw "DepotDownloader exited with code $($p.ExitCode) (app:$AppId depot:$DepotId)" }
    } elseif (Test-Path -LiteralPath $dll) {
        $p = Start-Process -FilePath 'dotnet' -ArgumentList ("`"$dll`" $argList") -PassThru -Wait -NoNewWindow
        if ($p.ExitCode -ne 0) { throw "DepotDownloader exited with code $($p.ExitCode) (app:$AppId depot:$DepotId)" }
    } else {
        throw 'DepotDownloader binary not found after extraction.'
    }
}

function Add-FirewallRuleForGame {
    param(
        [Parameter(Mandatory=$true)][string]$ExePath
    )
    try {
        Write-Step "Adding firewall allow rule for Dota 6.84..."
        $ruleName = 'Dota 6.84 Classic'
        if (-not (Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Program -eq $ExePath })) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Program $ExePath -Action Allow -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "$ruleName (Outbound)" -Direction Outbound -Program $ExePath -Action Allow -Profile Any | Out-Null
        } else {
            Write-Warn "Firewall rule already exists."
        }
    } catch {
        Write-Warn "Could not add firewall rule: $($_.Exception.Message)"
    }
}

function Toggle-HostsBlockDota2 {
    param(
        [Parameter(Mandatory=$true)][bool]$Enable
    )
    $hosts = Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'
    $line = '0.0.0.0 www.dota2.com'
    $content = @()
    if (Test-Path -LiteralPath $hosts) {
        $content = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue
    }
    if ($Enable) {
        if ($content -notcontains $line) {
            Write-Step "Blocking www.dota2.com in hosts..."
            Add-Content -LiteralPath $hosts -Value $line
        } else {
            Write-Warn "Hosts entry already present."
        }
    } else {
        if ($content -contains $line) {
            Write-Step "Removing www.dota2.com block from hosts..."
            $content | Where-Object { $_ -ne $line } | Set-Content -LiteralPath $hosts
        }
    }
}

function Install-Prereqs {
    $temp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("dota684_prereqs_" + [Guid]::NewGuid().ToString('N'))) -Force
    $dir = $temp.FullName

    # Known working static link for DirectX June 2010 redist
    $dxUrl = 'https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-AB65-9348EAE7DF11/directx_Jun2010_redist.exe'
    $vcx86 = 'https://aka.ms/vs/16/release/vc_redist.x86.exe'
    $vcx64 = 'https://aka.ms/vs/16/release/vc_redist.x64.exe'

    $dxFile = Join-Path $dir 'directx_Jun2010_redist.exe'
    $x86File = Join-Path $dir 'vc_redist.x86.exe'
    $x64File = Join-Path $dir 'vc_redist.x64.exe'

    # Detect if common DX June 2010 components appear present already
    $sys32 = [Environment]::GetFolderPath('System')
    $syswow64 = Join-Path $env:windir 'SysWOW64'
    $dxCandidates = @(
        (Join-Path $syswow64 'd3dx9_43.dll'),
        (Join-Path $syswow64 'xinput1_3.dll'),
        (Join-Path $syswow64 'XAudio2_7.dll')
    )
    $needDX = $true
    if ($dxCandidates | Where-Object { Test-Path -LiteralPath $_ }) { $needDX = $false }

    if ($needDX) {
        Write-Step "Downloading DirectX June 2010..."
        try {
            Invoke-WebRequest -Uri $dxUrl -OutFile $dxFile -UseBasicParsing
        } catch {
            Write-Warn ("DirectX download failed: {0}. Skipping DirectX; you can install manually from https://www.microsoft.com/en-us/download/details.aspx?id=8109" -f $_.Exception.Message)
            $dxFile = $null
        }
    } else {
        Write-Warn "DirectX June 2010 appears to be installed already. Skipping download."
        $dxFile = $null
    }
    # Detect if VC++ 2015-2019 runtime appears present already
    $sys32 = [Environment]::GetFolderPath('System')
    $syswow64 = Join-Path $env:windir 'SysWOW64'
    $needVcx86 = -not (Test-Path -LiteralPath (Join-Path $syswow64 'vcruntime140.dll'))
    $needVcx64 = -not (Test-Path -LiteralPath (Join-Path $sys32 'vcruntime140.dll'))

    if ($needVcx86) {
        Write-Step "Downloading VC++ x86..."
        Invoke-WebRequest -Uri $vcx86 -OutFile $x86File -UseBasicParsing
    } else {
        Write-Warn "VC++ x86 runtime appears installed. Skipping download."
        $x86File = $null
    }
    if ($needVcx64) {
        Write-Step "Downloading VC++ x64..."
        Invoke-WebRequest -Uri $vcx64 -OutFile $x64File -UseBasicParsing
    } else {
        Write-Warn "VC++ x64 runtime appears installed. Skipping download."
        $x64File = $null
    }

    if ($dxFile -and (Test-Path -LiteralPath $dxFile)) {
        Write-Step "Installing DirectX June 2010 (silent)..."
        Start-Process -FilePath $dxFile -ArgumentList '/Q' -Wait
        # DirectX extractor drops files; run DXSETUP silently if present
        $dxExtract = Get-ChildItem -Path $dir -Directory | Select-Object -First 1
        if ($dxExtract) {
            $dxSetup = Get-ChildItem -Path $dxExtract.FullName -Recurse -Filter 'DXSETUP.exe' | Select-Object -First 1
            if ($dxSetup) {
                Start-Process -FilePath $dxSetup.FullName -ArgumentList '/silent' -Wait
            }
        }
    } else {
        if ($needDX) { Write-Warn "Skipping DirectX install (package not downloaded)." }
    }

    if ($x86File -and (Test-Path -LiteralPath $x86File)) {
        Write-Step "Installing VC++ x86 (silent)..."
        Start-Process -FilePath $x86File -ArgumentList '/quiet /norestart' -Wait
    }
    if ($x64File -and (Test-Path -LiteralPath $x64File)) {
        Write-Step "Installing VC++ x64 (silent)..."
        Start-Process -FilePath $x64File -ArgumentList '/quiet /norestart' -Wait
    }

    Write-Step "Prerequisites installation complete."
}

function Create-DesktopLauncher {
    param(
        [Parameter(Mandatory=$true)][string]$GameExe,
        [Parameter(Mandatory=$true)][string]$InstallRoot
    )
    $desktop = [Environment]::GetFolderPath('Desktop')
    $batPath = Join-Path $desktop 'Launch Dota 6.84.bat'

    $bat = @(
        '@echo off',
        'title Dota 2 Classic 6.84 Launcher',
        'echo Ensure Steam is running. Starting the game...',
        'REM Optional: check if Steam.exe is running and warn',
        'tasklist /FI "IMAGENAME eq Steam.exe" | find /I "Steam.exe" >NUL',
        'if errorlevel 1 echo WARNING: Steam is not running. Please start Steam first.',
        'cd /d "%~dp0"',
        ('start "" "{0}"' -f $GameExe),
        'REM Optionally open queue page',
        'timeout /t 5 >NUL',
        'start "" https://dota2classic.com/queue'
    ) -join "`r`n"

    Set-Content -LiteralPath $batPath -Value $bat -Encoding ASCII
    Write-Step "Created Desktop launcher: $batPath"
}

function Open-QueuePages {
    Start-Process 'https://dota2classic.com/Auth/signin?redirectUrl=/&authProvider=Steam'
    Start-Process 'https://dota2classic.com/queue'
}

function Main {
    Assert-Admin

    Write-Host "Dota 2 Classic 6.84 Installer" -ForegroundColor Green
    Write-Host "Install directory: $InstallDir" -ForegroundColor Gray
    Ensure-Directory $InstallDir

    $archive = $null
    $localArchive = $null
    if ($LocalArchive -and (Test-Path -LiteralPath $LocalArchive)) { $localArchive = $LocalArchive } else { $localArchive = Get-LocalArchive }
    $localTorrent = Get-LocalTorrent

    if ($localArchive) {
        Write-Step "Using local archive: $localArchive"
        $archive = $localArchive
    } else {
        Write-Err "No local archive specified/found and Steam depot mode not selected. Provide -LocalArchive or choose the Steam depot option in the GUI."
        exit 1
    }

    if ($archive) {
        # Skip extraction if install dir already contains a Dota 6.84 install (detect dota.exe)
        $existingGameExe = Get-ChildItem -Path $InstallDir -Recurse -Filter 'dota.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existingGameExe) {
            Write-Warn ("Install folder already contains an existing game (found: {0}). Skipping extraction." -f $existingGameExe.FullName)
        } else {
            Write-Step "Extracting archive..."
            Expand-ArchiveSmart -ArchivePath $archive -Destination $InstallDir
        }
    }

    # Try to detect game executable
    $exeCandidates = @(
        (Join-Path $InstallDir 'dota.exe'),
        (Get-ChildItem -Path $InstallDir -Recurse -Filter 'dota.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.FullName })
    )
    $gameExe = $null
    foreach ($c in $exeCandidates) { if ($c -and (Test-Path -LiteralPath $c)) { $gameExe = $c; break } }
    if (-not $gameExe) {
        Write-Warn "Could not locate dota.exe automatically. Please select it in the installation directory."
        $gameExe = Read-Host "Enter full path to dota.exe"
        if (-not (Test-Path -LiteralPath $gameExe)) { throw "Invalid dota.exe path" }
    }

    # Ensure autoexec exists
    $gameRoot = [System.IO.Path]::GetDirectoryName($gameExe)
    Ensure-Autoexec -GameRoot $gameRoot
    Write-SteamFixups -GameRoot $gameRoot

    # Firewall
    if (-not $NoAdmin) { Add-FirewallRuleForGame -ExePath $gameExe } else { Write-Warn "Skipping firewall rule (NoAdmin)." }

    # Optional hosts block
    if ($BlockDota2Site -and -not $NoAdmin) { Toggle-HostsBlockDota2 -Enable $true } elseif ($BlockDota2Site -and $NoAdmin) { Write-Warn "Skipping hosts modification (NoAdmin)." }

    # Optional prerequisites
    if ($InstallPrereqs -and -not $NoAdmin) { Install-Prereqs } elseif ($InstallPrereqs -and $NoAdmin) { Write-Warn "Skipping prerequisites install (NoAdmin)." }

    # Desktop launcher
    Create-DesktopLauncher -GameExe $gameExe -InstallRoot $InstallDir

    if ($OpenQueue) { Open-QueuePages }

    Write-Host "Installation complete. Launch via the Desktop shortcut 'Launch Dota 6.84.bat'. Make sure Steam is running." -ForegroundColor Green
}

Main


