<#
Install a released Sindook binary for Windows without administrator rights.
The matching SHA-256 checksum is verified before installation; a cosign
keyless signature check runs when cosign is available (best-effort, clearly
announced). This script is meant to be downloaded and run directly.
#>
[CmdletBinding()]
param(
    [string]$Version = $env:SINDOOK_VERSION,
    [string]$InstallDir = $env:SINDOOK_INSTALL_DIR,
    [string]$Repo = $(if ($env:SINDOOK_REPO) { $env:SINDOOK_REPO } else { 'ruddro-roy/sindook' }),
    [switch]$Yes
)

# -Yes is accepted for scripted runs; the installer never prompts today.
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'sindook\bin'
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $headers = @{ 'User-Agent' = 'sindook-installer' }
    $release = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $tag = $release.tag_name
    $assetVersion = $tag.TrimStart('v')
    $downloadBase = "https://github.com/$Repo/releases/latest/download"
} else {
    if ($Version.StartsWith('v')) { $tag = $Version } else { $tag = "v$Version" }
    if ($tag -notmatch '^v[0-9]') {
        throw "Sindook installer: invalid release version '$tag'."
    }
    $assetVersion = $tag.TrimStart('v')
    $downloadBase = "https://github.com/$Repo/releases/download/$tag"
}

$architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch -Regex ($architecture) {
    '^(AMD64|x86_64)$' { $arch = 'amd64'; break }
    '^ARM64$' { $arch = 'arm64'; break }
    default { throw "Sindook installer: unsupported Windows architecture '$architecture'." }
}

$asset = "sindook_${assetVersion}_windows_${arch}.zip"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sindook-" + [Guid]::NewGuid().ToString('N'))
$archive = Join-Path $tempDir $asset
$checksums = Join-Path $tempDir 'checksums.txt'
$bundle = Join-Path $tempDir 'checksums.txt.sigstore.json'
$expanded = Join-Path $tempDir 'expanded'

try {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Write-Host "Downloading Sindook $tag for windows/$arch..."
    Invoke-WebRequest -Uri "$downloadBase/$asset" -OutFile $archive
    Invoke-WebRequest -Uri "$downloadBase/checksums.txt" -OutFile $checksums

    $checksumPattern = '^[A-Fa-f0-9]{64}\s+\*?' + [regex]::Escape($asset) + '$'
    $checksumLine = Get-Content -LiteralPath $checksums | Where-Object { $_ -match $checksumPattern } | Select-Object -First 1
    if (-not $checksumLine) {
        throw "Sindook installer: $asset was not listed in checksums.txt."
    }
    $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Sindook installer: checksum mismatch for $asset. Do not trust this download; report the incident."
    }
    Write-Host "SHA-256 verified: $expected"

    # Best-effort cosign keyless verification of checksums.txt. The SHA-256
    # check above is authoritative for installation; cosign additionally binds
    # the checksums to the repository's GitHub Actions identity when present.
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if ($cosign) {
        Write-Host 'cosign found; verifying keyless signature (best-effort)...'
        try {
            Invoke-WebRequest -Uri "$downloadBase/checksums.txt.sigstore.json" -OutFile $bundle
            & $cosign.Source verify-blob $checksums --bundle $bundle `
                --certificate-identity-regexp 'github.com/ruddro-roy/sindook' `
                --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host 'cosign verification succeeded.'
            } else {
                Write-Warning 'cosign verification reported a failure; continuing because the SHA-256 check passed.'
                Write-Warning 'Review manually: cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json'
            }
        } catch {
            Write-Warning 'cosign verification could not complete; continuing because the SHA-256 check passed.'
        }
    } else {
        Write-Host 'cosign not found; skipping keyless signature verification.'
        Write-Host 'The archive SHA-256 was verified against checksums.txt.'
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $expanded -Force
    $binary = Get-ChildItem -LiteralPath $expanded -Filter 'sindook.exe' -File -Recurse | Select-Object -First 1
    if (-not $binary) {
        throw 'Sindook installer: archive did not contain sindook.exe.'
    }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $target = Join-Path $InstallDir 'sindook.exe'
    Copy-Item -LiteralPath $binary.FullName -Destination $target -Force

    Write-Host ''
    Write-Host "Installed Sindook $tag to $target"
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $InstallDir)) {
        Write-Host "Add $InstallDir to your User PATH, open a new PowerShell window, then run:"
        Write-Host '  sindook version'
    }
    Write-Host 'Post-install check:'
    Write-Host '  sindook version'
    Write-Host 'Optional shell completion for the current profile:'
    Write-Host '  sindook completion powershell | Add-Content $PROFILE'
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
