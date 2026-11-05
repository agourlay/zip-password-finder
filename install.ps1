# Install the latest zip-password-finder release on Windows.
#
#   irm https://raw.githubusercontent.com/agourlay/zip-password-finder/master/site/install.ps1 | iex
#
# Fetched from raw.githubusercontent.com rather than from the landing page:
# GitHub Pages serves .ps1 as application/octet-stream, and irm hands iex
# bytes rather than text for that type on some PowerShell versions. Raw
# serves it as text/plain.
#
# Downloads the release archive for this machine from GitHub, puts
# zip-password-finder.exe in %LOCALAPPDATA%\Programs\zip-password-finder (or in
# $env:ZIP_PASSWORD_FINDER_INSTALL_DIR when set) and adds that folder to the
# user's PATH. It is one self-contained binary, so that is the whole install;
# to uninstall, delete the folder.
#
# Everything lives inside a script block invoked on the last line, so a
# download cut off halfway runs nothing rather than half a script.
& {
  $ErrorActionPreference = 'Stop'
  # Windows PowerShell 5.1 still offers TLS 1.0 first, which GitHub refuses.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  # The progress bar slows Invoke-WebRequest down by an order of magnitude.
  $ProgressPreference = 'SilentlyContinue'

  $repo = 'agourlay/zip-password-finder'

  # PROCESSOR_ARCHITEW6432 is set when an x86 shell runs on a 64-bit
  # system, and names the real processor.
  $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $arch = switch ($cpu) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { throw "zip-password-finder has no build for a $cpu processor" }
  }

  # The latest tag, from the API: the redirect trick install.sh uses is
  # awkward across the two PowerShell editions, and one anonymous call is
  # well inside the rate limit.
  $tag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
  if ($tag -notmatch '^v\d') { throw "could not find the latest release (got '$tag')" }

  $target = "$arch-pc-windows-msvc"
  $archive = "zip-password-finder-$target.zip"
  $url = "https://github.com/$repo/releases/download/$tag/$archive"
  $dir = if ($env:ZIP_PASSWORD_FINDER_INSTALL_DIR) { $env:ZIP_PASSWORD_FINDER_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\zip-password-finder' }

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "Downloading zip-password-finder $tag for $target"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile (Join-Path $tmp $archive)
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item (Join-Path $tmp 'zip-password-finder.exe') (Join-Path $dir 'zip-password-finder.exe') -Force
  } finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }

  Write-Host "Installed $dir\zip-password-finder.exe"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $entries = if ($userPath) { $userPath -split ';' } else { @() }
  if ($entries -notcontains $dir) {
    $newPath = (@($entries | Where-Object { $_ }) + $dir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$dir"
    Write-Host "Added $dir to your PATH; open a new terminal to pick it up."
  }
  Write-Host 'Run it with: zip-password-finder'
}
