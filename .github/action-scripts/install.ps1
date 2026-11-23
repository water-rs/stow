$ErrorActionPreference = 'Stop'

if ($env:STOW_LOCAL_ONLY -eq '1') {
  $configDir = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'stow'
  $configFile = Join-Path $configDir 'config.toml'
  $wanted = "[cache]`nremote = false`n"
  if (Test-Path -LiteralPath $configFile) {
    $existing = [System.IO.File]::ReadAllText($configFile)
    if ($existing -ne $wanted) {
      throw "$configFile already exists with custom contents; refusing to overwrite it"
    }
  }
  New-Item -ItemType Directory -Force -Path $configDir | Out-Null
  [System.IO.File]::WriteAllText($configFile, $wanted, [System.Text.UTF8Encoding]::new($false))
}

$version = $env:STOW_VERSION
if ($version -eq 'latest') {
  # The newest installable release; see install.sh.
  $tag = gh api 'repos/water-rs/stow/releases?per_page=100' `
    --jq '[.[] | select(.draft == false and .prerelease == false) | select(any(.assets[]; .name | startswith("stow-cli-"))) | .tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))][0] // empty'
  if ($LASTEXITCODE -ne 0) { throw 'gh api failed while listing releases' }
  if (-not $tag) { throw 'no installable v<version> release found on water-rs/stow' }
} else {
  $tag = 'v' + ($version -replace '^v', '')
}
$version = $tag -replace '^v', ''

$target = switch ("$env:RUNNER_OS-$env:RUNNER_ARCH") {
  'Windows-X64' { 'x86_64-pc-windows-msvc' }
  'Windows-ARM64' { 'aarch64-pc-windows-msvc' }
  default { throw "no stow-cli release target for $env:RUNNER_OS-$env:RUNNER_ARCH" }
}

$archive = "stow-cli-$target.zip"
$workdir = New-Item -ItemType Directory -Path (Join-Path $env:RUNNER_TEMP ([System.IO.Path]::GetRandomFileName()))
gh release download $tag --repo water-rs/stow --dir $workdir.FullName --pattern $archive --pattern "$archive.sha256"
if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $tag ($archive)" }

# A corrupt binary is not a fallback case: abort on mismatch.
$expected = ((Get-Content -Raw (Join-Path $workdir.FullName "$archive.sha256")) -split '\s+')[0].ToLower()
$actual = (Get-FileHash -Algorithm SHA256 (Join-Path $workdir.FullName $archive)).Hash.ToLower()
if ($expected -ne $actual) { throw "checksum mismatch for $archive (expected $expected, got $actual)" }

if (-not $env:RUNNER_TOOL_CACHE) { throw 'RUNNER_TOOL_CACHE is not set on this runner' }
$dest = Join-Path $env:RUNNER_TOOL_CACHE "stow\$version\$target"
$extract = New-Item -ItemType Directory -Path (Join-Path $env:RUNNER_TEMP ([System.IO.Path]::GetRandomFileName()))
Expand-Archive -Path (Join-Path $workdir.FullName $archive) -DestinationPath $extract.FullName
$binDir = (Get-ChildItem -Recurse -Filter stow-cli.exe $extract.FullName | Select-Object -First 1).DirectoryName
if (-not $binDir) { throw "$archive contains no stow-cli.exe" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Recurse -Force "$binDir\*" $dest
Add-Content -Path $env:GITHUB_PATH -Value $dest

& (Join-Path $dest 'stow.exe') setup --github-env | Out-File -Append -FilePath $env:GITHUB_ENV -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw 'stow setup --github-env failed' }
# The linker selection cannot ride in the job environment; setup
# writes it into the runner's global cargo config while leaving
# Cargo's standard `target/` layout untouched.
& (Join-Path $dest 'stow.exe') setup --no-build-dir --no-install-skill
if ($LASTEXITCODE -ne 0) { throw 'stow setup failed' }
