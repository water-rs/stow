# stow's one-line installer for Windows: fetch the latest stow-cli
# release through its cargo-dist installer, then wire cargo so every
# build on this machine runs through stow.
$ErrorActionPreference = 'Stop'

$InstallerUrl = 'https://github.com/water-rs/stow/releases/latest/download/stow-cli-installer.ps1'
$Installer = Join-Path ([System.IO.Path]::GetTempPath()) "stow-cli-installer-$PID.ps1"

try {
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $Installer -UseBasicParsing
}
catch {
    throw "stow install: downloading $InstallerUrl failed: $_"
}

try {
    & $Installer
    if ($LASTEXITCODE -ne 0) {
        throw "stow install: the stow-cli installer exited with $LASTEXITCODE"
    }

    $BinDir = if ($env:CARGO_HOME) {
        Join-Path $env:CARGO_HOME 'bin'
    } else {
        Join-Path $HOME '.cargo\bin'
    }
    $Stow = Join-Path $BinDir 'stow.exe'
    if (-not (Test-Path $Stow)) {
        throw "stow install: the installer did not leave $Stow"
    }

    # Write stow's wrapper wiring into the global cargo config — every
    # cargo invocation on this machine is accelerated from here on.
    & $Stow setup
    if ($LASTEXITCODE -ne 0) {
        throw "stow install: 'stow setup' failed with $LASTEXITCODE"
    }

    Write-Output 'stow is installed - plain ''cargo build'' now runs through stow'
}
finally {
    Remove-Item $Installer -Force -ErrorAction SilentlyContinue
}
