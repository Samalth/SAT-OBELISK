$AppVersion = "2.3.0"

$root = $PSScriptRoot
$packageVersion = (Select-String -Path "$root\obelisk\__init__.py" -Pattern '^__version__ = "(.+)"').Matches[0].Groups[1].Value
if ($packageVersion -ne $AppVersion) {
    Write-Host "Version mismatch: build_installer.ps1 has $AppVersion, obelisk\__init__.py has $packageVersion"
    exit 1
}
& "$root\build_exe.ps1"

$candidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host "Inno Setup not found. Install it:  winget install JRSoftware.InnoSetup"
    exit 1
}
& $iscc "/DAppVersion=$AppVersion" "$root\installer\obelisk.iss"
Write-Host "`nInstaller: installer\dist\SAT-Obelisk-Setup-$AppVersion.exe"
