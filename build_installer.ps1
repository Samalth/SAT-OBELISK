$root = $PSScriptRoot
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
& $iscc "$root\installer\obelisk.iss"
Write-Host "`nInstaller: installer\dist\SAT-Obelisk-Setup-2.0.1.exe"
