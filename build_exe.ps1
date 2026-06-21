$root = $PSScriptRoot
python -m pip install --quiet pyinstaller pillow argon2-cffi cryptography
python "$root\assets\make_icon.py"
$localeArgs = Get-ChildItem "$root\locales\*.json" | ForEach-Object {
    "--add-data"; "$($_.FullName);locales"
}
python -m PyInstaller --onefile --windowed --name Obelisk `
    --icon "$root\assets\icon.ico" `
    --add-data "$root\assets\icon.png;assets" `
    --add-data "$root\assets\icon.ico;assets" `
    --collect-all cryptography `
    --collect-all argon2 `
    @localeArgs `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" "$root\app.py"
Write-Host "`nPortable EXE: dist\Obelisk.exe"
