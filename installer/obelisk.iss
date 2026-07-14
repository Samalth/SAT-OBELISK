#define AppName "SAT-Obelisk"
#define AppVersion "2.2.0"
#define AppPublisher "S.A. Thiers"
#define AppExe "Obelisk.exe"

[Setup]
AppId={{8F3C2A14-7B1D-4A2E-9C77-A1B2C3D4E5F6}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=dist
OutputBaseFilename=SAT-Obelisk-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\assets\icon.ico
LicenseFile=..\LICENSE

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "nl"; MessagesFile: "compiler:Languages\Dutch.isl"

[Messages]
en.LicenseAccepted=I &accept the agreements
en.LicenseNotAccepted=I &do not accept the agreements
en.LicenseLabel3=Please read the following License Agreement. You must accept the terms of this agreement, and the related agreements it references, before continuing with the installation.
nl.LicenseAccepted=Ik &accepteer de overeenkomsten
nl.LicenseNotAccepted=Ik accepteer de overeenkomsten &niet
nl.LicenseLabel3=Lees de volgende licentieovereenkomst. U dient de voorwaarden van deze overeenkomst, en de daarin genoemde gerelateerde overeenkomsten, te accepteren voordat u verdergaat met de installatie.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "assocobl"; Description: "Associate .obl files (open to decrypt)"; GroupDescription: "Integration:"
Name: "contextmenu"; Description: "Add ""Encrypt with SAT-Obelisk"" to the right-click menu"; GroupDescription: "Integration:"

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Application language chosen on the custom wizard page, read by the app on startup
Root: HKA; Subkey: "Software\SAT-Obelisk"; ValueType: string; ValueName: "Language"; ValueData: "{code:GetAppLang}"; Flags: uninsdeletekey

Root: HKA; Subkey: "Software\Classes\.obl"; ValueType: string; ValueName: ""; ValueData: "SATObelisk.Encrypted"; Flags: uninsdeletevalue; Tasks: assocobl
Root: HKA; Subkey: "Software\Classes\SATObelisk.Encrypted"; ValueType: string; ValueName: ""; ValueData: "OBELISK encrypted file"; Flags: uninsdeletekey; Tasks: assocobl
Root: HKA; Subkey: "Software\Classes\SATObelisk.Encrypted\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"; Tasks: assocobl
Root: HKA; Subkey: "Software\Classes\SATObelisk.Encrypted\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: assocobl

Root: HKA; Subkey: "Software\Classes\*\shell\SATObelisk.Encrypt"; ValueType: string; ValueName: ""; ValueData: "Encrypt with SAT-Obelisk"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SATObelisk.Encrypt"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SATObelisk.Encrypt\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SATObelisk.Encrypt"; ValueType: string; ValueName: ""; ValueData: "Encrypt with SAT-Obelisk"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SATObelisk.Encrypt"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SATObelisk.Encrypt\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
const
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3C2A14-7B1D-4A2E-9C77-A1B2C3D4E5F6}_is1';

var
  AppLangCombo: TNewComboBox;
  SameLangCheck: TNewCheckBox;
  ReplacePage: TWizardPage;
  ReplaceCheck: TNewCheckBox;
  ExistingVer: String;

function ReadDisplayVersion(RootKey: Integer): String;
var
  v: String;
begin
  Result := '';
  if RegQueryStringValue(RootKey, UninstKey, 'DisplayVersion', v) then
    Result := v;
end;

function InstalledVersion(): String;
begin
  { Check every view: per-user (HKCU) and per-machine in both the 32- and
    64-bit registry views, since this 32-bit setup installs in 64-bit mode. }
  Result := ReadDisplayVersion(HKCU);
  if Result = '' then Result := ReadDisplayVersion(HKLM);
  if Result = '' then Result := ReadDisplayVersion(HKLM64);
end;

function LangCodeToIndex(Code: String): Integer;
begin
  if Code = 'nl' then Result := 1
  else if Code = 'es' then Result := 2
  else if Code = 'zh' then Result := 3
  else if Code = 'ro' then Result := 4
  else if Code = 'fr' then Result := 5
  else if Code = 'de' then Result := 6
  else if Code = 'it' then Result := 7
  else if Code = 'pt' then Result := 8
  else Result := 0;
end;

procedure UpdateLangComboState();
begin
  { When 'same as installer' is ticked, mirror the wizard language and lock the
    dropdown; otherwise let the user pick the application language freely. }
  if SameLangCheck.Checked then begin
    AppLangCombo.ItemIndex := LangCodeToIndex(ActiveLanguage);
    AppLangCombo.Enabled := False;
  end else
    AppLangCombo.Enabled := True;
end;

procedure SameLangClick(Sender: TObject);
begin
  UpdateLangComboState();
end;

procedure InitializeWizard();
var
  LangPage: TWizardPage;
  Lbl: TNewStaticText;
begin
  { Language page: first wizard page, right after Inno's startup language dialog }
  LangPage := CreateCustomPage(wpWelcome,
    'Language',
    'Choose the language for the application.');

  Lbl := TNewStaticText.Create(LangPage);
  Lbl.Parent := LangPage.Surface;
  Lbl.AutoSize := False;
  Lbl.Top := ScaleY(0);
  Lbl.Width := LangPage.SurfaceWidth;
  Lbl.Height := ScaleY(32);
  Lbl.WordWrap := True;
  Lbl.Caption := 'The installer (wizard) language is selected when Setup starts. ' +
    'Choose the language the application itself will start in below.';

  SameLangCheck := TNewCheckBox.Create(LangPage);
  SameLangCheck.Parent := LangPage.Surface;
  SameLangCheck.Top := Lbl.Top + ScaleY(40);
  SameLangCheck.Width := LangPage.SurfaceWidth;
  SameLangCheck.Caption := 'Use the same language as the installer';
  SameLangCheck.Checked := True;
  SameLangCheck.OnClick := @SameLangClick;

  Lbl := TNewStaticText.Create(LangPage);
  Lbl.Parent := LangPage.Surface;
  Lbl.Top := SameLangCheck.Top + ScaleY(32);
  Lbl.Caption := 'Application language:';

  AppLangCombo := TNewComboBox.Create(LangPage);
  AppLangCombo.Parent := LangPage.Surface;
  AppLangCombo.Style := csDropDownList;
  AppLangCombo.Top := Lbl.Top + ScaleY(18);
  AppLangCombo.Width := ScaleX(220);
  AppLangCombo.Items.Add('English');
  AppLangCombo.Items.Add('Nederlands (Dutch)');
  AppLangCombo.Items.Add('Espanol (Spanish)');
  AppLangCombo.Items.Add('Zhongwen (Chinese)');
  AppLangCombo.Items.Add('Romana (Romanian)');
  AppLangCombo.Items.Add('Francais (French)');
  AppLangCombo.Items.Add('Deutsch (German)');
  AppLangCombo.Items.Add('Italiano (Italian)');
  AppLangCombo.Items.Add('Portugues (Portuguese)');
  UpdateLangComboState();

  { Existing-version page: only created when a prior install is detected }
  ExistingVer := InstalledVersion();
  if ExistingVer <> '' then begin
    ReplacePage := CreateCustomPage(LangPage.ID,
      'Existing installation found',
      'A version of SAT-Obelisk is already installed on this device.');

    Lbl := TNewStaticText.Create(ReplacePage);
    Lbl.Parent := ReplacePage.Surface;
    Lbl.AutoSize := False;
    Lbl.Top := ScaleY(0);
    Lbl.Width := ReplacePage.SurfaceWidth;
    Lbl.Height := ScaleY(48);
    Lbl.WordWrap := True;
    Lbl.Caption := 'Version ' + ExistingVer + ' is currently installed. Tick the box below ' +
      'to replace it with version {#AppVersion}. If you do not want to replace it, cancel the setup.';

    ReplaceCheck := TNewCheckBox.Create(ReplacePage);
    ReplaceCheck.Parent := ReplacePage.Surface;
    ReplaceCheck.Top := Lbl.Top + ScaleY(56);
    ReplaceCheck.Width := ReplacePage.SurfaceWidth;
    ReplaceCheck.Caption := 'Replace version ' + ExistingVer + ' with version {#AppVersion}';
    ReplaceCheck.Checked := False;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (ReplacePage <> nil) and (CurPageID = ReplacePage.ID) and (not ReplaceCheck.Checked) then begin
    MsgBox('Tick "Replace version ' + ExistingVer + '" to continue, or cancel the setup.',
      mbInformation, MB_OK);
    Result := False;
  end;
end;

function GetAppLang(Param: String): String;
begin
  case AppLangCombo.ItemIndex of
    1: Result := 'nl';
    2: Result := 'es';
    3: Result := 'zh';
    4: Result := 'ro';
    5: Result := 'fr';
    6: Result := 'de';
    7: Result := 'it';
    8: Result := 'pt';
  else
    Result := 'en';
  end;
end;
