<#
.SYNOPSIS
    Automatisiertes Testskript für anon.ps1 (PowerShell 5.1+ und PowerShell 7+).
    Prüft:
    1. Alle 48 Testfälle in tests\faelle.json (LF UND CRLF, inkl. Grenzfälle, JSON-Validität, Rückübersetzung)
    2. Identische Ausgaben zwischen anon.ps1 und anonymisierer.html (LF UND CRLF über tests\erwartet\)
    3. Archiv-Verarbeitung (.zip und .tar.gz), Überspringen von Binärdateien
    4. Sicherheitsregeln: Zuordnungstabelle darf NIE im Ausgabeordner liegen; <Ausgabe>\_arbeit\ wird gelöscht; nur <Ausgabe>\anonym\ und bericht.json bleiben übrig
    5. Explizite Tests für alle 11 Code-Review-Befunde (Befund 1 bis Befund 11)
    6. Performance- & Stresstest (40.000+ Zeilen Aruba Show-Tech)
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$testDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $testDir
$anonScript = Join-Path (Join-Path $rootDir "powershell") "anon.ps1"
$rulesPath = Join-Path (Join-Path $rootDir "regeln") "anon-regeln.json"
$casesPath = Join-Path $testDir "faelle.json"
$beispieleDir = Join-Path $testDir "beispiele"
$erwartetDir = Join-Path $testDir "erwartet"

$passed = 0
$failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:passed++
    } else {
        $script:failed++
        Write-Host "  [FEHLER] $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -eq $Expected) {
        $script:passed++
    } else {
        $script:failed++
        Write-Host "  [FEHLER] $Message (Erwartet: '$Expected', Erhalten: '$Actual')" -ForegroundColor Red
    }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try {
        & $Action
    } catch {
        $threw = $true
    }
    Assert-True $threw $Message
}

Write-Host "=== 1. Initialisiere AnonTool.AnonEngine über anon.ps1 (Trockenlauf) ===" -ForegroundColor Cyan
& $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Regeln $rulesPath -Probe > $null
Assert-True ($LASTEXITCODE -eq 0) "Trockenlauf auf sauberer Beispieldatei liefert Exit-Code 0"
Assert-True ($null -ne ("AnonTool.AnonEngine" -as [type])) "C# AnonEngine erfolgreich geladen"

Write-Host "=== 2. Prüfe alle Testfälle aus tests\faelle.json (LF und CRLF, Parität A == B) ===" -ForegroundColor Cyan
$casesJson = [System.IO.File]::ReadAllText($casesPath, [System.Text.Encoding]::UTF8)
$cases = ConvertFrom-Json -InputObject $casesJson
Assert-True ($cases.Count -ge 48) "Mindestens 48 Testfälle geladen ($($cases.Count))"

$rawRules = [System.IO.File]::ReadAllText($rulesPath, [System.Text.Encoding]::UTF8)
$rulesObj = ConvertFrom-Json -InputObject $rawRules

function New-TestConfig {
    param($RulesObj, [bool]$Netzerhaltend = $true, [string[]]$KatFilter = $null)
    $cfg = New-Object AnonTool.EngineConfig
    $rxTimeout = [TimeSpan]::FromSeconds(5)
    $rxOpts = [System.Text.RegularExpressions.RegexOptions]::Compiled
    $cfg.Netzerhaltend = $Netzerhaltend
    $cfg.IpPrivatOeffentlichTrennen = [bool]$RulesObj.optionen.ipPrivatOeffentlichTrennen
    $cfg.SubnetzmaskenBehalten = [bool]$RulesObj.optionen.subnetzmaskenBehalten
    $cfg.MacNormalisieren = [bool]$RulesObj.optionen.macNormalisieren

    if ($null -ne $KatFilter -and $KatFilter.Count -gt 0) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $KatFilter) { [void]$set.Add($k) }
        $cfg.CatGeheimnisse = $set.Contains("geheimnisseEntfernen")
        $cfg.CatIp = $set.Contains("ip")
        $cfg.CatMac = $set.Contains("mac")
        $cfg.CatHostnamen = $set.Contains("hostnamen")
        $cfg.CatBenutzer = $set.Contains("benutzer")
        $cfg.CatSeriennummern = $set.Contains("seriennummern")
        $cfg.CatFreitext = $set.Contains("freitext")
        $cfg.CatEigeneBegriffe = $set.Contains("eigeneBegriffe")
    }

    foreach ($p in $RulesObj.eigeneBegriffe.festeZuordnung.PSObject.Properties) { $cfg.FesteZuordnung[$p.Name] = [string]$p.Value }
    foreach ($x in $RulesObj.eigeneBegriffe.firmenUndStandorte) { $cfg.FirmenUndStandorte.Add([string]$x) }
    foreach ($x in $RulesObj.eigeneBegriffe.interneDomains) { $cfg.InterneDomains.Add([string]$x) }
    foreach ($x in $RulesObj.ausnahmen.exakteWoerter) { [void]$cfg.ExakteAusnahmen.Add([string]$x) }
    foreach ($x in $RulesObj.ausnahmen.versionKontext) { $cfg.VersionKontextRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.ausnahmen.musterRegex) { $cfg.AusnahmenRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.pruefung.erlaubtListe) { [void]$cfg.PruefungErlaubtListe.Add([string]$x) }
    foreach ($x in $RulesObj.pruefung.erlaubtMuster) { $cfg.PruefungErlaubtMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }

    foreach ($gm in $RulesObj.geheimnisMuster) {
        $sr = New-Object AnonTool.SecretRule
        $sr.Name = [string]$gm.name
        $sr.Pattern = [string]$gm.suche
        $sr.Replacement = [string]$gm.ersetzen
        $sr.Compiled = New-Object System.Text.RegularExpressions.Regex ($sr.Pattern, $rxOpts, $rxTimeout)
        $cfg.GeheimnisMuster.Add($sr)
    }
    foreach ($fm in $RulesObj.freitextMuster) {
        $fr = New-Object AnonTool.FreeTextRule
        $fr.Name = [string]$fm.name
        $fr.Category = [string]$fm.kategorie
        $fr.Pattern = [string]$fm.suche
        $fr.Compiled = New-Object System.Text.RegularExpressions.Regex ($fr.Pattern, $rxOpts, $rxTimeout)
        $cfg.FreitextMuster.Add($fr)
    }
    foreach ($x in $RulesObj.seriennummerMuster) { $cfg.SeriennummerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.benutzerMuster) { $cfg.BenutzerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.hostnamenMuster) { $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    if ($null -ne $RulesObj.PSObject.Properties["eigeneHostnamenMuster"]) {
        foreach ($x in $RulesObj.eigeneHostnamenMuster) { $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    }
    if ($null -ne $RulesObj.PSObject.Properties["tabellenSpalten"]) {
        foreach ($tr in $RulesObj.tabellenSpalten) {
            $rule = New-Object AnonTool.TableRule
            $rule.Name = [string]$tr.name
            foreach ($k in $tr.kopf) { $rule.Kopf.Add([string]$k) }
            foreach ($sp in $tr.spalten) {
                $col = New-Object AnonTool.TableColumnSpec
                $col.Name = [string]$sp.name
                $col.Kategorie = [string]$sp.kategorie
                $rule.Spalten.Add($col)
            }
            $cfg.TabellenSpalten.Add($rule)
        }
    }
    return $cfg
}

foreach ($tc in $cases) {
    $netMode = if ($null -ne $tc.netzerhaltend) { [bool]$tc.netzerhaltend } else { $true }
    $katFilter = if ($null -ne $tc.PSObject.Properties["kategorien"]) { @($tc.kategorien) } else { $null }
    $cfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $netMode -KatFilter $katFilter

    # 2a. LF-Variante
    $st = New-Object AnonTool.AnonState
    $actual = [AnonTool.AnonEngine]::ProcessText([string]$tc.eingabe, $cfg, $st)
    $isEqual = ($actual -ceq [string]$tc.erwartet)
    if (-not $isEqual) {
        Write-Host "  [$($tc.id) LF] Erwartet: $($tc.erwartet)" -ForegroundColor Yellow
        Write-Host "  [$($tc.id) LF] Erhalten: $actual" -ForegroundColor Yellow
    }
    Assert-True $isEqual "$($tc.id) (LF): $($tc.name) (PS1 == Erwartet)"

    $findings = [AnonTool.AnonEngine]::AuditText($actual, "$($tc.id).txt", $cfg, $st)
    $isClean = ($findings.Count -eq 0)
    Assert-True ($isClean -eq [bool]$tc.sauber) "$($tc.id) (LF): Prüfmodus sauber=$isClean (erwartet $($tc.sauber))"

    # 2b. Befund 1: CRLF-Variante für den gesamten Testkorpus
    $crlfIn = ([string]$tc.eingabe) -replace "\r?\n", "`r`n"
    $crlfExp = ([string]$tc.erwartet) -replace "\r?\n", "`r`n"
    $stCrlf = New-Object AnonTool.AnonState
    $actualCrlf = [AnonTool.AnonEngine]::ProcessText($crlfIn, $cfg, $stCrlf)
    $isEqualCrlf = ($actualCrlf -ceq $crlfExp)
    if (-not $isEqualCrlf) {
        Write-Host "  [$($tc.id) CRLF] Erwartet: $crlfExp" -ForegroundColor Yellow
        Write-Host "  [$($tc.id) CRLF] Erhalten: $actualCrlf" -ForegroundColor Yellow
    }
    Assert-True $isEqualCrlf "$($tc.id) (CRLF): $($tc.name) (PS1 CRLF == Erwartet CRLF)"

    $findingsCrlf = [AnonTool.AnonEngine]::AuditText($actualCrlf, "$($tc.id).txt", $cfg, $stCrlf)
    Assert-True (($findingsCrlf.Count -eq 0) -eq [bool]$tc.sauber) "$($tc.id) (CRLF): Prüfmodus sauber=$($findingsCrlf.Count -eq 0)"

    # Bekannte Lücken: Der Prüfmodus muss die Rohdaten (ohne Anonymisierung) beanstanden
    if ($null -ne $tc.PSObject.Properties["pruefeRoh"] -and [bool]$tc.pruefeRoh) {
        $rawFindings = [AnonTool.AnonEngine]::AuditText([string]$tc.eingabe, "$($tc.id).txt", $cfg)
        Assert-True ($rawFindings.Count -gt 0) "$($tc.id): Prüfmodus meldet die Lücke in den Rohdaten ($($rawFindings.Count) Treffer)"
        if ($null -ne $tc.PSObject.Properties["pruefeRohKategorie"]) {
            $rohKat = [string]$tc.pruefeRohKategorie
            Assert-True (@($rawFindings | Where-Object { $_.Kategorie -eq $rohKat }).Count -gt 0) "$($tc.id): Prüfmodus meldet in den Rohdaten die Kategorie $rohKat"
        }
    }

    if ($null -ne $tc.PSObject.Properties["jsonValid"] -and [bool]$tc.jsonValid) {
        $validJson = $false
        try {
            $null = ConvertFrom-Json -InputObject $actual -ErrorAction Stop
            $validJson = $true
        } catch {}
        Assert-True $validJson "$($tc.id): JSON-Struktur nach Anonymisierung gültig"
    }

    if ($null -ne $tc.PSObject.Properties["pruefeRueck"] -and [bool]$tc.pruefeRueck) {
        $restored = [AnonTool.AnonEngine]::DeanonymizeText($actual, $st.Reverse)
        Assert-True ($restored -ceq [string]$tc.eingabe) "$($tc.id) (LF): Rückübersetzung exakt wie Original"
        $restoredCrlf = [AnonTool.AnonEngine]::DeanonymizeText($actualCrlf, $stCrlf.Reverse)
        Assert-True ($restoredCrlf -ceq $crlfIn) "$($tc.id) (CRLF): Rückübersetzung exakt wie CRLF-Original"
    }
}

Write-Host "=== 3. Prüfe End-to-End CLI-Lauf (Ordner, Referenzvergleich A == B auf LF & CRLF) ===" -ForegroundColor Cyan
$tempRunRoot = Join-Path $testDir "_tmp_testlauf"
if (Test-Path -LiteralPath $tempRunRoot) { Remove-Item -LiteralPath $tempRunRoot -Recurse -Force }
$outDir = Join-Path $tempRunRoot "ausgabe"
$tabDir = Join-Path $tempRunRoot "tabellen"
$tabFile = Join-Path $tabDir "test-tabelle.json"
$secPass = ConvertTo-SecureString "TestPasswort123!" -AsPlainText -Force
# Arbeitsordner und Standardtabellen des Testlaufs in einen eigenen LOCALAPPDATA-Ordner legen
$origLocalAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $tempRunRoot "localappdata"
$arbeitRoot = Join-Path (Join-Path $env:LOCALAPPDATA "Anon") "arbeit"

& $anonScript -Eingabe $beispieleDir -Ausgabe $outDir -Regeln $rulesPath -TabellenPfad $tabFile -PasswortSecure $secPass > $null
Assert-True ($LASTEXITCODE -eq 0) "End-to-End CLI-Lauf auf sauberen Beispieldateien liefert Exit-Code 0"

Assert-True (Test-Path -LiteralPath (Join-Path $outDir "anonym")) "<Ausgabe>\anonym\ wurde erstellt"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $outDir "_arbeit"))) "Kein Arbeitsordner im Ausgabeordner"
Assert-True ((Test-Path -LiteralPath $arbeitRoot) -and (@(Get-ChildItem -LiteralPath $arbeitRoot -Directory).Count -eq 0)) "Arbeitsordner unter LOCALAPPDATA\Anon\arbeit wurde nach dem Lauf gelöscht"
Assert-True (Test-Path -LiteralPath (Join-Path $outDir "bericht.json")) "<Ausgabe>\bericht.json wurde erstellt"
Assert-True (Test-Path -LiteralPath $tabFile) "Zuordnungstabelle wurde außerhalb von <Ausgabe> gespeichert"

# Vergleiche die von anon.ps1 erzeugten Dateien Byte-für-Byte mit tests\erwartet\ (aus der HTML/JS-Engine)
$expFiles = Get-ChildItem -LiteralPath $erwartetDir -File
foreach ($ef in $expFiles) {
    $psAnonFile = Join-Path (Join-Path $outDir "anonym") $ef.Name
    Assert-True (Test-Path -LiteralPath $psAnonFile) "Anonymisierte Datei $($ef.Name) existiert"
    $psText = [System.IO.File]::ReadAllText($psAnonFile, [System.Text.Encoding]::UTF8)
    $expText = [System.IO.File]::ReadAllText($ef.FullName, [System.Text.Encoding]::UTF8)
    Assert-True ($psText -ceq $expText) "Parität A == B (LF): 100 % identische Ausgabe für $($ef.Name)"
}

# Paritätstest A == B auch für CRLF auf allen Beispieldateien
$crlfBeispieleDir = Join-Path $tempRunRoot "beispiele_crlf"
$crlfOutDir = Join-Path $tempRunRoot "ausgabe_crlf"
$crlfTabFile = Join-Path $tabDir "test-tabelle-crlf.json"
[void](New-Item -ItemType Directory -Path $crlfBeispieleDir -Force)
foreach ($ef in $expFiles) {
    $srcPath = Join-Path $beispieleDir $ef.Name
    $rawLf = [System.IO.File]::ReadAllText($srcPath, [System.Text.Encoding]::UTF8)
    $rawCrlf = $rawLf -replace "\r?\n", "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $crlfBeispieleDir $ef.Name), $rawCrlf, (New-Object System.Text.UTF8Encoding($false)))
}
& $anonScript -Eingabe $crlfBeispieleDir -Ausgabe $crlfOutDir -Regeln $rulesPath -TabellenPfad $crlfTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "CRLF-Mehrdateienlauf liefert Exit-Code 0"
foreach ($ef in $expFiles) {
    $psCrlfFile = Join-Path (Join-Path $crlfOutDir "anonym") $ef.Name
    $psCrlfText = [System.IO.File]::ReadAllText($psCrlfFile, [System.Text.Encoding]::UTF8)
    $expCrlfText = ([System.IO.File]::ReadAllText($ef.FullName, [System.Text.Encoding]::UTF8)) -replace "\r?\n", "`r`n"
    Assert-True ($psCrlfText -ceq $expCrlfText) "Parität A == B (CRLF): 100 % identische CRLF-Ausgabe für $($ef.Name)"
}

Write-Host "=== 4. Explizite Tests für alle 11 Code-Review-Befunde ===" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# Befund 1: CRLF Gegenprobe in .NET
# ----------------------------------------------------------------------------
$probePattern = '(?im)^([ \t]*description[ \t]+)([^\r\n]+)(?=\r?$)'
Assert-True ([regex]::IsMatch("description Test`r`nx", $probePattern)) "Befund 1 Gegenprobe: [regex]::IsMatch('description Test`r`nx', '(?im)^([ \t]*description[ \t]+)([^\r\n]+)(?=\r?$)') liefert True"

# ----------------------------------------------------------------------------
# Befund 2: Dateinamen & Pfade anonymisieren und prüfen
# ----------------------------------------------------------------------------
$pathCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
$pathState = New-Object AnonTool.AnonState
$origRelPath = "Rechenzentrum-Nord/dc1-sw-core01/show-tech-acc-halle2-01_192.0.2.1.txt"
$anonRelPath = [AnonTool.AnonEngine]::ProcessPath($origRelPath, $pathCfg, $pathState)
Assert-True ($anonRelPath -ceq "FIRMA-1/CORE-A/show-tech-HOST-1_NET-1.H1.txt") "Befund 2: ProcessPath anonymisiert jeden Pfadbestandteil ($anonRelPath)"

$cleanPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $anonRelPath, $pathCfg)
Assert-True ($cleanPathAudit.Count -eq 0) "Befund 2: Anonymisierter Dateipfad ist in AuditText SAUBER"

$dirtyPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $origRelPath, $pathCfg)
Assert-True ($dirtyPathAudit.Count -ge 3) "Befund 2: Nicht anonymisierter Dateipfad wird in AuditText als Restfund gemeldet ($($dirtyPathAudit.Count) Treffer)"

# End-to-End Dateinamen-Test inkl. Binärdatei-Name im Bericht
$pathInDir = Join-Path $tempRunRoot "pfad_in"
$pathOutDir = Join-Path $tempRunRoot "pfad_out"
$pathTabFile = Join-Path $tabDir "pfad-tab.json"
[void](New-Item -ItemType Directory -Path $pathInDir -Force)
[System.IO.File]::WriteAllText((Join-Path $pathInDir "show-tech-dc1-sw-core01_192.0.2.1.txt"), "hostname dc1-sw-core01`r`n", [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllBytes((Join-Path $pathInDir "firmware-dc1-sw-core01.bin"), [byte[]]@(0, 1, 2, 0, 255, 0, 42))
& $anonScript -Eingabe $pathInDir -Ausgabe $pathOutDir -Regeln $rulesPath -TabellenPfad $pathTabFile -Unverschluesselt > $null
Assert-True (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-CORE-A_NET-1.H1.txt")) "Befund 2: Ausgabedatei in anonym\ trägt anonymisierten Namen (show-tech-CORE-A_NET-1.H1.txt)"
Assert-True (-not (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-dc1-sw-core01_192.0.2.1.txt"))) "Befund 2: Originaldateiname mit Hostname existiert NICHT in anonym\"
$pathBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $pathOutDir "bericht.json"), [System.Text.Encoding]::UTF8))
Assert-True ($pathBericht.uebersprungeneBinaer[0] -ceq "firmware-CORE-A.bin") "Befund 2: Auch uebersprungeneBinaer im Bericht nutzt anonymisierten Pfad ($($pathBericht.uebersprungeneBinaer[0]))"

# ----------------------------------------------------------------------------
# Befund 3: Zeichenkodierung (UTF-16-LE BOM, UTF-16-BE BOM, UTF-8 BOM -> UTF-8 ohne BOM)
# ----------------------------------------------------------------------------
$bomInDir = Join-Path $tempRunRoot "bom_in"
$bomOutDir = Join-Path $tempRunRoot "bom_out"
$bomTabFile = Join-Path $tabDir "bom-tab.json"
[void](New-Item -ItemType Directory -Path $bomInDir -Force)
$evText = "EventID=4624 IpAddress=203.0.113.60 ClientMAC=00:1a:2b:3c:4d:5e`r`n"
# Schreibe UTF-16 LE mit BOM, UTF-16 BE mit BOM und UTF-8 mit BOM
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16le.log"), $evText, [System.Text.Encoding]::Unicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16be.log"), $evText, [System.Text.Encoding]::BigEndianUnicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf8bom.log"), $evText, (New-Object System.Text.UTF8Encoding($true)))

& $anonScript -Eingabe $bomInDir -Ausgabe $bomOutDir -Regeln $rulesPath -TabellenPfad $bomTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "Befund 3: BOM-Dateien (UTF-16 LE/BE, UTF-8-BOM) verarbeitet und SAUBER (Exit-Code 0)"
foreach ($bFile in @("ev-utf16le.log", "ev-utf16be.log", "ev-utf8bom.log")) {
    $outPath = Join-Path (Join-Path $bomOutDir "anonym") $bFile
    $outBytes = [System.IO.File]::ReadAllBytes($outPath)
    $hasBom = ($outBytes.Length -ge 2 -and (($outBytes[0] -eq 0xFF -and $outBytes[1] -eq 0xFE) -or ($outBytes[0] -eq 0xFE -and $outBytes[1] -eq 0xFF))) -or
              ($outBytes.Length -ge 3 -and $outBytes[0] -eq 0xEF -and $outBytes[1] -eq 0xBB -and $outBytes[2] -eq 0xBF)
    Assert-True (-not $hasBom) "Befund 3: Ausgabe von $bFile ist UTF-8 ohne BOM"
    $outContent = [System.Text.Encoding]::UTF8.GetString($outBytes).Trim()
    Assert-True ($outContent -ceq "EventID=4624 IpAddress=NET-1.H1 ClientMAC=MAC-1") "Befund 3: IPs und MACs in $bFile erkannt und ersetzt ($outContent)"
}

# ----------------------------------------------------------------------------
# Befund 4: ANON-AES256-2 Tabellenverschlüsselung + 6 Pflicht-Negativtests + ANON-AES256-1 Upgrade
# ----------------------------------------------------------------------------
$tabHeaderObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
Assert-True ($tabHeaderObj.format -eq "ANON-AES256-2") "Befund 4: Tabellenformat ist ANON-AES256-2"
$expKdf = if ([AnonTool.AnonCrypto]::Sha256KdfAvailable()) { "PBKDF2-SHA256" } else { "PBKDF2-SHA1" }
Assert-True ($tabHeaderObj.kdf -eq $expKdf) "Befund 4: Tabellenkopf kdf ist $expKdf (SHA256 ab .NET 4.7.2)"
Assert-True ([int]$tabHeaderObj.iterations -eq 600000) "Befund 4: PBKDF2 Iterationszahl im Tabellenkopf ist 600.000 ($($tabHeaderObj.iterations))"

$kiAntwortPfad = Join-Path $tempRunRoot "ki-antwort.txt"
$kiRueckPfad = Join-Path $tempRunRoot "ki-rueck.txt"
[System.IO.File]::WriteAllText($kiAntwortPfad, "Bitte prüfen Sie auf CORE-A das Interface zu CORE-B mit IP NET-1.H2/24 und MAC MAC-1.", [System.Text.Encoding]::UTF8)
& $anonScript -Zurueck -Eingabe $kiAntwortPfad -Ausgabe $kiRueckPfad -TabellenPfad $tabFile -PasswortSecure $secPass > $null
$rueckText = [System.IO.File]::ReadAllText($kiRueckPfad, [System.Text.Encoding]::UTF8)
Assert-True ($rueckText.Contains("dc1-sw-core01") -and $rueckText.Contains("dc2-sw-core02") -and $rueckText.Contains("192.0.2.1/24") -and $rueckText.Contains("00:1a:2b:3c:4d:5e")) "Befund 4: Rückübersetzung (-Zurueck) mit ANON-AES256-2 erfolgreich"

# 6 Pflicht-Negativtests gegen ANON-AES256-2
$tamperDir = Join-Path $tempRunRoot "tamper"
[void](New-Item -ItemType Directory -Path $tamperDir -Force)

# 4a. leeres hmac
$t1 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$t1.hmac = ""
$t1Path = Join-Path $tamperDir "t1-empty-hmac.json"
[System.IO.File]::WriteAllText($t1Path, ($t1 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t1Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 1: Leeres 'hmac' MUSS fehlschlagen"

# 4b. verkürztes hmac (16 Byte statt 32 Byte)
$t2 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$fullMacBytes = [Convert]::FromBase64String([string]$t2.hmac)
$shortMacBytes = New-Object byte[] 16
[System.Buffer]::BlockCopy($fullMacBytes, 0, $shortMacBytes, 0, 16)
$t2.hmac = [Convert]::ToBase64String($shortMacBytes)
$t2Path = Join-Path $tamperDir "t2-short-hmac.json"
[System.IO.File]::WriteAllText($t2Path, ($t2 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t2Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 2: Verkürztes 'hmac' MUSS fehlschlagen"

# 4c. verändertes IV
$t3 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$ivBytes = [Convert]::FromBase64String([string]$t3.iv)
$ivBytes[0] = $ivBytes[0] -bxor 1
$t3.iv = [Convert]::ToBase64String($ivBytes)
$t3Path = Join-Path $tamperDir "t3-bad-iv.json"
[System.IO.File]::WriteAllText($t3Path, ($t3 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t3Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 3: Verändertes IV MUSS fehlschlagen"

# 4d. verändertes Salt
$t4 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$saltBytes = [Convert]::FromBase64String([string]$t4.salt)
$saltBytes[0] = $saltBytes[0] -bxor 1
$t4.salt = [Convert]::ToBase64String($saltBytes)
$t4Path = Join-Path $tamperDir "t4-bad-salt.json"
[System.IO.File]::WriteAllText($t4Path, ($t4 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t4Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 4: Verändertes Salt MUSS fehlschlagen"

# 4e. verändertes iterations-Feld
$t5 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$t5.iterations = 600001
$t5Path = Join-Path $tamperDir "t5-bad-iter.json"
[System.IO.File]::WriteAllText($t5Path, ($t5 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t5Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 5: Verändertes iterations-Feld MUSS fehlschlagen"

# 4f. falsches Passwort
$wrongPass = ConvertTo-SecureString "FalschesPasswort99!" -AsPlainText -Force
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $tabFile -PasswortSecure $wrongPass > $null 2>&1 } "Befund 4 Negativtest 6: Falsches Passwort MUSS fehlschlagen"

# 4g. ANON-AES256-1 bleibt ladbar mit Warnung und wird beim Speichern auf ANON-AES256-2 gehoben
$legacySalt = New-Object byte[] 16
$legacyIv = New-Object byte[] 16
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($legacySalt)
$rng.GetBytes($legacyIv)
$legacyKdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes("AltPasswort99!", $legacySalt, 100000)
$legacyKey = $legacyKdf.GetBytes(32)
$legacyAes = [System.Security.Cryptography.Aes]::Create()
$legacyAes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$legacyAes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$legacyAes.Key = $legacyKey
$legacyAes.IV = $legacyIv
$legacyPlain = '{"version":"1.0","vorwaerts":{"fixed|dc1-sw-core01":"CORE-A"},"rueckwaerts":{"CORE-A":"dc1-sw-core01"},"zaehler":{},"netzHosts":{}}'
$legacyPlainBytes = [System.Text.Encoding]::UTF8.GetBytes($legacyPlain)
$legacyCipher = $legacyAes.CreateEncryptor().TransformFinalBlock($legacyPlainBytes, 0, $legacyPlainBytes.Length)
$legacyHmac = (New-Object System.Security.Cryptography.HMACSHA256(,$legacyKey)).ComputeHash($legacyCipher)
$legacyWrapper = [ordered]@{
    format = "ANON-AES256-1"
    salt   = [Convert]::ToBase64String($legacySalt)
    iv     = [Convert]::ToBase64String($legacyIv)
    hmac   = [Convert]::ToBase64String($legacyHmac)
    daten  = [Convert]::ToBase64String($legacyCipher)
} | ConvertTo-Json -Depth 5
$legacyTabFile = Join-Path $tabDir "legacy-tabelle-100k.json"
[System.IO.File]::WriteAllText($legacyTabFile, $legacyWrapper, [System.Text.Encoding]::UTF8)
$legacyInFile = Join-Path $tempRunRoot "legacy-in.txt"
$legacyOutFile = Join-Path $tempRunRoot "legacy-out.txt"
[System.IO.File]::WriteAllText($legacyInFile, "Switch CORE-A ist aktiv.", [System.Text.Encoding]::UTF8)
$secLegacyPass = ConvertTo-SecureString "AltPasswort99!" -AsPlainText -Force
$warnStream = & $anonScript -Zurueck -Eingabe $legacyInFile -Ausgabe $legacyOutFile -TabellenPfad $legacyTabFile -PasswortSecure $secLegacyPass 3>&1
$warnText = ($warnStream | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join " "
$legacyRestored = [System.IO.File]::ReadAllText($legacyOutFile, [System.Text.Encoding]::UTF8)
Assert-True ($legacyRestored -ceq "Switch dc1-sw-core01 ist aktiv.") "Befund 4: ANON-AES256-1 (100.000 Iterationen ohne Kopf-Feld) bleibt ladbar"
Assert-True ($warnText.Contains("ANON-AES256-1")) "Befund 4: Laden von ANON-AES256-1 erzeugt Warnung ($warnText)"

# ----------------------------------------------------------------------------
# Befund 5: Keine stille Herabstufung beim Weiterverwenden + Upgrade von -1 auf -2 beim Speichern
# ----------------------------------------------------------------------------
$reuseOutDir = Join-Path $tempRunRoot "reuse_out"
# Lade die ANON-AES256-1 Tabelle über -Tabelle und führe einen Lauf durch (ohne -Unverschluesselt) -> muss verschlüsselt bleiben und auf ANON-AES256-2 gehoben werden!
$null = & $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Ausgabe $reuseOutDir -Regeln $rulesPath -Tabelle $legacyTabFile -PasswortSecure $secLegacyPass 3>&1 > $null
$upgradedTabObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($legacyTabFile, [System.Text.Encoding]::UTF8))
Assert-True ($upgradedTabObj.format -eq "ANON-AES256-2") "Befund 4 & 5: Beim Weiterverwenden bleibt Tabelle verschlüsselt (keine stille Herabstufung) und wird von ANON-AES256-1 auf ANON-AES256-2 gehoben"

# ----------------------------------------------------------------------------
# Befund 6: Exit-Code 2 im Hauptlauf bei Restfunden
# ----------------------------------------------------------------------------
$dirtyOutDir = Join-Path $tempRunRoot "dirty_out"
$dirtyTabFile = Join-Path $tabDir "dirty-tab.json"
& $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Ausgabe $dirtyOutDir -Regeln $rulesPath -TabellenPfad $dirtyTabFile -Unverschluesselt -Kategorien "geheimnisseEntfernen" > $null
Assert-True ($LASTEXITCODE -eq 2) "Befund 6: Hauptlauf mit Restfunden (pruefTrefferAnzahl > 0) liefert Exit-Code 2 (erhalten: $LASTEXITCODE)"

# ----------------------------------------------------------------------------
# Befund 7: Set-StrictMode -Version Latest mit minimaler Regeldatei (ohne optionen, ausnahmen, pruefung)
# ----------------------------------------------------------------------------
$minRulesPath = Join-Path $tempRunRoot "min-regeln.json"
$minRulesContent = '{"eigeneBegriffe":{"festeZuordnung":{"dc1-sw-core01":"MIN-CORE-1"}}}'
[System.IO.File]::WriteAllText($minRulesPath, $minRulesContent, [System.Text.Encoding]::UTF8)
$minInFile = Join-Path $tempRunRoot "min-in.txt"
[System.IO.File]::WriteAllText($minInFile, "hostname dc1-sw-core01`r`nip address 198.51.100.3/24`r`n", [System.Text.Encoding]::UTF8)
$minOutDir = Join-Path $tempRunRoot "min_out"
$minTabFile = Join-Path $tabDir "min-tab.json"
& $anonScript -Eingabe $minInFile -Ausgabe $minOutDir -Regeln $minRulesPath -TabellenPfad $minTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "Befund 7: Minimale Regeldatei ohne optionen, ausnahmen und pruefung läuft unter Set-StrictMode -Version Latest fehlerfrei"
$minResultText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $minOutDir "anonym") "min-in.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($minResultText.Contains("MIN-CORE-1") -and $minResultText.Contains("NET-1.H1/24")) "Befund 7: Minimale Regeldatei ersetzt festeZuordnung und Standard-Kategorien korrekt"

# ----------------------------------------------------------------------------
# Befund 8: Wort-/Namensgrenzen bei festeZuordnung und firmenUndStandorte
# ----------------------------------------------------------------------------
$bState = New-Object AnonTool.AnonState
$bOut = [AnonTool.AnonEngine]::ProcessText("dc1-tor-01 und dc1-tor-010", $pathCfg, $bState)
Assert-True ($bOut -ceq "TOR-A und dc1-tor-010" -and (-not $bOut.Contains("TOR-A0"))) "Befund 8: Wort-/Namensgrenzen verhindern Teilwort-Ersetzung ('dc1-tor-010' -> 'HOST-1' statt 'TOR-A0')"

# ----------------------------------------------------------------------------
# Befund 9: Add-Type sauber nach PSEdition verzweigt ohne stillen Catch-Fallback
# ----------------------------------------------------------------------------
$ps1Raw = [System.IO.File]::ReadAllText($anonScript, [System.Text.Encoding]::UTF8)
Assert-True ($ps1Raw.Contains('$PSVersionTable.PSEdition -eq "Desktop"') -and ($ps1Raw -notmatch '(?s)try\s*\{\s*Add-Type.*?\}\s*catch\s*\{\s*Add-Type')) "Befund 9: Add-Type verzweigt sauber nach PSEdition ohne stillen Catch-Fallback"

# ----------------------------------------------------------------------------
# Befund 10: Mindestlänge 12 Zeichen für Passwörter erzwingen
# ----------------------------------------------------------------------------
$shortPass = ConvertTo-SecureString "Kurz1234567" -AsPlainText -Force # 11 Zeichen
$shortTabFile = Join-Path $tabDir "short-pass-tab.json"
$shortOutDir = Join-Path $tempRunRoot "short_out"
Assert-Throws {
    & $anonScript -Eingabe $minInFile -Ausgabe $shortOutDir -Regeln $rulesPath -TabellenPfad $shortTabFile -PasswortSecure $shortPass > $null 2>&1
} "Befund 10: Passwort unter 12 Zeichen (11 Zeichen) wird abgelehnt"

# ----------------------------------------------------------------------------
# Befund 11: Regex-Timeout (5 Sekunden) auf allen Regex-Instanzen in A
# ----------------------------------------------------------------------------
Assert-True ([AnonTool.AnonEngine]::RxTimeout.TotalSeconds -eq 5) "Befund 11: Statisches RxTimeout in AnonEngine beträgt 5 Sekunden"
$allRulesHaveTimeout = $true
foreach ($r in $pathCfg.GeheimnisMuster) { if ($r.Compiled.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
foreach ($r in $pathCfg.FreitextMuster) { if ($r.Compiled.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
foreach ($r in $pathCfg.HostnamenMuster) { if ($r.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
Assert-True $allRulesHaveTimeout "Befund 11: Alle kompilierten Regel-Regex-Instanzen haben 5 Sekunden MatchTimeout"

# Prüfe Sicherheitsabbruch, wenn -TabellenPfad im Ausgabeordner liegt
$unsafeTab = Join-Path $outDir "geheim.json"
Assert-Throws {
    & $anonScript -Eingabe $beispieleDir -Ausgabe $outDir -TabellenPfad $unsafeTab -Unverschluesselt > $null 2>&1
} "Sicherheitsprüfung verhindert Speichern der Zuordnungstabelle im Ausgabeordner"

# Prüfe Archiv-Entpackung (.zip) und Binärdatei-Überspringen
$archInputDir = Join-Path $tempRunRoot "arch_in"
[void](New-Item -ItemType Directory -Path $archInputDir -Force)
Copy-Item -LiteralPath (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Destination (Join-Path $archInputDir "config.txt")
[System.IO.File]::WriteAllBytes((Join-Path $archInputDir "firmware.bin"), [byte[]]@(0, 1, 2, 0, 255, 0, 42, 0, 99))
$zipPath = Join-Path $tempRunRoot "showtech.zip"
[System.IO.Compression.ZipFile]::CreateFromDirectory($archInputDir, $zipPath)

$zipOutDir = Join-Path $tempRunRoot "zip_out"
& $anonScript -Eingabe $zipPath -Ausgabe $zipOutDir -Regeln $rulesPath -TabellenPfad $tabFile -PasswortSecure $secPass > $null
$zipBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $zipOutDir "bericht.json"), [System.Text.Encoding]::UTF8))
Assert-True ($zipBericht.verarbeiteteDateien -eq 1) "ZIP-Archiv entpackt und 1 Textdatei verarbeitet"
Assert-True ($zipBericht.uebersprungeneBinaer.Count -eq 1) "Binärdatei im ZIP erkannt und im Bericht als übersprungen gemeldet"
Assert-True ($zipBericht.pruefergebnis -eq "SAUBER") "ZIP-Ausgabe ist SAUBER"

Write-Host "=== 5. Performance- & Stresstest: Großer Aruba AOS-CX Show-Tech (40.000+ Zeilen) ===" -ForegroundColor Cyan
$sb = New-Object System.Text.StringBuilder (4 * 1024 * 1024)
[void]$sb.AppendLine("================================f=show tech====================================")
[void]$sb.AppendLine("hostname dc1-sw-core01")
[void]$sb.AppendLine("Version : FL.10.13.1020")
[void]$sb.AppendLine("snmp-server system-location Rechenzentrum-Nord Halle 3")
[void]$sb.AppendLine("snmp-server system-contact Max Mustermann (netze@intern.example.invalid)")
[void]$sb.AppendLine("user admin password ciphertext AQBapf92384719283749182374918273948172938471928374")
for ($i = 1; $i -le 5000; $i++) {
    $vId = ($i % 400) + 10
    $o4 = ($i % 250) + 1
    $hex = ($i -band 0xFF).ToString("x2")
    $port = ($i % 48) + 1
    $dist = ($i % 30) + 1
    $acc = ($i % 80) + 1
    $net = @("192.0.2", "198.51.100", "203.0.113")[$i % 3]
    [void]$sb.AppendLine("vlan $vId")
    [void]$sb.AppendLine("    name KD_${vId}_${net}.0-24")
    [void]$sb.AppendLine("interface 1/1/$port")
    [void]$sb.AppendLine("    description Uplink_$i zu dist-sw$dist (Musterfirma GmbH)")
    [void]$sb.AppendLine("    ip address ${net}.${o4}/24")
    [void]$sb.AppendLine("1/1/$port  acc-sw$acc  00:1a:2b:3c:4d:$hex  ${net}.254  Aruba JL658A  FL.10.13.1020")
    [void]$sb.AppendLine("2026-10-16T14:22:15.123Z dc1-sw-core01 hpe-routing[$i]: Event on sn link state up for ${net}.${o4}")
}
$largeShowTech = $sb.ToString()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$perfCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
$perfState = New-Object AnonTool.AnonState
$largeAnon = [AnonTool.AnonEngine]::ProcessText($largeShowTech, $perfCfg, $perfState)
$largeFindings = [AnonTool.AnonEngine]::AuditText($largeAnon, "aruba-show-tech-large.txt", $perfCfg)
$sw.Stop()
Write-Host ("  Großer Show-Tech ({0:N2} MB) verarbeitet + geprüft in {1} ms" -f ($largeShowTech.Length / 1MB), $sw.ElapsedMilliseconds) -ForegroundColor Gray
Assert-True ($sw.ElapsedMilliseconds -lt 8000) "Performance-Ziel erreicht: $($sw.ElapsedMilliseconds) ms (< 8000 ms)"
Assert-True ($largeFindings.Count -eq 0) "Großer Aruba Show-Tech ist nach Anonymisierung SAUBER (0 Restfunde)"
Assert-True (-not $largeAnon.Contains([string][char]2 + "PROT_")) "Alle Schutz-Marker vollständig aufgelöst"

Write-Host "`n=== 7. Prüfe Code-Review Commit 65cd5d4 (Befund 1; Befunde 2-3 betrafen den Sammler, eigenes Projekt) ===" -ForegroundColor Cyan

# 7.1 Befund 1: Freitext-Leck bei geschützten Wörtern im Body (LF + CRLF, inkl. Alle-freitextMuster-Schleife)
$freitextSamplesByRule = @{
    "Mehrzeilige oder einzeilige Banner (banner/header motd, exec, login, shell, incoming)" = "banner motd ^Kunde Mustermann Ethernet1/1/1^"
    "SNMP Location & System-Location (CLI)"                                                 = "snmp-server system-location Kunde Mustermann Ethernet1/1/1"
    "SNMP Contact & System-Contact (CLI)"                                                   = "snmp-server system-contact Kunde Mustermann Ethernet1/1/1"
    "Interface Description / Alias (CLI)"                                                   = " description Kunde Mustermann Ethernet1/1/1"
    "VLAN-Namen (CLI)"                                                                      = " name Kunde Mustermann Ethernet1/1/1"
    "VLAN-/Objektnamen (JSON)"                                                              = '"vlan_name": "Kunde Mustermann Ethernet1/1/1"'
    "SONiC / JSON Description, Alias, Location, Contact"                                    = '"description": "Kunde Mustermann Ethernet1/1/1"'
    "LLDP / CDP System Description & Port Description"                                      = "System Description : Kunde Mustermann Ethernet1/1/1"
    "MikroTik comment= (in Anführungszeichen, inkl. Leerzeichen und mehrzeiliger \-Fortsetzung)" = 'set [ find default-name=ether1 ] comment="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik comment= (ohne Anführungszeichen)"                                            = "set [ find default-name=ether1 ] comment=Kunde Mustermann Ethernet1/1/1"
    "MikroTik SNMP Location (location=)"                                                    = '/snmp set location="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik SNMP Contact (contact=)"                                                      = '/snmp set contact="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik Interface-/VLAN-/Bridge-Namen (name= und interface= konsistent)"              = '/interface vlan add interface=bridge1 name="Kunde Mustermann Ethernet1/1/1" vlan-id=10'
}
Assert-Equal $rulesObj.freitextMuster.Count $freitextSamplesByRule.Count "Alle $($rulesObj.freitextMuster.Count) freitextMuster-Regeln sind im Mustermann+Ethernet1/1/1-Test abgedeckt"

foreach ($eol in @("`n", "`r`n")) {
    $eolName = if ($eol -eq "`r`n") { "CRLF" } else { "LF" }
    $ftState = New-Object AnonTool.AnonState
    $ftCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    $ftLines = @(
        "interface 1/1/10",
        " description Uplink Praxis Dr Weber Ethernet1/1/10",
        "snmp-server system-location Praxis Weber München Ethernet1/1/2",
        'set [ find default-name=ether1 ] comment="Kunde Weber Gi1/0/1"',
        "vlan 20",
        " name Praxis_Weber_FL.10.13.1020",
        "System Description : Switch bei Weber FL.10.13.1020",
        "System Description : ArubaOS-CX FL.10.13.1020"
    )
    $ftInput = $ftLines -join $eol
    $ftOut = [AnonTool.AnonEngine]::ProcessText($ftInput, $ftCfg, $ftState)

    Assert-True ($ftOut.Contains(" description TEXT-1") -and -not $ftOut.Contains("Weber") -and -not $ftOut.Contains("Ethernet1/1/10")) "Befund 1 ($eolName): description mit Personenname + Portname (Ethernet1/1/10) wird komplett ersetzt"
    Assert-True ($ftOut.Contains("snmp-server system-location ORT-1") -and -not $ftOut.Contains("München") -and -not $ftOut.Contains("Ethernet1/1/2")) "Befund 1 ($eolName): snmp-server system-location mit Ort + Portname wird komplett ersetzt"
    Assert-True ($ftOut.Contains('comment="TEXT-4"') -and -not $ftOut.Contains("Gi1/0/1")) "Befund 1 ($eolName): MikroTik comment=""... Gi1/0/1"" wird komplett ersetzt"
    Assert-True ($ftOut.Contains(" name TEXT-2")) "Befund 1 ($eolName): VLAN-name mit Name + Versionsnummer (FL.10.13.1020) wird komplett ersetzt"
    Assert-True ($ftOut.Contains("System Description : TEXT-3") -and -not $ftOut.Contains("Switch bei Weber")) "Befund 1 ($eolName): System Description 'Switch bei Weber FL.10.13.1020' wird komplett ersetzt"
    Assert-True ($ftOut.Contains("System Description : ArubaOS-CX FL.10.13.1020")) "Befund 1 Positivtest ($eolName): System Description 'ArubaOS-CX FL.10.13.1020' (nur Produkt + Version) bleibt erhalten"

    # Schleife über ALLE freitextMuster: Body "Kunde Mustermann Ethernet1/1/1" muss bei jedem Muster ersetzt werden
    foreach ($fRule in $rulesObj.freitextMuster) {
        $rName = [string]$fRule.name
        $sampleLine = $freitextSamplesByRule[$rName]
        Assert-True (-not [string]::IsNullOrEmpty($sampleLine)) "Testzeile für freitextMuster '$rName' vorhanden"

        $singleRegeln = ($rawRules | ConvertFrom-Json)
        $singleRegeln.freitextMuster = @($fRule)
        $singleCfg = New-TestConfig -RulesObj $singleRegeln -Netzerhaltend $true
        $singleState = New-Object AnonTool.AnonState
        $singleInput = $sampleLine + $eol + "next-line"
        $singleOut = [AnonTool.AnonEngine]::ProcessText($singleInput, $singleCfg, $singleState)
        $expectedCat = if ([string]::IsNullOrWhiteSpace($fRule.kategorie)) { "TEXT" } else { [string]$fRule.kategorie }
        $expectedPh = "$expectedCat-1"
        Assert-True ($singleOut.Contains($expectedPh) -and -not $singleOut.Contains("Mustermann") -and -not $singleOut.Contains("Kunde") -and -not $singleOut.Contains("Ethernet1/1/1")) "Befund 1 Alle-Muster-Test ($eolName) [$rName]: 'Kunde Mustermann Ethernet1/1/1' wird durch $expectedPh ersetzt"
    }
}

# 7.4 Statische Prüfung für anonymisierer.html (keine Verwendung von localStorage/sessionStorage/indexedDB)
$htmlRawContent = [System.IO.File]::ReadAllText((Join-Path (Join-Path $rootDir "web") "anonymisierer.html"), [System.Text.Encoding]::UTF8)
Assert-True (-not [regex]::IsMatch($htmlRawContent, '(?i)\b(?:localStorage|sessionStorage|indexedDB)\b')) "Statischer Check (PowerShell): anonymisierer.html enthält kein localStorage, sessionStorage oder indexedDB"

Write-Host "=== 8. Prüfe editierbare Zuordnungstabelle & anon-regeln.lokal.json (ausnahmen.exakteWoerter) ===" -ForegroundColor Cyan
# 8.1 anon.ps1 mit -LokaleRegeln (festeZuordnung + ausnahmen.exakteWoerter)
$lokalTestDir = Join-Path $tempRunRoot "lokal_test"
[void](New-Item -ItemType Directory -Path $lokalTestDir -Force)
$lokalRegelnDatei = Join-Path $lokalTestDir "anon-regeln.lokal.json"
$lokalEingabeDatei = Join-Path $lokalTestDir "eingabe.txt"
$lokalAusgabeOrdner = Join-Path $lokalTestDir "ausgabe"
$lokalTabelleDatei = Join-Path $lokalTestDir "tabelle.json"

$lokalJsonContent = @'
{
  "eigeneBegriffe": {
    "festeZuordnung": {
      "sw-core-lokal01": "CORE-LOKAL"
    }
  },
  "ausnahmen": {
    "exakteWoerter": [
      "Rechenzentrum-Nord Raum 2.04",
      "198.51.100.77"
    ]
  }
}
'@
[System.IO.File]::WriteAllText($lokalRegelnDatei, $lokalJsonContent, [System.Text.Encoding]::UTF8)

$lokalInputText = @"
hostname sw-core-lokal01
snmp-server location Rechenzentrum-Nord Raum 2.04
interface 1/1/1
   ip address 198.51.100.77/24
   description Uplink zu Server
"@
[System.IO.File]::WriteAllText($lokalEingabeDatei, $lokalInputText, [System.Text.Encoding]::UTF8)

& $anonScript -Eingabe $lokalEingabeDatei -Ausgabe $lokalAusgabeOrdner -Regeln $rulesPath -LokaleRegeln $lokalRegelnDatei -TabellenPfad $lokalTabelleDatei -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "anon.ps1 CLI mit -LokaleRegeln beendet mit Exit-Code 0"

$lokalOutFile = Join-Path (Join-Path $lokalAusgabeOrdner "anonym") "eingabe.txt"
Assert-True (Test-Path -LiteralPath $lokalOutFile) "Ausgabedatei wurde erzeugt"
$lokalOutText = [System.IO.File]::ReadAllText($lokalOutFile, [System.Text.Encoding]::UTF8)

Assert-True ($lokalOutText.Contains("hostname CORE-LOKAL")) "festeZuordnung aus -LokaleRegeln wird korrekt angewendet ('CORE-LOKAL')"
Assert-True ($lokalOutText.Contains("snmp-server location Rechenzentrum-Nord Raum 2.04")) "Freitext-Ausnahme aus ausnahmen.exakteWoerter bleibt im Klartext"
Assert-True ($lokalOutText.Contains("198.51.100.77")) "IP-Ausnahme aus ausnahmen.exakteWoerter bleibt im Klartext"

# Prüfmodus auf der Ausgabedatei über CLI (-Pruefen)
& $anonScript -Eingabe $lokalOutFile -Regeln $rulesPath -LokaleRegeln $lokalRegelnDatei -Pruefen > $null
Assert-Equal $LASTEXITCODE 0 "Prüfmodus: Ausgabedatei mit ausnahmen.exakteWoerter ist SAUBER (Exit-Code 0)"

# 8.1b Lokale Muster (eigeneHostnamenMuster, seriennummerMuster, tabellenSpalten) aus anon-regeln.lokal.json
$musterTestDir = Join-Path $tempRunRoot "lokal_muster"
[void](New-Item -ItemType Directory -Path $musterTestDir -Force)
$musterRegeln = Join-Path $musterTestDir "anon-regeln.lokal.json"
$musterEingabe = Join-Path $musterTestDir "eingabe.txt"
$musterAusgabe = Join-Path $musterTestDir "ausgabe"
$musterTabelle = Join-Path $musterTestDir "tabelle.json"
$musterJson = @'
{
  "eigeneHostnamenMuster": ["(?i)(?<![A-Za-z0-9-])(xy[0-9]-(?:sw|dist)[0-9]{2})(?![A-Za-z0-9-])"],
  "seriennummerMuster": ["(?i)((?<![A-Za-z0-9_])Inventar-Nr[ \\t]*:[ \\t]*)([A-Za-z0-9-]{5,24})()"],
  "tabellenSpalten": [{ "name": "Beispiel Nachbartabelle", "kopf": ["Nachbar", "Schnittstelle"], "spalten": [{ "name": "Nachbar", "kategorie": "HOST" }] }]
}
'@
[System.IO.File]::WriteAllText($musterRegeln, $musterJson, (New-Object System.Text.UTF8Encoding($false)))
$musterInput = "Peer XY1-SW03 is reachable`nuplink xy2-dist11 up, backup xy2-dist11_alt`nInventar-Nr: INV-0042-77`n`nNachbar        Schnittstelle`nnb-lager-ost   1/1/7`n"
$musterExpected = "Peer HOST-2 is reachable`nuplink HOST-3 up, backup HOST-3_alt`nInventar-Nr: SERIAL-1`n`nNachbar        Schnittstelle`nHOST-1         1/1/7`n"
[System.IO.File]::WriteAllText($musterEingabe, $musterInput, (New-Object System.Text.UTF8Encoding($false)))

& $anonScript -Eingabe $musterEingabe -Ausgabe $musterAusgabe -Regeln $rulesPath -LokaleRegeln $musterRegeln -TabellenPfad $musterTabelle -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "Lokale Muster: Ausgabe ist SAUBER (Exit-Code 0)"
$musterOut = [System.IO.File]::ReadAllText((Join-Path (Join-Path $musterAusgabe "anonym") "eingabe.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($musterOut -ceq $musterExpected) "Lokale Muster: eigeneHostnamenMuster, seriennummerMuster und tabellenSpalten greifen (PS1)"
& $anonScript -Eingabe $musterEingabe -Regeln $rulesPath -LokaleRegeln $musterRegeln -Pruefen > $null
Assert-Equal $LASTEXITCODE 2 "Lokale Muster: Prüfmodus beanstandet die Rohdaten (Exit-Code 2)"

# 8.2 Zuordnungstabelle: Aliase werden beim Export/Import beibehalten und für Rückübersetzung genutzt
$tabJson = [System.IO.File]::ReadAllText($lokalTabelleDatei, [System.Text.Encoding]::UTF8)
$tabObj = ConvertFrom-Json -InputObject $tabJson
Assert-True ($null -ne $tabObj.aliase) "Exportierte Tabelle enthält Feld 'aliase'"

# Ergänze einen Alias in der Tabelle für den CLI-Rückübersetzungstest
$tabObj.aliase | Add-Member -NotePropertyName "TEXT-23" -NotePropertyValue "VLAN-GAESTE"
$tabObj.rueckwaerts | Add-Member -NotePropertyName "VLAN-GAESTE" -NotePropertyValue "Uplink Praxis Dr Weber"
$tabObj.rueckwaerts | Add-Member -NotePropertyName "TEXT-23" -NotePropertyValue "Uplink Praxis Dr Weber"
[System.IO.File]::WriteAllText($lokalTabelleDatei, ($tabObj | ConvertTo-Json -Depth 8), [System.Text.Encoding]::UTF8)

# Rückübersetzung über CLI (-Zurueck)
$kiAntwortPfad = Join-Path $lokalTestDir "ki-antwort.txt"
$kiRueckPfad = Join-Path $lokalTestDir "ki-rueck.txt"
[System.IO.File]::WriteAllText($kiAntwortPfad, "Prüfe TEXT-23 und VLAN-GAESTE", [System.Text.Encoding]::UTF8)
& $anonScript -Zurueck -Eingabe $kiAntwortPfad -Ausgabe $kiRueckPfad -TabellenPfad $lokalTabelleDatei -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "Rückübersetzung mit Aliastabelle beendet mit Exit-Code 0"

$kiRueckText = [System.IO.File]::ReadAllText($kiRueckPfad, [System.Text.Encoding]::UTF8)
Assert-True ($kiRueckText.Trim() -eq "Prüfe Uplink Praxis Dr Weber und Uplink Praxis Dr Weber") "Rückübersetzung (-Zurueck) funktioniert sowohl für neuen Namen als auch für alten Alias 'TEXT-23'"

Write-Host "=== 9. Datenabfluss & Tabellenformate (Punkt 2) ===" -ForegroundColor Cyan
$p2Dir = Join-Path $tempRunRoot "punkt2"
[void](New-Item -ItemType Directory -Path $p2Dir -Force)
$p2In = Join-Path $p2Dir "eingabe"
[void](New-Item -ItemType Directory -Path $p2In -Force)
[System.IO.File]::WriteAllText((Join-Path $p2In "probe.txt"), "hostname edge7`nlink edge7-alt`nip 192.0.2.10`n", (New-Object System.Text.UTF8Encoding($false)))

# 9.1 Unbekannte Tabellenformate: Abbruch, Datei bleibt unverändert
$fremdeTabellen = [ordered]@{
    "unbekannt" = '{ "format": "ANON-UNBEKANNT-9", "daten": "AAAA" }'
    "webcrypto" = '{ "format": "ANON-WEBCRYPTO-AESGCM-1", "kdf": "PBKDF2-SHA256", "iterations": 600000, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "iv": "AAAAAAAAAAAAAAAA", "daten": "AAAA" }'
    "fremdjson" = '{ "irgendwas": 1 }'
    "kaputt"    = '{ kein json'
}
foreach ($name in $fremdeTabellen.Keys) {
    $tPfad = Join-Path $p2Dir "tabelle-$name.json"
    [System.IO.File]::WriteAllText($tPfad, $fremdeTabellen[$name], (New-Object System.Text.UTF8Encoding($false)))
    $vorher = [System.IO.File]::ReadAllText($tPfad)
    $meldung = ""
    try {
        & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-$name") -Regeln $rulesPath -TabellenPfad $tPfad -Unverschluesselt *> $null
    } catch { $meldung = $_.Exception.Message }
    Assert-True ($meldung -ne "") "Tabellenformat '$name': anon.ps1 bricht mit Fehler ab"
    Assert-True ([System.IO.File]::ReadAllText($tPfad) -ceq $vorher) "Tabellenformat '$name': Tabellendatei wurde nicht überschrieben"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path (Join-Path $p2Dir "aus-$name") (Join-Path "anonym" "probe.txt")))) "Tabellenformat '$name': keine Ausgabe geschrieben"
}

# 9.2 Obergrenze 5.000.000 Iterationen
$iterTab = Join-Path $p2Dir "tabelle-iter.json"
[System.IO.File]::WriteAllText($iterTab, '{ "format": "ANON-AES256-2", "kdf": "PBKDF2-SHA1", "iterations": 5000001, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "iv": "AAAAAAAAAAAAAAAAAAAAAA==", "hmac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "daten": "AAAAAAAAAAAAAAAAAAAAAA==" }', (New-Object System.Text.UTF8Encoding($false)))
$iterMeldung = ""
try {
    & $anonScript -Zurueck -Eingabe (Join-Path $p2In "probe.txt") -TabellenPfad $iterTab -PasswortSecure $secPass *> $null
} catch { $iterMeldung = $_.Exception.Message }
Assert-True ($iterMeldung -like "*5.000.000*") "Iterationszahl über 5.000.000 wird beim Laden abgelehnt"

# 9.3 Konsole: Prüftreffer nur mit Kategorie, Datei und Zeile, nie mit dem Wert
$konsole = (& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-konsole") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-konsole.json") -Unverschluesselt *>&1 | Out-String)
Assert-Equal $LASTEXITCODE 2 "Konsolentest: Restfund wird gemeldet (Exit-Code 2)"
Assert-True ($konsole.Contains("[Rest-Bekannt] probe.txt:2")) "Konsole nennt Kategorie, Datei und Zeile"
Assert-True (-not $konsole.Contains("edge7")) "Konsole enthält den gefundenen Wert nicht"
$konsolePruef = (& $anonScript -Pruefen -Eingabe $p2In -Regeln $rulesPath *>&1 | Out-String)
Assert-True ($konsolePruef.Contains("[Rest-IPv4] probe.txt:3") -and -not $konsolePruef.Contains("192.0.2.10") -and -not $konsolePruef.Contains("edge7")) "-Pruefen: Konsole ohne gefundene Werte"
$berichtText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-konsole") "bericht.json"))
Assert-True (-not $berichtText.Contains("edge7")) "bericht.json enthält den gefundenen Wert nicht"

# 9.4 Fehlermeldungen ohne Dateinamen
$fehlerMeldung = ""
try {
    & $anonScript -Eingabe (Join-Path $p2Dir "geheim-sw01_192.0.2.77.txt") -Ausgabe (Join-Path $p2Dir "aus-fehler") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-fehler.json") -Unverschluesselt *> $null
} catch { $fehlerMeldung = $_.Exception.Message }
Assert-True ($fehlerMeldung -like "*Nr. 1*" -and -not $fehlerMeldung.Contains("geheim-sw01") -and -not $fehlerMeldung.Contains("192.0.2.77")) "Fehlermeldung nennt nur die laufende Nummer, keinen Dateinamen ($fehlerMeldung)"
$fehlerPruef = ""
try { & $anonScript -Pruefen -Eingabe (Join-Path $p2Dir "geheim-sw01.txt") -Regeln $rulesPath *> $null } catch { $fehlerPruef = $_.Exception.Message }
Assert-True ($fehlerPruef -like "*Nr. 1*" -and -not $fehlerPruef.Contains("geheim-sw01")) "-Pruefen: Fehlermeldung ohne Dateinamen"
$sicherMeldung = ""
try {
    & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "kunde-x") -TabellenPfad (Join-Path (Join-Path $p2Dir "kunde-x") "tab.json") -Regeln $rulesPath -Unverschluesselt *> $null
} catch { $sicherMeldung = $_.Exception.Message }
Assert-True ($sicherMeldung -like "*SICHERHEITSFEHLER*" -and -not $sicherMeldung.Contains("kunde-x")) "Tabelle im Ausgabeordner: Fehlermeldung ohne Pfade"

# 9.5 -Netzerhaltend / -NichtNetzerhaltend als Schalter
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-nicht") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-nicht.json") -Unverschluesselt -NichtNetzerhaltend *> $null
$nichtText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-nicht") (Join-Path "anonym" "probe.txt")))
Assert-True ($nichtText.Contains("ip IP-PUB-1")) "-NichtNetzerhaltend: IP wird als IP-PUB-n ersetzt"
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-netz") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-netz.json") -Unverschluesselt -Netzerhaltend *> $null
$netzText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-netz") (Join-Path "anonym" "probe.txt")))
Assert-True ($netzText.Contains("ip NET-1.H1")) "-Netzerhaltend: IP wird als NET-n.Hm ersetzt"
Assert-Throws { & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-beide") -Regeln $rulesPath -Unverschluesselt -Netzerhaltend -NichtNetzerhaltend *> $null } "-Netzerhaltend und -NichtNetzerhaltend zusammen werden abgelehnt"
$paramInfo = (Get-Command $anonScript).Parameters
Assert-True ($paramInfo["Netzerhaltend"].ParameterType -eq [System.Management.Automation.SwitchParameter] -and $paramInfo["NichtNetzerhaltend"].ParameterType -eq [System.Management.Automation.SwitchParameter]) "-Netzerhaltend und -NichtNetzerhaltend sind Schalter (kein Nullable[bool])"

# 9.6 Verwaiste Arbeitsordner früherer Abbrüche werden beim Start entfernt
$verwaist = Join-Path $arbeitRoot "verwaist0001"
[void](New-Item -ItemType Directory -Path $verwaist -Force)
[System.IO.File]::WriteAllText((Join-Path $verwaist "reste.txt"), "hostname edge7")
(Get-Item -LiteralPath $verwaist).LastWriteTime = (Get-Date).AddDays(-2)
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-verwaist") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-verwaist.json") -Unverschluesselt *> $null
Assert-True (-not (Test-Path -LiteralPath $verwaist)) "Verwaister Arbeitsordner eines abgebrochenen Laufs wird beim nächsten Start gelöscht"

# 9.6b Rückübersetzung: Klartext nie unter anonym\ oder im Ausgabeordner eines Laufs, Standard <Basis>\klartext\
$laufOrdner = Join-Path $p2Dir "aus-konsole"
$kiDatei = Join-Path $p2Dir "ki.txt"
[System.IO.File]::WriteAllText($kiDatei, "Pruefe HOST-1 und NET-1.H1", (New-Object System.Text.UTF8Encoding($false)))
$konsoleTab = Join-Path $p2Dir "tab-konsole.json"
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiDatei -Ausgabe (Join-Path (Join-Path $laufOrdner "anonym") "rueck.txt") -TabellenPfad $konsoleTab *> $null } "-Zurueck: Ziel unterhalb von anonym\ wird abgelehnt"
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiDatei -Ausgabe (Join-Path $laufOrdner "rueck.txt") -TabellenPfad $konsoleTab *> $null } "-Zurueck: Ziel im Ausgabeordner eines Laufs (anonym\ + bericht.json) wird abgelehnt"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $laufOrdner "rueck.txt"))) "-Zurueck: im Ausgabeordner wurde nichts geschrieben"
$rueckKonsole = (& $anonScript -Zurueck -Eingabe $kiDatei -TabellenPfad $konsoleTab *>&1 | Out-String)
$klartextDir = Join-Path (Join-Path $env:LOCALAPPDATA "Anon") "klartext"
$klartextDateien = @(Get-ChildItem -LiteralPath $klartextDir -File -ErrorAction SilentlyContinue)
Assert-True ($klartextDateien.Count -eq 1) "-Zurueck ohne -Ausgabe: Klartext landet in <Basis>\klartext\"
Assert-True ($klartextDateien.Count -eq 1 -and [System.IO.File]::ReadAllText($klartextDateien[0].FullName).Contains("edge7")) "-Zurueck ohne -Ausgabe: Datei enthält den rückübersetzten Text"
Assert-True (-not $rueckKonsole.Contains("edge7")) "-Zurueck: Klartext erscheint nicht auf der Konsole"

# 9.6c Standard-Regeldatei: neben anon.ps1 (Admin-VM) oder ..\regeln\ (Repository)
$ohneRegeln = (& $anonScript -Pruefen -Eingabe $erwartetDir *>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $ohneRegeln.Contains("SAUBER")) "Ohne -Regeln wird regeln\anon-regeln.json gefunden (Repository-Struktur)"

# 9.7 Prüfung der Quelldateien: UTF-8 mit BOM, keine Gedankenstriche (PS 5.1 liest .ps1 ohne BOM als ANSI)
foreach ($ps1 in @($anonScript, (Join-Path $testDir "run-tests.ps1"))) {
    $raw = [System.IO.File]::ReadAllBytes($ps1)
    $hasBom = ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF)
    Assert-True $hasBom "$([System.IO.Path]::GetFileName($ps1)) ist UTF-8 mit BOM"
    $txt = [System.Text.Encoding]::UTF8.GetString($raw)
    $dash = $txt.IndexOf([char]0x2013) -ge 0 -or $txt.IndexOf([char]0x2014) -ge 0 -or $txt.IndexOf([char]0x201E) -ge 0 -or $txt.IndexOf([char]0x201C) -ge 0
    Assert-True (-not $dash) "$([System.IO.Path]::GetFileName($ps1)) enthält keine Gedankenstriche oder typografischen Anführungszeichen"
}

$env:LOCALAPPDATA = $origLocalAppData

# Aufräumen des temporären Testordners
if (Test-Path -LiteralPath $tempRunRoot) { Remove-Item -LiteralPath $tempRunRoot -Recurse -Force }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TESTERGEBNIS (PowerShell): $passed bestanden, $failed fehlgeschlagen" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 } else { exit 0 }


