[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$Script:FailureCount = 0
$RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$ModulePath = Join-Path -Path $RepositoryRoot -ChildPath "HardeningKitty.psm1"
$ListsPath = Join-Path -Path $RepositoryRoot -ChildPath "lists"
$ManifestPath = Join-Path -Path $ListsPath -ChildPath "hardeningkitty_lists_manifest.psd1"
$SignaturePath = Join-Path -Path $ListsPath -ChildPath "hardeningkitty_lists_manifest.psd1.p7s"
$PinnedThumbprint = "F47005C8B9BECD8225E13A00A256BEE23DE27673"

Function Assert-True {
    param (
        [Parameter(Mandatory = $true)]
        [Boolean]
        $Condition,
        [Parameter(Mandatory = $true)]
        [String]
        $Message
    )

    If (-not($Condition)) {
        throw $Message
    }
}

Function Invoke-SafetyTest {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $Test
    )

    try {
        & $Test
        Write-Host "[PASS] $Name"
    } catch {
        $Script:FailureCount++
        Write-Host "[FAIL] $Name`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$Tokens = $null
$ParseErrors = $null
$ModuleAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $ModulePath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
$ModuleText = [System.IO.File]::ReadAllText($ModulePath)

Invoke-SafetyTest -Name "Module parses without errors" -Test {
    Assert-True -Condition ($ParseErrors.Count -eq 0) -Message "PowerShell parser reported $($ParseErrors.Count) error(s)."
}

# Load only the private, side-effect-free helpers under test. Importing the full module would not
# expose them because HardeningKitty currently defines its helpers inside Invoke-HardeningKitty.
$HelperNames = @(
    "Read-HardeningKittyFileSnapshot",
    "ConvertFrom-HardeningKittyTextBytes",
    "Read-FindingListSnapshot",
    "Test-FindingListWriteSchema",
    "ConvertFrom-HardeningKittyManifestBytes",
    "Confirm-FindingListIntegrity"
)
ForEach ($HelperName in $HelperNames) {
    $Definitions = @($ModuleAst.FindAll({
        param ($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $HelperName
    }, $true))
    If ($Definitions.Count -ne 1) {
        throw "Expected one definition of $HelperName, found $($Definitions.Count)."
    }
    . ([ScriptBlock]::Create($Definitions[0].Extent.Text))
}

Invoke-SafetyTest -Name "All signed CSV files have consistent hashes" -Test {
    $CsvFiles = @(Get-ChildItem -LiteralPath $ListsPath -Filter "*.csv" -File)
    Assert-True -Condition ($CsvFiles.Count -eq 134) -Message "Expected 134 signed CSV files, found $($CsvFiles.Count)."
    ForEach ($CsvFile in $CsvFiles) {
        $Snapshot = Read-FindingListSnapshot -LiteralPath $CsvFile.FullName
        $Status = Confirm-FindingListIntegrity -ListPath $CsvFile.FullName `
            -ListBytes $Snapshot.Bytes `
            -ManifestPath $ManifestPath `
            -SignaturePath $SignaturePath `
            -PinnedThumbprint $PinnedThumbprint
        Assert-True -Condition $Status.Verified -Message "$($CsvFile.Name) failed integrity verification: $($Status.Reason)"
    }
}

Invoke-SafetyTest -Name "Only executable finding lists pass the write schema" -Test {
    $ValidNames = @()
    $InvalidNames = @()
    $CsvFiles = @(Get-ChildItem -LiteralPath $ListsPath -Filter "*.csv" -File)
    ForEach ($CsvFile in $CsvFiles) {
        $Snapshot = Read-FindingListSnapshot -LiteralPath $CsvFile.FullName
        $Schema = Test-FindingListWriteSchema -Snapshot $Snapshot
        If ($Schema.Valid) {
            $ValidNames += $CsvFile.Name
        } Else {
            $InvalidNames += $CsvFile.Name
        }
    }

    Assert-True -Condition ($ValidNames.Count -eq 132) -Message "Expected 132 executable finding lists, found $($ValidNames.Count)."
    Assert-True -Condition ($InvalidNames.Count -eq 2) -Message "Expected two auxiliary CSV files, found $($InvalidNames.Count)."
    Assert-True -Condition ($InvalidNames -contains "finding_list_intune.csv") -Message "The Intune metadata file was not rejected."
    Assert-True -Condition ($InvalidNames -contains "finding_list_translation.csv") -Message "The translation metadata file was not rejected."
}

Invoke-SafetyTest -Name "List parsing and hashing use one byte snapshot" -Test {
    $TemporaryDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("HardeningKittySafety_" + [Guid]::NewGuid().ToString("N"))
    New-Item -Path $TemporaryDirectory -ItemType Directory -ErrorAction Stop | Out-Null
    try {
        $OfficialName = "finding_list_4d5a_machine.csv"
        $OfficialPath = Join-Path -Path $ListsPath -ChildPath $OfficialName
        $TestPath = Join-Path -Path $TemporaryDirectory -ChildPath $OfficialName
        $OfficialBytes = [System.IO.File]::ReadAllBytes($OfficialPath)
        [System.IO.File]::WriteAllBytes($TestPath, $OfficialBytes)

        $OfficialSnapshot = Read-FindingListSnapshot -LiteralPath $TestPath
        $MaliciousCsv = "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,ClassName,Namespace,Property,DefaultValue,RecommendedValue,Operator,Severity`r`nPOC,PoC,Marker,Registry,,HKLM:\SOFTWARE\PoC,Marker,,,,0,1,=,High`r`n"
        $Utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($TestPath, $MaliciousCsv, $Utf8)

        $OfficialStatus = Confirm-FindingListIntegrity -ListPath $TestPath `
            -ListBytes $OfficialSnapshot.Bytes `
            -ManifestPath $ManifestPath `
            -SignaturePath $SignaturePath `
            -PinnedThumbprint $PinnedThumbprint
        Assert-True -Condition $OfficialStatus.Verified -Message "The captured official bytes should remain verified after a path swap."
        Assert-True -Condition ($OfficialSnapshot.Rows[0].ID -ne "POC") -Message "Rows changed after the source path was replaced."

        $MaliciousSnapshot = Read-FindingListSnapshot -LiteralPath $TestPath
        [System.IO.File]::WriteAllBytes($TestPath, $OfficialBytes)
        $MaliciousStatus = Confirm-FindingListIntegrity -ListPath $TestPath `
            -ListBytes $MaliciousSnapshot.Bytes `
            -ManifestPath $ManifestPath `
            -SignaturePath $SignaturePath `
            -PinnedThumbprint $PinnedThumbprint
        Assert-True -Condition (-not($MaliciousStatus.Verified)) -Message "Captured malicious bytes were incorrectly verified after the path was restored."
        Assert-True -Condition ($MaliciousSnapshot.Rows[0].ID -eq "POC") -Message "The malicious snapshot was not parsed consistently."
    } finally {
        If (Test-Path -LiteralPath $TemporaryDirectory) {
            Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Invoke-SafetyTest -Name "Manifest parser accepts literals and rejects dynamic expressions" -Test {
    $ManifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
    $Manifest = ConvertFrom-HardeningKittyManifestBytes -Bytes $ManifestBytes
    Assert-True -Condition ($Manifest.Version -eq 1) -Message "The signed literal manifest was rejected."

    $DynamicText = '@{ Version = 1; Algorithm = "SHA256"; Lists = @{}; Dynamic = $(Get-Date) }'
    $Utf8 = New-Object System.Text.UTF8Encoding($false)
    $DynamicBytes = $Utf8.GetBytes($DynamicText)
    $Rejected = $false
    try {
        ConvertFrom-HardeningKittyManifestBytes -Bytes $DynamicBytes | Out-Null
    } catch {
        $Rejected = $true
    }
    Assert-True -Condition $Rejected -Message "A dynamic manifest expression was accepted."
}

Invoke-SafetyTest -Name "Write modes complete preflight before side effects" -Test {
    $HailMaryStart = $ModuleText.IndexOf('Elseif ($Mode -eq "HailMary")')
    $GpoStart = $ModuleText.IndexOf('Elseif ($Mode -eq "GPO")')
    Assert-True -Condition ($HailMaryStart -ge 0 -and $GpoStart -gt $HailMaryStart) -Message "Could not locate write mode blocks."

    $HailMaryText = $ModuleText.Substring($HailMaryStart, $GpoStart - $HailMaryStart)
    $HailMarySchema = $HailMaryText.IndexOf('Test-FindingListWriteSchema')
    $RestorePoint = $HailMaryText.IndexOf('Checkpoint-Computer -Description')
    Assert-True -Condition ($HailMarySchema -ge 0 -and $HailMarySchema -lt $RestorePoint) -Message "HailMary can create a restore point before schema validation."

    $GpoText = $ModuleText.Substring($GpoStart)
    $GpoSchema = $GpoText.IndexOf('Test-FindingListWriteSchema')
    $NewGpo = $GpoText.IndexOf('New-GPO -Name $GPOname')
    Assert-True -Condition ($GpoSchema -ge 0 -and $GpoSchema -lt $NewGpo) -Message "GPO creation occurs before schema validation."
}

Invoke-SafetyTest -Name "Unsafe path re-reads are absent" -Test {
    Assert-True -Condition (-not($ModuleText.Contains('$FindingList = Import-Csv -Path $FileFindingList'))) -Message "A finding list is still imported directly from its source path."
    Assert-True -Condition (-not($ModuleText.Contains('Import-PowerShellDataFile -Path $ManifestPath'))) -Message "The manifest is still reopened after signature verification."
    $GuardCount = [Regex]::Matches($ModuleText, '@\("!=", "notcontains"\) -contains').Count
    Assert-True -Condition ($GuardCount -eq 2) -Message "Expected negative-operator guards in both write modes, found $GuardCount."
}

If ($Script:FailureCount -gt 0) {
    throw "$Script:FailureCount finding-list safety test(s) failed."
}

Write-Host "All finding-list safety tests passed."
