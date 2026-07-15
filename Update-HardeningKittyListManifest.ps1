<#
.SYNOPSIS
    Generate and sign the HardeningKitty finding-list manifest

     =^._.^=
    _(      )/  HardeningKitty


    Author:  Michael Schneider
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION
    Builds lists\hardeningkitty_lists_manifest.psd1 - a readable PowerShell data file mapping every official
    finding list (*.csv) to its SHA-256 hash - and produces a detached PKCS#7 signature
    lists\hardeningkitty_lists_manifest.psd1.p7s using the maintainer code-signing certificate.

    HardeningKitty verifies a finding list by checking this detached signature with
    SignedCms.CheckSignature($true) (signature integrity only, chain/validity ignored) and by
    matching the signer certificate thumbprint against the value pinned in HardeningKitty.psm1
    ($HardeningKittyListSigningThumbprint). A self-signed certificate is therefore sufficient and
    no timestamp is required.

    Re-run this script whenever the lists are regenerated (e.g. as a release / CI step).

.PARAMETER ListDirectory
    Directory containing the *.csv finding lists. Defaults to the lists\ folder next to this script.

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.PARAMETER PfxPath
    Path to a PFX file holding the signing certificate and its private key.

.PARAMETER PfxPassword
    Password for the PFX as a SecureString. If omitted with -PfxPath, you are prompted.

.EXAMPLE
    .\Update-HardeningKittyListManifest.ps1 -CertificateThumbprint $cert.Thumbprint

.EXAMPLE
    .\Update-HardeningKittyListManifest.ps1 -PfxPath .\signing-key.pfx
#>

[CmdletBinding(DefaultParameterSetName = "Store")]
param (
    [String]
    $ListDirectory = (Join-Path -Path $PSScriptRoot -ChildPath "lists"),

    [Parameter(Mandatory = $true, ParameterSetName = "Store")]
    [String]
    $CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = "Pfx")]
    [String]
    $PfxPath,

    [Parameter(ParameterSetName = "Pfx")]
    [System.Security.SecureString]
    $PfxPassword
)

$Version = "0.0.1-1784108070"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# The PKCS#7/CMS types (SignedCms, ContentInfo, CmsSigner) live in the System.Security assembly,
# which is not loaded by default on Windows PowerShell 5.1. It is already present on PowerShell 7.
if (-not ([System.Management.Automation.PSTypeName]'System.Security.Cryptography.Pkcs.SignedCms').Type) {
    Add-Type -AssemblyName System.Security
}

$ManifestName  = "hardeningkitty_lists_manifest.psd1"
$ManifestPath  = Join-Path -Path $ListDirectory -ChildPath $ManifestName
$SignaturePath = "$ManifestPath.p7s"

#
# Header
#
Write-Output "`n"
Write-Output "      =^._.^="
Write-Output "     _(      )/  HardeningKitty List Manifest Tool $Version"
Write-Output "`n"

if (-not (Test-Path -LiteralPath $ListDirectory)) {
    throw "List directory not found: $ListDirectory"
}

#
# Load the signing certificate
#
if ($PSCmdlet.ParameterSetName -eq "Pfx") {
    if (-not (Test-Path -LiteralPath $PfxPath)) {
        throw "PFX file not found: $PfxPath"
    }
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host -AsSecureString "PFX password"
    }
    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $PfxPath,
        $PfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    )
} else {
    $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint", "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Certificate) {
        throw "No certificate with thumbprint $CertificateThumbprint found in Cert:\CurrentUser\My or Cert:\LocalMachine\My"
    }
}

if (-not $Certificate.HasPrivateKey) {
    throw "The signing certificate does not have an associated private key."
}

Write-Host "[*] Signing certificate: $($Certificate.Subject) ($($Certificate.Thumbprint))"

#
# Build the manifest
#
$Lists = Get-ChildItem -Path $ListDirectory -Filter "*.csv" -File | Sort-Object -Property Name

if ($Lists.Count -eq 0) {
    throw "No *.csv finding lists found in $ListDirectory"
}

$Builder = New-Object System.Text.StringBuilder
[void]$Builder.AppendLine("@{")
[void]$Builder.AppendLine("    Version   = 1")
[void]$Builder.AppendLine("    Algorithm = 'SHA256'")
[void]$Builder.AppendLine("    Lists     = @{")
foreach ($List in $Lists) {
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $List.FullName).Hash
    [void]$Builder.AppendLine("        '$($List.Name)' = '$Hash'")
}
[void]$Builder.AppendLine("    }")
[void]$Builder.AppendLine("}")

# Write deterministically as UTF-8 without BOM; the detached signature is over these exact bytes.
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, $Builder.ToString(), $Utf8NoBom)
Write-Host "[*] Wrote manifest: $ManifestPath ($($Lists.Count) lists)"

# Sanity check: the manifest must be parseable as a data file
$null = Import-PowerShellDataFile -Path $ManifestPath

#
# Produce a detached PKCS#7 signature over the manifest bytes
#
$ManifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
$ContentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $ManifestBytes)
$SignedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms($ContentInfo, $true)   # detached
$CmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner($Certificate)
# Embed the signer certificate so the verifier can read its thumbprint. EndCertOnly is required:
# the default (ExcludeRoot) would drop a self-signed certificate, which is its own root.
$CmsSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
$CmsSigner.DigestAlgorithm = New-Object System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1")  # SHA-256
$SignedCms.ComputeSignature($CmsSigner)
[System.IO.File]::WriteAllBytes($SignaturePath, $SignedCms.Encode())
Write-Host "[*] Wrote detached signature: $SignaturePath"

#
# Self-verify the way HardeningKitty will
#
$Verify = New-Object System.Security.Cryptography.Pkcs.SignedCms(
    (New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $ManifestBytes)),
    $true
)
$Verify.Decode([System.IO.File]::ReadAllBytes($SignaturePath))
$Verify.CheckSignature($true)
Write-Host "[+] Signature verifies. Signer thumbprint: $($Verify.SignerInfos[0].Certificate.Thumbprint)"
Write-Host "[+] Ensure `$HardeningKittyListSigningThumbprint in HardeningKitty.psm1 is set to this thumbprint."
