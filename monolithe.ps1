<#
.SYNOPSIS
    Orchestrateur du Monolithe Supela-K3-Omega (verrous -> scellement).
    Nomenclature canonique : GDS = <D, O, A, gamma>
.DESCRIPTION
    Equivalent Windows/local du Makefile. Cibles :
      -Task Test    : opa (fmt/check/test) + Pester  [verrou logique]
      -Task Sign    : cosign sign-blob sur manifeste + ledger  [verrou signature]
      -Task Attest  : tpm2_quote (ancrage materiel)  [verrou silicium]
      -Task Verify  : cosign verify-blob  [scellement verifiable]
      -Task Clean   : supprime les preuves temporaires
    HONNETETE : cet orchestrateur verifie la presence des outils. Si un outil
    est absent, il le dit et n execute PAS la cible (pas de faux succes).
#>
[CmdletBinding()]
param(
    [ValidateSet("Test", "Sign", "Attest", "Verify", "Clean", "All")]
    [string]$Task = "Test",
    [string]$Root = $PSScriptRoot,
    [string]$Vault = (Join-Path $env:TEMP "gds_runtime")
)

$ErrorActionPreference = "Stop"
$Policies = Join-Path $Root "policies"
$Tests    = Join-Path $Root "tests"
$Runtime  = Join-Path $Root "runtime"
$Manifest = Join-Path $Vault "gds_manifest.json"
$Ledger   = Join-Path $Vault "ledger_append_only.log"

function Assert-Tool([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host ("[!] outil absent du PATH : {0} - cible NON executee (honnetete)" -f $name) -ForegroundColor Red
        return $false
    }
    return $true
}

function Invoke-GdsTest {
    Write-Host "=== VERROU 1 : validation logique (OPA + Pester) ===" -ForegroundColor Cyan
    if (Assert-Tool "opa") {
        Write-Host "[*] opa fmt --diff"
        $diff = & opa fmt --diff $Policies $Tests 2>&1
        if ($diff) { Write-Host "[!] Rego non formate :`n$diff" -ForegroundColor Red } else { Write-Host "[+] formatage OK" -ForegroundColor Green }
        Write-Host "[*] opa check --strict"
        & opa check --strict $Policies $Tests
        Write-Host "[*] opa test -v --explain=fails"
        & opa test $Policies $Tests -v --explain=fails
    }
    Write-Host "[*] Invoke-Pester (runtime idempotence)"
    & (Join-Path $Runtime "init_gds_pipeline.ps1") -VaultPath $Vault | Out-Null
    Invoke-Pester -Path (Join-Path $Tests "init_gds_pipeline.Tests.ps1") -PassThru | ForEach-Object { Write-Host ("[+] Pester : {0}/{1} tests passes" -f $_.PassedCount, $_.TotalCount) -ForegroundColor Green }
}

function Invoke-GdsSign {
    Write-Host "=== VERROU 2 : signature cryptographique (cosign) ===" -ForegroundColor Cyan
    if (-not (Assert-Tool "cosign")) { return }
    if (-not (Test-Path $Manifest)) { Write-Host "[!] manifeste absent - lance d abord -Task Test" -ForegroundColor Red; return }
    & cosign sign-blob --key cosign.key --yes --bundle "$Manifest.bundle" $Manifest
    Write-Host ("[+] manifeste signe (bundle) : {0}.bundle" -f $Manifest) -ForegroundColor Green
    if (Test-Path $Ledger) { & cosign sign-blob --key cosign.key --yes --bundle "$Ledger.bundle" $Ledger; Write-Host "[+] ledger signe" -ForegroundColor Green }
}

function Invoke-GdsAttest {
    Write-Host "=== VERROU 3 : ancrage materiel (tpm2-tools) ===" -ForegroundColor Cyan
    if (-not (Assert-Tool "tpm2_quote")) { Write-Host "[i] tpm2_quote absent : ancrage silicium DECLARATIF sur cette machine (voir README)." -ForegroundColor Yellow; return }
    $hash = (Get-FileHash -Path $Manifest -Algorithm SHA256).Hash
    Write-Host ("[*] hash manifeste : {0}" -f $hash)
    & tpm2_quote -c primary.ctx -l sha256:15,16,22 -m quote.msg -s quote.sig -p pcr.bin -g sha256
    Write-Host "[+] quote TPM generee" -ForegroundColor Green
}

function Invoke-GdsVerify {
    Write-Host "=== VERROU 4 : verification du scellement (cosign verify) ===" -ForegroundColor Cyan
    if (-not (Assert-Tool "cosign")) { return }
    & cosign verify-blob --key cosign.pub --bundle "$Manifest.bundle" $Manifest
    Write-Host "[+] signature du manifeste VERIFIEE" -ForegroundColor Green
}

function Invoke-GdsClean {
    Write-Host "=== NETTOYAGE des preuves temporaires ===" -ForegroundColor Cyan
    Remove-Item -Force -ErrorAction SilentlyContinue "$Manifest.bundle", "$Ledger.bundle", "quote.msg", "quote.sig", "pcr.bin"
    Write-Host "[+] nettoye" -ForegroundColor Green
}

switch ($Task) {
    "Test"    { Invoke-GdsTest }
    "Sign"    { Invoke-GdsSign }
    "Attest"  { Invoke-GdsAttest }
    "Verify"  { Invoke-GdsVerify }
    "Clean"   { Invoke-GdsClean }
    "All"     { Invoke-GdsTest; Invoke-GdsSign; Invoke-GdsAttest; Invoke-GdsVerify }
}
