<#
.SYNOPSIS
    Instanciation physique de la Générale du Savoir (GDS).
    Nomenclature canonique : GDS = <D, O, A, gamma>
.DESCRIPTION
    Rituel d initialisation déterministe et IDEMPOTENT.
    - Arborescence convergente : chaque sous-dossier est testé séparément.
    - Manifeste : écrit UNE fois, puis verrouillé en lecture seule (WORM logique).
    - Empreinte SHA-256 réelle (Get-FileHash) du manifeste.
    - Ledger append-only : Add-Content uniquement, jamais Set-Content.
    Transparence : ce script produit un WORM LOGIQUE (lecture seule + append-only).
    Il ne prétend pas à un WORM matériel ; l ancrage TPM/TEE reste hors périmètre.
#>
[CmdletBinding()]
param(
    [string]$VaultPath = "C:\Supela\Vaults\GDS"
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Instanciation du Monolithe GDS - tuple <D, O, A, gamma>..." -ForegroundColor Cyan

# --- 1. Arborescence convergente (idempotente) : CHAQUE sous-dossier testé seul
$subdirs = [ordered]@{
    "Diffusion_D"     = "D - Diffusion (circulation du savoir)"
    "Ouverture_O"     = "O - Ouverture (registre)"
    "Absorption_A"    = "A - Absorption (noyau multi-agents)"
    "Operateur_Gamma" = "gamma - Operateur de coherence (SCT)"
}

if (-not (Test-Path $VaultPath)) {
    New-Item -ItemType Directory -Force -Path $VaultPath | Out-Null
}

foreach ($name in $subdirs.Keys) {
    $p = Join-Path $VaultPath $name
    if (-not (Test-Path $p)) {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
        Write-Host ("    + cree    {0}" -f $name) -ForegroundColor Gray
    } else {
        Write-Host ("    = present {0} (idempotent)" -f $name) -ForegroundColor DarkGray
    }
}

$manifest = Join-Path $VaultPath "gds_manifest.json"
$ledger   = Join-Path $VaultPath "ledger_append_only.log"
$seal     = Join-Path $VaultPath "gds_seal.txt"

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")

# --- 2. Manifeste : écrit UNE fois, puis verrouillé lecture seule (WORM logique)
if (-not (Test-Path $manifest)) {
    $manifestContent = [ordered]@{
        system         = "Supela-K3-Omega-Monolithe"
        nomenclature   = "GDS = <D, O, A, gamma>"
        gds_tuple      = [ordered]@{
            D     = "Diffusion - circulation du savoir"
            O     = "Ouverture - registre append-only (WORM)"
            A     = "Absorption - noyau multi-agents Zero-Trust"
            gamma = "Operateur de coherence (SCT)"
        }
        created_utc    = $timestamp
    } | ConvertTo-Json -Depth 5

    Set-Content -Path $manifest -Value $manifestContent -Encoding utf8
    Set-ItemProperty -Path $manifest -Name IsReadOnly -Value $true
    Write-Host "[+] manifeste cree et verrouille (IsReadOnly)" -ForegroundColor Green
} else {
    Write-Host "[=] manifeste deja present - NON reecrit (idempotent)" -ForegroundColor Yellow
}

# --- 3. Empreinte SHA-256 REELLE du manifeste
$hash = (Get-FileHash -Path $manifest -Algorithm SHA256).Hash

# --- 4. Ledger append-only : Add-Content uniquement (jamais Set-Content)
$entry = ("{0} | run | manifest_sha256={1} | idempotent=true" -f $timestamp, $hash)
Add-Content -Path $ledger -Value $entry -Encoding utf8

# --- 5. Sceau : rapport de la derniere execution (non verrouille)
$ledgerLines = (Get-Content -Path $ledger | Measure-Object -Line).Lines
$sealContent = @"
Sceau GDS (preuve reproductible)
timestamp_utc   : $timestamp
manifest_path    : $manifest
manifest_sha256  : $hash
ledger_path      : $ledger
ledger_lines     : $ledgerLines
note             : manifeste en lecture seule ; ledger append-only (Add-Content).
"@
Set-Content -Path $seal -Value $sealContent -Encoding utf8

Write-Host ("[+] SHA-256 manifeste = {0}" -f $hash) -ForegroundColor Green
Write-Host ("[+] ledger append-only = {0} lignes" -f $ledgerLines) -ForegroundColor Green
Write-Host "[+] Rituel accompli. Octets graves." -ForegroundColor Green
