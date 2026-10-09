# Tests Pester (v3.4) du runtime GDS - verrou logique/idempotence
$here = $PSScriptRoot
$runtime = Join-Path $here "..\runtime\init_gds_pipeline.ps1"
$vault = Join-Path $env:TEMP ("gds_pester_{0}" -f [guid]::NewGuid())

Describe "GDS runtime - rituel d initialisation (GDS = <D, O, A, gamma>)" {
    & $runtime -VaultPath $vault | Out-Null
    $manifest = Join-Path $vault "gds_manifest.json"
    $ledger   = Join-Path $vault "ledger_append_only.log"

    It "cree les 4 sous-dossiers canoniques" {
        foreach ($d in "Diffusion_D", "Ouverture_O", "Absorption_A", "Operateur_Gamma") {
            (Test-Path (Join-Path $vault $d)) | Should Be $true
        }
    }

    It "cree le manifeste" {
        Test-Path $manifest | Should Be $true
    }

    It "verrouille le manifeste (WORM logique, IsReadOnly)" {
        (Get-Item $manifest).IsReadOnly | Should Be $true
    }

    It "calcule une empreinte SHA-256 valide (64 hex majuscules)" {
        $h = (Get-FileHash -Path $manifest -Algorithm SHA256).Hash
        $h | Should Match "^[A-F0-9]{64}$"
    }

    It "est idempotent : le hash du manifeste est stable au 2e run" {
        $h1 = (Get-FileHash -Path $manifest -Algorithm SHA256).Hash
        & $runtime -VaultPath $vault | Out-Null
        $h2 = (Get-FileHash -Path $manifest -Algorithm SHA256).Hash
        $h2 | Should Be $h1
    }

    It "ledger append-only : croit au 2e run (jamais ecrase)" {
        $l1 = (Get-Content -Path $ledger | Measure-Object -Line).Lines
        & $runtime -VaultPath $vault | Out-Null
        $l2 = (Get-Content -Path $ledger | Measure-Object -Line).Lines
        $l2 | Should BeGreaterThan $l1
    }

    It "nettoyage : supprime le vault de test" {
        Remove-Item $vault -Recurse -Force -ErrorAction SilentlyContinue
        (Test-Path $vault) | Should Be $false
    }
}
