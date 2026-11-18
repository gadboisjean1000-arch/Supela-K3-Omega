# Tests Pester (v5) du runtime GDS - verrou logique/idempotence
BeforeAll {
    $here = $PSScriptRoot
    $script:runtime = Join-Path $here "..\runtime\init_gds_pipeline.ps1"
    $script:vault = Join-Path $env:TEMP ("gds_pester_{0}" -f [guid]::NewGuid())
    & $script:runtime -VaultPath $script:vault | Out-Null
    $script:manifest = Join-Path $script:vault "gds_manifest.json"
    $script:ledger   = Join-Path $script:vault "ledger_append_only.log"
}

AfterAll {
    Remove-Item $script:vault -Recurse -Force -ErrorAction SilentlyContinue
}

Describe "GDS runtime - rituel d initialisation (GDS = <D, O, A, gamma>)" {
    It "cree les 4 sous-dossiers canoniques" {
        foreach ($d in "Diffusion_D", "Ouverture_O", "Absorption_A", "Operateur_Gamma") {
            (Test-Path (Join-Path $script:vault $d)) | Should -Be $true
        }
    }

    It "cree le manifeste" {
        Test-Path $script:manifest | Should -Be $true
    }

    It "verrouille le manifeste (WORM logique, IsReadOnly)" {
        (Get-Item $script:manifest).IsReadOnly | Should -Be $true
    }

    It "calcule une empreinte SHA-256 valide (64 hex majuscules)" {
        $h = (Get-FileHash -Path $script:manifest -Algorithm SHA256).Hash
        $h | Should -Match "^[A-F0-9]{64}$"
    }

    It "est idempotent : le hash du manifeste est stable au 2e run" {
        $h1 = (Get-FileHash -Path $script:manifest -Algorithm SHA256).Hash
        & $script:runtime -VaultPath $script:vault | Out-Null
        $h2 = (Get-FileHash -Path $script:manifest -Algorithm SHA256).Hash
        $h2 | Should -Be $h1
    }

    It "ledger append-only : croit au 2e run (jamais ecrase)" {
        $l1 = (Get-Content -Path $script:ledger | Measure-Object -Line).Lines
        & $script:runtime -VaultPath $script:vault | Out-Null
        $l2 = (Get-Content -Path $script:ledger | Measure-Object -Line).Lines
        $l2 | Should -BeGreaterThan $l1
    }
}
