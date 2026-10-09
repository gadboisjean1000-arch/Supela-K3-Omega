# SUPELA-K3-OMEGA : EXECUTION & PROOF PIPELINE (POSIX make)
# Nomenclature canonique : GDS = <D, O, A, gamma> | gamma* = gamma compose Lambda | SCT = gamma*(D,O,A)
# Usage (CI Linux / macOS) : make <test|sign|attest|verify|clean>
# Equivalent Windows/local : .\monolithe.ps1 -Task <...>
# Outils requis : opa, cosign (v3 : --bundle), tpm2-tools. Ce Makefile MESURE, il ne proclame pas.

OPA       ?= opa
COSIGN    ?= cosign
TPM2      ?= tpm2_quote
POLICIES  := policies
TESTS     := tests
VAULT     ?= $(or $(GDS_VAULT),$(RUNNER_TEMP))/gds
MANIFEST  := $(VAULT)/gds_manifest.json
LEDGER    := $(VAULT)/ledger_append_only.log
COSIGN_KEY ?= cosign.key
COSIGN_PUB ?= cosign.pub

.PHONY: help test sign attest verify clean

help:
	@echo "cibles: test | sign | attest | verify | clean"

test:
	$(OPA) fmt --diff $(POLICIES) $(TESTS)
	$(OPA) check --strict $(POLICIES) $(TESTS)
	$(OPA) test $(POLICIES) $(TESTS) -v --explain=fails
	pwsh -NoProfile -Command "$$r = Invoke-Pester -Script $(TESTS)/init_gds_pipeline.Tests.ps1 -PassThru; if ($$r.FailedCount -gt 0) { exit 1 }"

sign:
	@test -f $(MANIFEST) || { echo "manifeste absent : lance le runtime d abord"; exit 1; }
	$(COSIGN) sign-blob --key $(COSIGN_KEY) --yes --bundle $(MANIFEST).bundle $(MANIFEST)
	@if [ -f "$(LEDGER)" ]; then $(COSIGN) sign-blob --key $(COSIGN_KEY) --yes --bundle $(LEDGER).bundle $(LEDGER); fi

attest:
	@command -v $(TPM2) >/dev/null 2>&1 || { echo "tpm2_quote absent : ancrage silicium DECLARATIF (verrou NON satisfait)"; exit 1; }
	$(TPM2) quote -c primary.ctx -l sha256:15,16,22 -m quote.msg -s quote.sig -p pcr.bin -g sha256

verify:
	$(COSIGN) verify-blob --key $(COSIGN_PUB) --bundle $(MANIFEST).bundle $(MANIFEST)

clean:
	rm -f $(MANIFEST).bundle $(LEDGER).bundle quote.msg quote.sig pcr.bin

