# SUPELA-K3-OMEGA : OPA + Cosign + Proof Pipeline
# Multi-stage build: OPA validator + runtime

# Build stage
FROM alpine:3.20 AS builder
WORKDIR /app

# Install OPA, cosign, tpm2-tools
RUN apk add --no-cache \
    curl \
    ca-certificates \
    bash \
    git && \
    # Install OPA
    curl -fsSL https://openpolicyagent.org/downloads/latest/opa_linux_amd64 -o /usr/local/bin/opa && \
    chmod +x /usr/local/bin/opa && \
    # Install cosign
    curl -fsSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Copy policies and tests
COPY policies/ ./policies/
COPY tests/ ./tests/
COPY monolithe.ps1 ./
COPY Makefile ./
COPY README.md ./

# Runtime stage
FROM alpine:3.20
WORKDIR /app

# Install runtime deps
RUN apk add --no-cache \
    bash \
    ca-certificates \
    git \
    curl

# Copy OPA and cosign from builder
COPY --from=builder /usr/local/bin/opa /usr/local/bin/opa
COPY --from=builder /usr/local/bin/cosign /usr/local/bin/cosign

# Copy app files
COPY --from=builder /app/policies ./policies
COPY --from=builder /app/tests ./tests
COPY --from=builder /app/monolithe.ps1 ./
COPY --from=builder /app/Makefile ./
COPY --from=builder /app/README.md ./

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD opa --version && cosign --version || exit 1

# Default: run OPA tests
CMD ["sh", "-c", "opa test policies/ tests/ -v --explain=fails"]
