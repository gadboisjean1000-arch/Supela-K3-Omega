# SUPELA-K3-OMEGA : OPA + Cosign + Proof Pipeline
# Multi-stage build: OPA validator + runtime

# Build stage
FROM alpine:3.20 AS builder
WORKDIR /app

# Install pinned OPA v1.22.4 and Cosign v3.1.4 with SHA-256 verification
RUN apk add --no-cache \
    curl \
    ca-certificates \
    bash \
    git && \
    curl -fsSL https://github.com/open-policy-agent/opa/releases/download/v1.22.4/opa_linux_amd64_static -o /usr/local/bin/opa && \
    echo "35e3b352e715e80624ead6c89930d8585f6f7d94cdc409eb2a9fe36620dcccba  /usr/local/bin/opa" | sha256sum -c - && \
    chmod +x /usr/local/bin/opa && \
    curl -fsSL https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 -o /usr/local/bin/cosign && \
    echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /usr/local/bin/cosign" | sha256sum -c - && \
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
    CMD opa version && cosign version || exit 1

# Default: run OPA tests
CMD ["sh", "-c", "opa test policies/ tests/ -v --explain=fails"]
