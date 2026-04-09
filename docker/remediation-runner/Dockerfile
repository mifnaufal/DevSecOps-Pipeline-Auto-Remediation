FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/remediation-runner/ ./cmd/remediation-runner/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /remediation-runner ./cmd/remediation-runner/

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip install tree-sitter tree-sitter-python tree-sitter-javascript

WORKDIR /app

COPY --from=builder /remediation-runner /app/remediation-runner
COPY codemods/ /app/codemods/

RUN addgroup --gid 1001 appgroup && \
    adduser --uid 1001 --ingroup appgroup --disabled-password appuser
USER appuser

ENTRYPOINT ["/app/remediation-runner"]
