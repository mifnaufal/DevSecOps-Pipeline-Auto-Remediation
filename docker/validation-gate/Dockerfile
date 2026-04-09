FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/validation-gate/ ./cmd/validation-gate/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /validation-gate ./cmd/validation-gate/

FROM golang:1.21-alpine

RUN apk add --no-cache \
    bash \
    jq \
    nodejs npm \
    python3 py3-pip

WORKDIR /app

COPY --from=builder /validation-gate /app/validation-gate
COPY scripts/validation-gate.sh /app/scripts/validation-gate.sh

RUN chmod +x /app/scripts/validation-gate.sh

ENTRYPOINT ["/app/validation-gate"]
