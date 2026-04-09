FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/triage-engine/ ./cmd/triage-engine/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /triage-engine ./cmd/triage-engine/

FROM alpine:3.19

RUN apk add --no-cache jq

WORKDIR /app

COPY --from=builder /triage-engine /app/triage-engine

RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -D appuser
USER appuser

ENTRYPOINT ["/app/triage-engine"]
