FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/api-server/ ./cmd/api-server/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /api-server ./cmd/api-server/

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /api-server /app/api-server

RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -D appuser
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/api-server"]
