# signer/Dockerfile (dentro da pasta signer/)

FROM golang:1.25-bookworm AS builder

WORKDIR /build

# O go.mod está na RAIZ do payment-gateway (um nível acima)
COPY ../go.mod ../go.sum ./
RUN go mod download

# Copia TODO o projeto (porque o signer pode depender de pacotes internos)
COPY .. .

# Build do signer - ele está em ./signer/
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/signer ./signer

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/signer /app/signer

ENV PORT=4010
EXPOSE 4010

CMD ["/app/signer"]