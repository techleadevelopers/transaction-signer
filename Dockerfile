FROM golang:1.25-bookworm AS builder

WORKDIR /build

# go.mod está na MESMA pasta que o Dockerfile
COPY go.mod go.sum ./
RUN go mod download

# Copia tudo (só a pasta signer)
COPY . .

# Build (main.go está na raiz)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/signer .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/signer /app/signer

ENV PORT=4010
EXPOSE 4010

CMD ["/app/signer"]