# signer/Dockerfile
# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Copia go.mod e go.sum (estão na mesma pasta que o Dockerfile)
COPY go.mod go.sum ./
RUN go mod download

# Copia TODO o código fonte (está tudo na mesma pasta)
COPY . .

# Build do signer (o main.go está na RAIZ, não em ./signer)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/signer .

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10002 signer

WORKDIR /app

COPY --from=builder /out/signer /app/signer

ENV PORT=4010
ENV TZ=UTC

EXPOSE 4010

USER signer

CMD ["/app/signer"]