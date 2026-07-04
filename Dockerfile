# signer/Dockerfile
# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build do signer - o binário vai ser chamado de "signer"
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

# O binário "/out/signer" vai ser copiado como "/app/signer"
# O nome do arquivo é "signer", não tem pasta signer/
COPY --from=builder /out/signer /app/signer

ENV PORT=4010
ENV TZ=UTC

EXPOSE 4010

USER signer

CMD ["/app/signer"]