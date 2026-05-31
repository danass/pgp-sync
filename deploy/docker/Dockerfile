# Multi-stage build for pgp-sync. CGO is off so this is a pure-Go build —
# the final image is just a static binary on top of a distroless base.

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pgp-sync ./cmd/pgp-sync

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pgp-sync /pgp-sync

# Defaults assume you mount /var/lib/pgp-sync for persistence and /etc/pgp-sync
# for cert + env. Reverse-proxy in front for TLS if not using built-in.
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/pgp-sync"]
