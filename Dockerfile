# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/pgppi ./cmd/pgppi

# One image serves both roles: `pgppi plugin` (CNPG-I plugin Deployment) and
# `pgppi proxy` (the sidecar the plugin injects into instance pods).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pgppi /usr/local/bin/pgppi
ENTRYPOINT ["/usr/local/bin/pgppi"]
