#!/usr/bin/env bash
# Builds Linkerd controller and proxy images from local checkouts, tagged
# cr.l5d.io/linkerd/{controller,proxy}:$TAG so the checkout's bin/linkerd
# installs them without overrides.
#
# On amd64 hosts this uses the upstream build scripts. On arm64 hosts
# (e.g. Apple Silicon) the upstream Dockerfiles cannot run, since
# ghcr.io/linkerd/dev:*-rust* is amd64-only, so instead:
#   - the Go controller is cross-compiled natively and layered over the
#     released multi-arch controller image (keeping its policy-controller,
#     which linkerd/linkerd2#15676 does not change);
#   - the proxy is compiled natively in a linux/arm64 Rust container and
#     layered over the released proxy image, mirroring the final stage of
#     linkerd2-proxy's own Dockerfile.
#
# Usage: build-linkerd-images.sh TAG LINKERD2_DIR LINKERD2_PROXY_DIR BASE_TAG
set -euo pipefail

tag=$1 linkerd2=$2 proxy=$3 base=$4

case "$(uname -m)" in
x86_64 | amd64)
  (cd "$linkerd2" && TAG=$tag bin/docker-build-controller)
  (cd "$proxy" && LINKERD_TAG=$base just docker-repo=cr.l5d.io/linkerd/proxy docker-tag="$tag" docker)
  exit 0
  ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "--> controller (Go, cross-compiled for linux/arm64)"
mkdir -p "$work/controller"
(cd "$linkerd2" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o "$work/controller/controller" -tags prod -mod=readonly -ldflags "-s -w" ./controller/cmd)
cat >"$work/controller/Dockerfile" <<DOCKERFILE
FROM cr.l5d.io/linkerd/controller:$base
COPY controller /controller
DOCKERFILE
docker build --platform linux/arm64 -t "cr.l5d.io/linkerd/controller:$tag" "$work/controller"

echo "--> proxy (Rust, native linux/arm64 build; the first run takes a while)"
toolchain=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$proxy/rust-toolchain.toml")
mkdir -p "$work/proxy"
# Named volumes keep the cargo registry and target dir warm across runs.
docker run --rm --platform linux/arm64 \
  -v "$proxy":/src:ro \
  -v pgppi-cargo-registry:/usr/local/cargo/registry \
  -v pgppi-proxy-target:/target \
  -v "$work/proxy":/out \
  -e CARGO_TARGET_DIR=/target \
  -e RUSTFLAGS="-A deprecated --cfg tokio_unstable" \
  -e LINKERD2_PROXY_VERSION="0.0.0-dev.$(git -C "$proxy" rev-parse --short HEAD)" \
  -e LINKERD2_PROXY_VENDOR="pg-ppi-e2e" \
  -w /src "rust:$toolchain-bookworm" bash -ec '
    apt-get update -qq && apt-get install -y -qq cmake clang protobuf-compiler >/dev/null
    cargo build --locked --package=linkerd2-proxy
    cp /target/debug/linkerd2-proxy /out/'
cat >"$work/proxy/Dockerfile" <<DOCKERFILE
FROM ghcr.io/linkerd/proxy:$base
COPY linkerd2-proxy /usr/lib/linkerd/linkerd2-proxy
DOCKERFILE
docker build --platform linux/arm64 -t "cr.l5d.io/linkerd/proxy:$tag" "$work/proxy"
