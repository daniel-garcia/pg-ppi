#!/usr/bin/env bash
# Brings up a kind cluster with cert-manager, Linkerd built from the
# proxy-protocol-v2 branches, CloudNativePG, the pgppi plugin, an example
# Cluster and psql client workloads. Re-running is safe; completed steps are
# mostly no-ops.
#
# Environment:
#   CLUSTER             kind cluster name (default: pgppi)
#   LINKERD2_DIR        linkerd/linkerd2 checkout with #15676
#   LINKERD2_PROXY_DIR  linkerd/linkerd2-proxy checkout with #4625
#   LINKERD_BASE_TAG    released edge tag whose proxy image supplies the
#                       identity/await wrappers (default: edge-26.9.1)
#   SKIP_LINKERD_BUILD  set to reuse previously built Linkerd images
#   PGPPI_IMAGE         image for the plugin and sidecar
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
CLUSTER=${CLUSTER:-pgppi}
LINKERD2_DIR=${LINKERD2_DIR:-$root/../../linkerd/linkerd2}
LINKERD2_PROXY_DIR=${LINKERD2_PROXY_DIR:-$root/../../linkerd/linkerd2-proxy}
LINKERD_BASE_TAG=${LINKERD_BASE_TAG:-edge-26.9.1}
PGPPI_IMAGE=${PGPPI_IMAGE:-ghcr.io/daniel-garcia/pg-ppi:dev}
CERT_MANAGER_VERSION=${CERT_MANAGER_VERSION:-v1.21.2}
CNPG_VERSION=${CNPG_VERSION:-1.30.1}

ctx=kind-$CLUSTER
k() { kubectl --context "$ctx" "$@"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "kind cluster $CLUSTER"
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s

step "Linkerd images from $LINKERD2_DIR and $LINKERD2_PROXY_DIR"
tag=$(cd "$LINKERD2_DIR" && bin/root-tag)
controller_image=cr.l5d.io/linkerd/controller:$tag
proxy_image=cr.l5d.io/linkerd/proxy:$tag
if [ -z "${SKIP_LINKERD_BUILD:-}" ]; then
  "$root/hack/build-linkerd-images.sh" "$tag" "$LINKERD2_DIR" "$LINKERD2_PROXY_DIR" "$LINKERD_BASE_TAG"
fi
kind load docker-image --name "$CLUSTER" "$controller_image" "$proxy_image"

step "pgppi image $PGPPI_IMAGE"
docker build -t "$PGPPI_IMAGE" "$root"
kind load docker-image --name "$CLUSTER" "$PGPPI_IMAGE"

step "cert-manager $CERT_MANAGER_VERSION"
k apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
k -n cert-manager rollout status deploy --timeout=180s

step "Linkerd $tag"
linkerd=("$LINKERD2_DIR/bin/linkerd" --context "$ctx")
"${linkerd[@]}" install --crds --set installGatewayAPI=true | k apply --server-side -f -
"${linkerd[@]}" install | k apply -f -
"${linkerd[@]}" check --wait 5m

step "CloudNativePG $CNPG_VERSION"
k apply --server-side -f \
  "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-${CNPG_VERSION%.*}/releases/cnpg-$CNPG_VERSION.yaml"
k -n cnpg-system rollout status deploy/cnpg-controller-manager --timeout=180s

step "pgppi CNPG-I plugin"
k apply -k "$root/deploy/plugin"
k -n cnpg-system wait certificate --all --for=condition=Ready --timeout=120s
k -n cnpg-system rollout restart deploy/pgppi
k -n cnpg-system rollout status deploy/pgppi --timeout=120s

step "example Cluster and clients"
k apply -f "$root/examples/cluster.yaml"
k apply -f "$root/examples/clients.yaml"
# The Cluster only becomes Ready once the plugin-injected instance pod is up.
k -n db wait cluster/pg --for=condition=Ready --timeout=600s
k -n billing rollout status deploy --timeout=300s

step "ready"
k -n db get pods -o wide
echo
echo "Run the tests with: make e2e"
