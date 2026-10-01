IMAGE ?= ghcr.io/daniel-garcia/pg-ppi:dev

.PHONY: build test integration image e2e-setup e2e e2e-down

build:
	go build -o bin/pgppi ./cmd/pgppi

# Unit tests (no external dependencies).
test:
	go test -race ./...

# pgppi against a real PostgreSQL in Docker, with cert auth + pg_ident.
integration:
	go test -tags integration -count=1 -v ./test/integration/

image:
	docker build -t $(IMAGE) .

# kind + cert-manager + Linkerd (from local branches) + CloudNativePG + plugin.
e2e-setup:
	PGPPI_IMAGE=$(IMAGE) hack/e2e-setup.sh

e2e:
	go test -tags e2e -count=1 -v ./test/e2e/

e2e-down:
	hack/e2e-teardown.sh
