# pg-ppi: PostgreSQL PROXY-protocol identity

Log in to PostgreSQL **as your Linkerd workload identity**, with no passwords.

This example builds on two in-progress Linkerd changes:

- [linkerd/linkerd2#15676](https://github.com/linkerd/linkerd2/pull/15676): the
  `config.linkerd.io/proxy-protocol-v2-inbound-ports` annotation, rendered as
  `LINKERD2_PROXY_INBOUND_PORTS_PROXY_PROTOCOL_V2` on the proxy.
- [linkerd/linkerd2-proxy#4625](https://github.com/linkerd/linkerd2-proxy/pull/4625):
  for those ports, the inbound proxy prepends a PROXY protocol v2 header to the
  connection to the app, with the verified mTLS client identity in TLV `0xE0`.

`pgppi` is a sidecar that sits between the Linkerd proxy and PostgreSQL. It
turns that header into a PostgreSQL login, and a CloudNativePG CNPG-I plugin
injects it into every instance pod.

```
 billing pod (SA billing)                    pg-1 pod (CloudNativePG instance)
┌──────────────────────┐   mTLS   ┌──────────────────────────────────────────────────────────┐
│ psql user=billing_app├─────────►│ linkerd-proxy ──PPv2{id}──► pgppi ──TLS+cert(CN=id)──► postgres│
│   └─ linkerd-proxy   │          │  :4143             pod IP:15432   127.0.0.1:5432              │
└──────────────────────┘          └──────────────────────────────────────────────────────────┘
                                                                        pg_hba: cert map=linkerd
                                                                        pg_ident: id → billing_app
```

## How it works

1. The Linkerd inbound proxy terminates mTLS and writes a PROXY v2 header
   before any client bytes. TLV `0xE0` holds the client identity, e.g.
   `billing.billing.serviceaccount.identity.linkerd.cluster.local`.
2. pgppi reads and strips the header. It declines the client's `SSLRequest`
   (Linkerd already encrypted the network hop) and reads the `StartupMessage`.
3. pgppi opens a **TLS** connection to PostgreSQL on loopback. It presents a
   short-lived client certificate with **CN = the Linkerd identity**, signed
   on the fly with the cluster's client CA (the one PostgreSQL uses as
   `ssl_ca_file`).
4. PostgreSQL authenticates with `hostssl … cert map=linkerd`, and
   **`pg_ident.conf` decides which roles that identity may log in as**.
   pgppi then just splices bytes in both directions.

### Why client certificates instead of `trust` or `SET ROLE`

The design in the original notes doesn't hold up, for two reasons:

- **`trust` ignores `map=`.** User-name maps only apply to `ident`, `peer`,
  `cert`, `gss` and `sspi`. A `host … 127.0.0.1/32 trust` line lets *any*
  loopback client log in as *any* role, including the Linkerd proxy
  forwarding raw traffic from port 5432. Also, CloudNativePG puts
  `local all all peer map=local` first, so a Unix-socket rule never matches.
- **`SET ROLE` can be undone.** A gateway role that runs `SET ROLE billing_app`
  on the client's behalf has to be a member of every application role. The
  client can then run `RESET ROLE` or `SET ROLE reporting_app`.

With `cert map=`, PostgreSQL enforces the mapping, the session is a real
login as the target role, and nothing without a valid client certificate can
match the rule.

## Layout

| Path | What |
| --- | --- |
| `cmd/pgppi` | Single binary: `pgppi proxy` (sidecar) and `pgppi plugin` (CNPG-I) |
| `internal/proxyproto` | PROXY v2 parser, checked against the proxy's golden encoding |
| `internal/pgwire` | Startup-phase messages: SSLRequest, StartupMessage, CancelRequest, ErrorResponse |
| `internal/certs` | Per-identity client certificate minting, cached, reloads a rotated CA |
| `internal/proxy` | The sidecar server |
| `internal/plugin` | CNPG-I identity, operator (validation) and lifecycle (pod patch) services |
| `deploy/plugin` | Plugin Deployment/Service and cert-manager certs for operator↔plugin mTLS |
| `examples` | Example `Cluster` with `pg_hba`/`pg_ident`, client Service, psql clients |
| `test/integration` | pgppi against real PostgreSQL in Docker (the test plays the Linkerd proxy) |
| `test/e2e`, `hack/` | kind + Linkerd (built from the PR branches) + CloudNativePG end to end |

## The plugin

Add the plugin to a `Cluster` (see [`examples/cluster.yaml`](examples/cluster.yaml)):

```yaml
spec:
  plugins:
  - name: pgppi.daniel-garcia.github.io
    parameters:
      port: "15432"        # sidecar port (default 15432)
      userMode: client     # or "identity"
      allowReplication: logical  # none (default) | logical | all
      # image: ...         # default: PGPPI_SIDECAR_IMAGE on the plugin Deployment
      # linkerd: "true"    # annotate instance pods for Linkerd (default true)
      # logLevel: info
  postgresql:
    pg_hba:
    - hostssl all all 127.0.0.1/32 cert map=linkerd
    - hostssl all all ::1/128      cert map=linkerd
    pg_ident:
    - linkerd billing.billing.serviceaccount.identity.linkerd.cluster.local billing_app
```

For **instance pods only** (the initdb/join Jobs are left alone, so they
aren't blocked by a proxy that never exits), the lifecycle hook:

- adds the `pgppi` container, listening on `$(POD_IP):15432`;
- mounts the client CA (`ca.crt`, `ca.key`) and server CA (`ca.crt`). It
  uses the names from `status.certificates`; by default that's
  `<cluster>-ca` for both;
- sets `linkerd.io/inject: enabled`,
  `config.linkerd.io/opaque-ports: 5432,15432` and
  `config.linkerd.io/proxy-protocol-v2-inbound-ports: 15432`.

`userMode: identity` ignores the requested user and logs in as the
ServiceAccount name. Pair it with a regex map:

```
linkerd /^([a-z0-9-]+)\.shop\.serviceaccount\.identity\.linkerd\.cluster\.local$ \1
```

## Replication (Debezium and other CDC tools)

`allowReplication` controls which walsender connections pgppi forwards. The
`replication` startup parameter is parsed exactly as PostgreSQL parses it.

| Value | Forwards | Also needed in PostgreSQL |
| --- | --- | --- |
| `none` (default) | ordinary connections only | nothing |
| `logical` | `replication=database`: Debezium, pglogrepl, subscriptions | a role with `REPLICATION`, a `pg_ident` entry, `wal_level: logical`, a publication |
| `all` | also physical (`replication=true`): `pg_receivewal`, `pg_basebackup` | as above, plus `hostssl replication all 127.0.0.1/32 cert map=linkerd` in `pg_hba` |

Forwarding a connection doesn't authorize it; PostgreSQL still decides. In
the tests, a `NOREPLICATION` role is refused a walsender with `42501`, and an
identity without a `pg_ident` entry for the CDC role is refused with `28000`.
The default is `none` because a role with `REPLICATION` can read every change
in its database through a slot, whatever its table grants.

Physical replication goes further: it streams the **whole cluster**, every
database plus `pg_authid`. Only enable `all` for identities you'd trust with
a full copy of the data. It works because `all` in `pg_hba`'s database
column never matches physical replication. Only the explicit `replication`
line does, and CNPG's own `streaming_replica` rule wants
CN=`streaming_replica`, which pgppi can never mint.

Point Debezium at the pgppi Service with no password, from a meshed pod
whose identity is mapped to the CDC role:

```properties
database.hostname=pg-pgppi.db.svc.cluster.local
database.port=15432
database.user=cdc
database.dbname=app
database.sslmode=disable
plugin.name=pgoutput
publication.name=invoices_pub
```

## Security model and caveats

- **Trust boundary is the instance pod.** Linkerd delivers traffic to the pod
  IP, not loopback, so pgppi binds to the pod IP. A process on `127.0.0.1`
  can't reach it to forge a header. Other containers in the pod (PostgreSQL,
  the instance manager) are already fully privileged over the database.
- **pgppi holds the client CA key**, so it could mint any CN. It only mints
  names shaped like Linkerd identities
  (`<sa>.<ns>.serviceaccount.identity.<…>`). Those can never collide with
  CloudNativePG's own CNs such as `streaming_replica`. If you want a narrower
  blast radius, give the cluster a dedicated `spec.certificates.clientCASecret`.
- **No identity, no connection.** Connections without a PROXY header, `LOCAL`
  headers, headers without TLV `0xE0` (unmeshed or non-mTLS clients),
  replication connections the `allowReplication` policy doesn't cover, and
  direct TLS (`sslnegotiation=direct`) are all rejected with a PostgreSQL
  `FATAL` error.
- Consider adding a Linkerd `Server` + `AuthorizationPolicy` on port 15432 that
  requires mesh identities, so unmeshed traffic is refused at the proxy.
- Clients still see `sslmode=prefer` behavior: pgppi answers `N` to
  `SSLRequest`. Use `sslmode=disable` or `prefer`, not `require`.
- `pg_stat_ssl.client_dn` is truncated to 63 bytes. Authentication and
  `pg_ident` matching use the full CN.
- Connecting straight to `pg-rw:5432` still works with normal password auth.
  pgppi adds a path; it doesn't remove the existing one.

## Running the tests

```sh
make test          # unit tests
make integration   # needs Docker; real PostgreSQL 17 with cert auth + pg_ident
make e2e-setup     # kind + cert-manager + Linkerd from ../../linkerd/{linkerd2,linkerd2-proxy}
make e2e           # psql from meshed/unmeshed clients through the injected sidecar
make e2e-down
```

`hack/e2e-setup.sh` builds `cr.l5d.io/linkerd/{controller,proxy}:<root-tag>`
from `LINKERD2_DIR` and `LINKERD2_PROXY_DIR`, loads both into kind, and
installs with that checkout's `bin/linkerd`. Set `SKIP_LINKERD_BUILD=1` to
reuse images you've already built.

Linkerd's `ghcr.io/linkerd/dev` build images are amd64-only. On arm64 hosts,
[`hack/build-linkerd-images.sh`](hack/build-linkerd-images.sh) takes a
different route:

- it cross-compiles the Go controller and layers it over the released
  `controller:edge-26.9.1`, keeping that image's policy-controller;
- it compiles the proxy natively in a `rust:<toolchain>` arm64 container and
  layers it over `proxy:edge-26.9.1`.

On Rancher Desktop, kind nodes fail to boot with "Too many open files". To
fix it, raise the VM's limits:
`rdctl shell sudo sysctl -w fs.inotify.max_user_instances=8192 fs.inotify.max_user_watches=1048576`.

The e2e suite checks that:

- the instance pod has `postgres`, `pgppi` and `linkerd-proxy`, and the proxy
  has `LINKERD2_PROXY_INBOUND_PORTS_PROXY_PROTOCOL_V2=15432`;
- `billing` can log in as `billing_app` and `reporting` as `reporting_app`,
  with their grants;
- these are rejected: claiming another identity's role, `postgres`, or `app`;
  an unmapped ServiceAccount; an unmeshed pod (even one using the `billing`
  ServiceAccount); bypassing pgppi without a password;
- after login, `SET ROLE`, `SET SESSION AUTHORIZATION` and `CREATE` in
  `public` all fail;
- the `cdc` identity opens a logical walsender and creates a `pgoutput` slot.
  A `NOREPLICATION` role, an identity claiming `cdc`, and physical
  replication (under the `logical` policy) are all refused.
