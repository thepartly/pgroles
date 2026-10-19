---
title: Database connections
description: Point the operator at a database with a connection URL or structured parameters, including cloud IAM authentication.
---

How the operator finds and authenticates to your database. {% .lead %}

---

## Database connection

The operator supports two connection modes: a single connection URL from a Secret, or structured parameters with separate fields for host, port, database, and credentials.

### Connection URL (single Secret)

Create a Secret containing your PostgreSQL connection string. Read the value
interactively so a password-bearing URL does not enter shell history or the
process list:

```bash
umask 077
read -rsp 'Database URL: ' DATABASE_URL && printf '\n'
printf '%s' "$DATABASE_URL" > db-url
unset DATABASE_URL
kubectl create secret generic mydb-credentials \
  --from-file=DATABASE_URL=db-url
rm db-url
```

In production, prefer a secret manager or CSI driver over creating the Secret
by hand.

Reference it in the policy:

```yaml
connection:
  secretRef:
    name: mydb-credentials
  secretKey: DATABASE_URL  # optional, defaults to DATABASE_URL
```

When the Secret's `resourceVersion` changes (e.g. credential rotation), the operator automatically reconnects with updated credentials.

### Structured parameters

Use `connection.params` to build the connection from individual fields. Each field is either a literal value or a reference to a key in a Kubernetes Secret. This integrates natively with PostgreSQL operators that create credential Secrets (Zalando, CloudNativePG, CrunchyData PGO).

**Zalando postgres-operator** — credentials in a Secret, host/port/database as literals:

```yaml
connection:
  params:
    host: my-cluster-postgres              # K8s service name (namespace-relative)
    port: 5432
    dbname: mydb
    sslMode: require
    usernameSecret:
      name: postgres.my-cluster-postgres.credentials.postgresql.acid.zalan.do
      key: username
    passwordSecret:
      name: postgres.my-cluster-postgres.credentials.postgresql.acid.zalan.do
      key: password
```

**CloudNativePG / CrunchyData PGO** — all fields from the operator-created Secret:

```yaml
connection:
  params:
    hostSecret:
      name: cluster-example-app
      key: host
    dbnameSecret:
      name: cluster-example-app
      key: dbname
    usernameSecret:
      name: cluster-example-app
      key: user
    passwordSecret:
      name: cluster-example-app
      key: password
```

Each connection field supports a literal value and a `*Secret` variant:

| Field | Literal | Secret | Required |
|---|---|---|---|
| `host` / `hostSecret` | Hostname string | SecretKeySelector | Yes (exactly one) |
| `port` / `portSecret` | Integer (default 5432) | SecretKeySelector | No |
| `dbname` / `dbnameSecret` | Database name | SecretKeySelector | Yes (exactly one) |
| `username` / `usernameSecret` | Username string | SecretKeySelector | Yes (exactly one) |
| `password` / `passwordSecret` | Password string | SecretKeySelector | Yes unless `auth` is set |
| `auth` | Provider-backed auth config (`type`, `scope`, `impersonateServiceAccount`) | n/a | No |
| `setRole` | Role to `SET ROLE` to on every operator connection | n/a | No |
| `sslMode` / `sslModeSecret` | SSL mode string | SecretKeySelector | No |

Valid `sslMode` values: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`.

For required fields, exactly one of the literal or Secret variant must be set. For optional fields, at most one may be set. When a Secret referenced by `params` changes, the operator detects the `resourceVersion` change and reconnects automatically.

### GKE Workload Identity for Cloud SQL IAM

Use `connection.params.auth.type: gcp_workload_identity` when the operator pod runs on GKE with Workload Identity and connects to Cloud SQL using IAM database authentication. The operator fetches a short-lived OAuth token from the GKE metadata server and uses it as the PostgreSQL password. `password` and `passwordSecret` must be omitted. If `sslMode` is omitted, the operator uses `require`.

```yaml
connection:
  params:
    host: 10.0.0.5
    port: 5432
    dbname: discovery
    username: pgroles-operator@my-project.iam
    auth:
      type: gcp_workload_identity
      # Optional: impersonate a different GCP service account.
      impersonateServiceAccount: target-sa@other-project.iam.gserviceaccount.com
      # Optional: defaults to https://www.googleapis.com/auth/sqlservice.login
      scope: https://www.googleapis.com/auth/sqlservice.login
```

The Kubernetes ServiceAccount used by the operator must be annotated for Workload Identity — set `operator.serviceAccount.annotations` in the chart — and the Google service account must have Cloud SQL IAM database login permissions for the target instance.

An IAM identity usually has too few privileges to manage roles itself. Use
`connection.params.setRole` to authenticate as the low-privilege IAM identity
and switch to a privileged parent role on every connection:

```yaml
connection:
  params:
    username: pgroles-operator@my-project.iam
    setRole: pgroles_admin
    auth:
      type: gcp_workload_identity
```

The IAM identity must be a member of the target role. `setRole` accepts
`^[A-Za-z_][A-Za-z0-9_$-]*$` — deliberately excluding `@` and `.`, so an IAM
principal name such as `sa@project.iam` is rejected. Name the PostgreSQL group
role to switch into, not the identity you authenticate as. See
[executor privileges](/docs/executor-privileges) for what that role needs.

### AKS Workload Identity for Azure PostgreSQL Flexible Server

Use `connection.params.auth.type: azure_workload_identity` for Microsoft Entra
authentication. The operator reads the projected AKS service account assertion,
exchanges it for the PostgreSQL resource scope, and uses the short lived access
token as the PostgreSQL password. It refreshes the token and connection pool
before expiry. No PostgreSQL password Secret is required. `password` and
`passwordSecret` are rejected in this mode; omitted `sslMode` defaults to
`verify-full` so the server certificate and hostname are checked.

The Entra identity comes from the operator pod environment and is shared by all
Azure policies handled by that operator. Per-policy impersonation is not
supported; use separate operator deployments when different Entra identities
are needed. `scope` and `impersonateServiceAccount` are GCP-only fields and are
rejected for Azure authentication.

```yaml
operator:
  serviceAccount:
    annotations:
      azure.workload.identity/client-id: <managed-identity-client-id>
  podLabels:
    azure.workload.identity/use: "true"
```

```yaml
connection:
  params:
    host: myserver.postgres.database.azure.com
    dbname: postgres
    username: pgroles-operator
    auth:
      type: azure_workload_identity
```

Configure the AKS federated identity credential, [enable Entra authentication](https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-configure)
on the Flexible Server, and [create/map the Entra principal](https://learn.microsoft.com/en-us/azure/postgresql/security/security-connect-with-managed-identity#create-an-azure-database-for-postgresql-user-for-your-managed-identity)
as a PostgreSQL role before reconciliation. The pod needs `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE`, injected by the AKS
Workload Identity webhook. Treat the Entra role as externally owned in policy:

```yaml
roles:
  - name: pgroles-operator
    external: true
```

`external: true` leaves role creation, attributes, password, and deletion to
Azure, while declared memberships and grants can still refer to that role.
Use a separate PostgreSQL role and `setRole` if the login identity needs the
executor privileges described in [executor privileges](/docs/executor-privileges).

Azure can attribute automatic creator ADMIN memberships to `azuresu`. pgroles
keeps the executor's own ADMIN memberships without them being declared; see
[executor privileges](/docs/executor-privileges). Other members' `azuresu`
memberships are reconciled like any other, so declare their live options to keep
them; see [memberships](/docs/memberships). On PostgreSQL 16+, a plan that
creates a role and also declares the executor as its member with `admin: true`
fails with `ADMIN option cannot be granted back to your own grantor`. Create the
role first, then add that membership in a later reconcile. Treat this
SQL-authority constraint separately when validating token authentication and
policy convergence.

The operator reads its Azure configuration once at startup and reuses its HTTP
client. It re-reads the projected assertion on every token exchange.
`AZURE_AUTHORITY_HOST` can override the default `https://login.microsoftonline.com/`
with an HTTPS authority origin. Restart the operator after changing its identity
or authority configuration.

The CLI supports the same projected identity with
`pgroles diff --auth azure-workload-identity --database-url 'postgres://pgroles-operator@myserver.postgres.database.azure.com/postgres?sslmode=verify-full'`.
The flag also applies to `apply`, `inspect`, `generate`, and current-state
`graph`; omit a password from the connection URL. The CLI obtains a fresh
access token for each invocation.

{% callout type="note" title="Host resolution" %}
The `host` must be reachable from the operator pod. For an in-cluster database in a different namespace, use the fully qualified service name (e.g. `my-postgres.my-namespace.svc`). For a database outside the cluster, use the external hostname or IP directly (e.g. `db.example.com` or `10.0.1.50`).
{% /callout %}
