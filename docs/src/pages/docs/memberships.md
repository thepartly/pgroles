---
title: Memberships
description: Manage role membership and inheritance with pgroles.
---

Memberships declare which roles are members of other roles, allowing privilege inheritance and role-based access patterns. {% .lead %}

---

## Syntax

```yaml
memberships:
  - role: inventory-editor
    members:
      - name: app-service
      - name: "deploy@example.com"
        admin: true
```

{% explorer-scenario scenario="acme-membership-bridge" /%}

## Member options

| Field | Default | Description |
|---|---|---|
| `name` | *required* | The member role name |
| `inherit` | `true` | Whether the member inherits the role's privileges (omit for default) |
| `admin` | `false` | Whether the member can grant the role to others (omit for default) |

Both `inherit` and `admin` can be omitted entirely — they default to `true` and `false` respectively. Omitting default values is recommended because it keeps the Kubernetes resource minimal and avoids perpetual diffs in GitOps tools like ArgoCD.

PostgreSQL has one role primitive: `LOGIN` makes a role connectable, while a `NOLOGIN` role is commonly used as a capability group or owner. Read `role: inventory-editor` with `name: app-service` as “app-service is a member of inventory-editor”; privileges flow from the granted role to the member.

## Generated SQL

On supported PostgreSQL versions, pgroles generates per-membership options:

```sql
GRANT "inventory-editor" TO "app-service" WITH INHERIT TRUE;
GRANT "inventory-editor" TO "deploy@example.com" WITH INHERIT TRUE, ADMIN TRUE;
```

Per-membership `INHERIT` requires PostgreSQL 16 or later. See
[installation compatibility](/docs/installation#compatibility) for the
currently supported server versions.

PostgreSQL 16 also records a separate `SET` option on each membership. pgroles does not currently inspect or converge that option. A membership created by pgroles receives PostgreSQL's default `SET TRUE`. An existing `SET FALSE` edge may appear to match, but if pgroles changes `inherit` or `admin` it revokes and recreates the membership without a `SET` clause, restoring `SET TRUE`. Do not rely on `SET FALSE` remaining intact on a pgroles-managed edge. See [Membership mechanics](/docs/postgresql-role-hierarchy).

Role attributes such as `CREATEDB`, `CREATEROLE`, and `BYPASSRLS` are not inherited like object privileges. A member must normally `SET ROLE` to use an attribute on the granted role.

## Flag changes

If a membership exists but the `inherit` or `admin` flags differ from the manifest, pgroles generates a `REVOKE` followed by a new `GRANT` with the correct flags. Because `apply` is transactional, that temporary remove-and-re-add sequence does not leave the database half-updated if execution fails.

## Convergent behavior

Memberships in the database that are not declared in the manifest will be revoked. Only declare memberships that pgroles should manage.

Two kinds of granted role follow a gentler rule — see the next section.

## Predefined and external granted roles

A membership stanza may name one of PostgreSQL's predefined roles (`pg_read_all_data`, `pg_monitor`, ...) directly — no `roles:` entry is needed, and declaring one under `roles:` requires `external: true` because its lifecycle can never be managed. Memberships granted from predefined roles and from `external: true` roles converge differently from ordinary memberships:

- **Declared members converge**: they are granted, and re-granted when their `inherit`/`admin` options change.
- **Undeclared live members are left untouched by default**, so adopting pgroles never strips memberships a cloud platform granted to its own management roles (for example `pg_monitor` grants on RDS or Cloud SQL).
- **`exclusive: true`** on the stanza asserts the member list is complete: any live member not listed is planned for `REVOKE` — including cloud-provider management roles such as `rds_superuser`, so only assert exclusivity once you have accounted for every member the platform needs. It is rejected on ordinary managed roles, whose memberships are already reconciled exhaustively, and a bundle rejects an exclusive member list split across policy documents.
- **Exception: members that are themselves predefined roles are never revoked**, even under `exclusive: true`. PostgreSQL ships built-in `pg_*` → `pg_*` edges (for example `pg_monitor` is a member of `pg_read_all_stats`), and revoking those would break the built-in hierarchy cluster-wide. An exclusive stanza therefore asserts the complete list of *ordinary* members; the built-in hierarchy stays intact and is not planned for revocation.

```yaml {% schema="pgroles-manifest" policy="fragment" %}
roles:
  - name: auditor
    login: true

memberships:
  - role: pg_read_all_data
    exclusive: true
    members:
      - name: auditor
```

Like every absence assertion (`ensure: absent` included), `exclusive: true` revocations are skipped under additive reconciliation — the plan prints a warning when that happens; use adopt or authoritative mode to enforce the assertion.

Granting or revoking a predefined role requires the executor to hold `ADMIN OPTION` on it — in PostgreSQL 16+ that effectively means a superuser executor or an explicit `GRANT pg_read_all_data TO executor WITH ADMIN OPTION`; `CREATEROLE` alone is not sufficient. The plan preflight warns (and apply blocks) when that authority is missing, and when a manifest references a predefined role the connected server does not have yet (naming the PostgreSQL version that introduced it).

## Common patterns

### Service account inherits a profile role

```yaml
roles:
  - name: app-service
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: app-service
```

### Blue/green login roles sharing an owner role

For zero-downtime password rotation, two login roles alternate as the application credential while a shared NOLOGIN role owns all objects. Combining membership with a [`config.role` setting](/docs/manifest-reference#role-configuration-defaults) makes PostgreSQL `SET ROLE` at connect time, so objects created under either credential are owned by the shared role:

```yaml
roles:
  - name: combined
  - name: blue
    login: true
    config:
      role: combined
  - name: green
    login: true
    config:
      role: combined

memberships:
  - role: combined
    members:
      - name: blue
      - name: green
```

Without the membership, PostgreSQL would reject the `role` setting at login — pgroles validates the pair at manifest-validation time. See [examples/zero-downtime-password-rotation.yaml](https://github.com/thepartly/pgroles/blob/main/examples/zero-downtime-password-rotation.yaml) for a complete manifest.

### Email-based roles (e.g. IAM authentication)

PostgreSQL roles can have names like email addresses. pgroles handles quoting automatically:

```yaml
memberships:
  - role: inventory-editor
    members:
      - name: "alice@company.com"
      - name: "bob@company.com"
        admin: true
```
