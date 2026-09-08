---
title: Application access patterns
description: How pgroles fits beside schema ownership, service roles, team roles, and multi-file bundles.
---

Use pgroles as the PostgreSQL access-control layer next to your existing application and schema lifecycle. {% .lead %}

Most stacks already have a way to create tables, indexes, functions, and application metadata. Keep that path responsible for schema DDL. Let pgroles own PostgreSQL roles, memberships, grants, default privileges, passwords, and retirements.

---

## The boundary

pgroles is intentionally not a schema migration framework. It does not create tables, rewrite indexes, manage row-level security policies, or replace application migration history.

The clean split is:

| Layer | Owner |
| --- | --- |
| Database infrastructure | Instance, networking, database creation, platform IAM |
| Schema lifecycle | Tables, views, functions, types, extensions, triggers, queues, event triggers |
| Access control | Roles, memberships, grants, default privileges, passwords, retirements |
| Runtime connections | Service-specific login roles with only the privileges they need |

This avoids the common failure mode where application bootstrap scripts, deployment jobs, and operators all issue their own `GRANT` statements.

## Recommended order

For each environment, converge access control after the database exists and before application traffic relies on new privileges:

```shell
# 1. Apply schema changes with the service's schema-owner role.
./service-migrate

# 2. Preview and apply role and privilege policy.
pgroles diff -f pgroles.yaml --database-url "$DATABASE_URL"
pgroles apply -f pgroles.yaml --database-url "$DATABASE_URL"

# 3. Deploy or restart application workloads.
```

If schema changes create new objects in an already-managed schema, pgroles has two safety nets:

- wildcard grants cover objects that already exist when pgroles runs
- default privileges cover future objects created by the configured owner

If schema changes need a brand-new schema, either declare that schema in pgroles so pgroles creates it and converges its PostgreSQL owner, or create the schema first and then apply the pgroles policy that grants access to it.

## Role model

Prefer separate roles for distinct duties:

| Role type | Purpose |
| --- | --- |
| Schema-owner role | Runs schema changes and owns created objects |
| Runtime role | Serves normal application traffic |
| Worker role | Performs a narrower background-processing task |
| Read-only role | Reporting, analytics, support, or debugging |
| Team role | Grants human access through membership rather than direct grants |
| pgroles administrator | Runs pgroles with enough authority to converge the declared policy |

This makes privilege boundaries visible in one manifest instead of scattering them across connection strings and setup scripts.

## Schema-owned systems

Some PostgreSQL-backed libraries and platform features create their own tables, functions, triggers, queues, publications, or metadata schemas. Treat those as schema-owned systems:

1. give the owner or installer role enough privilege to create and upgrade its own objects
2. let that owner path create or upgrade the schema objects
3. use pgroles to grant narrower runtime and team roles access to the resulting objects
4. include default privileges for the owner/schema pair if future upgrades create more tables, sequences, or functions

Do not point pgroles at an internally managed schema and expect it to understand that system's upgrade invariants. pgroles manages privileges around those objects; the schema-owning system still owns its DDL.

pgroles preserves existing owner-grantee ACL entries on tables,
sequences, functions, and types; declaring those grants is not needed to prevent
pgroles revoking them. PostgreSQL itself permits owners to revoke their ordinary
privileges, and pgroles can grant missing declared privileges back. Schema ownership also ensures effective `CREATE` and `USAGE` on the
schema. Owning a schema does not imply ownership of its contents: declare grants
or memberships for access to objects owned by another role, and default
privileges for each role that creates future objects.

## Bundles for teams

For one application, a single manifest is often enough. For a shared database with multiple teams, use bundle mode so each team owns a scoped fragment:

```shell
pgroles validate --bundle pgroles.bundle.yaml
pgroles diff --bundle pgroles.bundle.yaml --database-url "$DATABASE_URL"
pgroles apply --bundle pgroles.bundle.yaml --database-url "$DATABASE_URL"
```

Bundle composition gives each fragment an explicit ownership boundary. If two fragments both try to manage the same role, schema facet, grant, default privilege, or membership selector, pgroles rejects the bundle before it connects to PostgreSQL.

Use bundle fragments for ownership boundaries such as:

- platform-owned team roles and human memberships
- one service-owned schema, migrator role, and runtime roles per service
- shared read-only roles or reporting access owned by the team that grants it

## Multi-service example

The repository includes an executable [multi-service bundle example](https://github.com/thepartly/pgroles/tree/main/examples/microservices) for a shared database with separate `billing` and `shipping` services.

It demonstrates the recommended split:

- `platform.yaml` owns team roles and human memberships
- `billing.yaml` owns billing roles, billing schema ownership, and billing grants
- `shipping.yaml` owns shipping roles, shipping schema ownership, and shipping grants
- each service has a migration role that owns its schema objects
- each service has separate runtime roles for API, worker, or reporting access
- human users inherit read access from team roles such as `team_payments` and `team_fulfillment`
- CI verifies that each runtime role can access its own schema and is denied access to the other service's schema

| Principal | Connects as | Scope |
| --- | --- | --- |
| Billing migrations | `billing_migrator` | Owns and migrates the `billing` schema |
| Billing API | `billing_api` | Reads, inserts, and updates billing tables |
| Billing worker | `billing_worker` | Reads and updates billing invoices, but cannot insert |
| Shipping migrations | `shipping_migrator` | Owns and migrates the `shipping` schema |
| Shipping API | `shipping_api` | Reads, inserts, and updates shipping tables |
| Shipping reports | `shipping_reports` | Read-only access to shipping tables |
| Payments engineers | `team_payments` membership | Read-only access to billing tables |
| Fulfillment engineers | `team_fulfillment` membership | Read-only access to shipping tables |

Run the example locally against a disposable database:

```shell
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
./scripts/test-microservices-example.sh
```

## Anti-patterns

- Do not grant broad runtime privileges just because schema changes need them. Split schema-owner and runtime credentials.
- Do not keep permanent `GRANT` policy in old setup scripts and also manage the same grants with pgroles. Pick pgroles as the source of truth once adopted.
- Do not depend on `PUBLIC` grants for application access. pgroles manages a `PUBLIC` privilege only where a rule names it, so anything you leave undeclared stays outside the manifest.
- Do not give CI or code generation jobs superuser access when read-only catalog/schema access is sufficient.
- Do not use one bundle fragment per file unless the scope boundary is real. Bundle files should reflect ownership, not just directory layout.
