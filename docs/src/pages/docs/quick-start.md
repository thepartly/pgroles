---
title: CLI quick start
description: Install pgroles and run your first manifest against a PostgreSQL database.
---

Get up and running with pgroles in a few minutes. {% .lead %}

---

## Prerequisites

- **PostgreSQL 16, 17, or 18** — the versions supported and tested in CI
- A disposable database named `mydb`, with a table in `public` and an administrator connection for this exercise

## Installation

Download the binary for your platform from the [latest stable release](https://github.com/thepartly/pgroles/releases/latest), then verify `pgroles --version`. See [installation](/docs/installation) for containers and Cargo.

{% callout type="note" title="Starting from an existing database?" %}
Use `pgroles generate --database-url ... > pgroles.yaml` first, then refine the generated flat manifest into profiles and schema bindings.
{% /callout %}

## Create a manifest

Before typing any YAML, here is the role graph the manifest below describes — a single login role with read-only access to one schema.

{% role-graph-diagram /%}

If schema `USAGE`, table `SELECT`, and membership still feel like separate pieces, start with [The permission chain](/docs/postgresql-access-model), then return here to apply the model.

Create a file called `pgroles.yaml`:

```yaml
roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: public }
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
```

## Validate the manifest

Check the manifest is valid without connecting to a database:

```shell
pgroles validate
```

```
Manifest is valid.
  1 role(s) defined
  3 grant(s) defined
  0 default privilege(s) defined
  0 membership(s) defined
```

## Plan changes

See what SQL would be generated against a live database:

```shell
pgroles diff --mode additive --database-url postgres://localhost/mydb
```

This shows the exact SQL statements needed to converge the database to match your manifest.

{% callout title="No changes are made" %}
The `diff` command (also available as `plan`) is read-only. It connects to your database to inspect the current state but does not execute any changes.

{% explorer-scenario scenario="acme-adoption" /%}
{% /callout %}

## Apply changes

When you're happy with the plan, apply it:

```shell
pgroles apply --mode additive --database-url postgres://localhost/mydb
```

Or preview without executing:

```shell
pgroles apply --mode additive --database-url postgres://localhost/mydb --dry-run
```

## Using environment variables

Instead of passing `--database-url` every time, set the `DATABASE_URL` environment variable:

```shell
export DATABASE_URL=postgres://localhost/mydb
pgroles diff --mode additive
pgroles apply --mode additive
```

## Verify the result

Run the same additive diff again; it should print `-- No changes needed`. This proves convergence within additive mode, which leaves undeclared access untouched. Continue with [staged adoption](/docs/adoption) before enabling revocations on an existing database.
