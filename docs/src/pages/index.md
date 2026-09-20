---
title: Choose your path
pageTitle: pgroles - Declarative PostgreSQL role management
description: One YAML file. Every role, grant, and privilege in your database — defined, diffed, and applied.
---

## Try pgroles

{% quick-links %}

{% quick-link title="CLI quick start" icon="installation" href="/docs/quick-start" description="Install pgroles and run your first diff against a live database." /%}

{% quick-link title="Operator quick start" icon="plugins" href="/docs/operator-quick-start" description="Install the Kubernetes operator, review a first plan, and verify the result." /%}

{% /quick-links %}

## Bring an existing database under management

Start with [staged adoption](/docs/adoption) and check [executor prerequisites](/docs/executor-privileges). Additive mode lets you introduce declared access before deciding which undeclared access to remove.

## Review a policy or plan

{% quick-links %}

{% quick-link title="Open the explorer" icon="presets" href="/docs/explorer" description="Validate a policy, compare a caller-sanitized snapshot, or import a recorded native review locally in your browser." /%}

{% quick-link title="Review a native plan" icon="installation" href="/docs/recorded-reviews" description="Export one CLI planning run and review its recorded changes, findings, and evidence without database access." /%}

{% /quick-links %}

{% callout type="note" title="New to PostgreSQL permissions?" %}
[Learn PostgreSQL roles](/docs/learn-postgresql) through interactive exercises covering roles, ownership, default privileges, and row security. Start at the beginning or jump to the topic you need.
{% /callout %}

## Why pgroles?

Record intended access in a version-controlled policy, review the SQL it produces, and reconcile the scope you manage. The [policy guide](/docs/manifest-format) explains how the pieces fit together.

## Key features

Use [profiles and schemas](/docs/profiles) to reuse privilege rules, [default privileges](/docs/default-privileges) to cover future objects, and [planning and reconciliation modes](/docs/planning) to choose which changes pgroles may make.
