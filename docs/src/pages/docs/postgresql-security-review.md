---
title: 9. The security review
description: "Audit effective access through PUBLIC, SECURITY DEFINER, delegation, and predefined roles."
---

An auditor asks a harder question than “what grants are in our YAML?”: **can this role actually perform the operation?** Acme’s role graph is tidy, but PostgreSQL has access paths outside ordinary named ACLs. {% .lead %}

Before changing anything, use the lab to identify the unexpected path, name the role or object that makes it possible, repair that path, and repeat the affected login's query as a negative test.

{% postgres-security-review-lab /%}

## Close the PUBLIC path explicitly

PostgreSQL gives `PUBLIC`—every role—`EXECUTE` on new functions by default. State both desired absences so existing and future functions converge:

```yaml {% schema="pgroles-manifest" %}
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: billing_api, name: "*" }

default_privileges:
  - owner: app_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
```

The global default matters because PostgreSQL’s built-in function default is global. A schema-scoped revoke cannot subtract a global grant.

## Review predefined roles by capability

[Predefined roles](https://www.postgresql.org/docs/18/predefined-roles.html) are memberships with privileged behavior outside ordinary object ACLs. Audit who holds them and what category of capability each one supplies:

- `pg_read_all_data` and `pg_write_all_data` are broad data-access roles for matching objects, but they do not bypass row-level security.
- `pg_monitor` groups `pg_read_all_settings`, `pg_read_all_stats`, and `pg_stat_scan_tables` for configuration, statistics, and observation; it is not a business-data ACL.
- `pg_signal_backend` can signal ordinary backends, but cannot signal superuser backends.
- `pg_database_owner` has exactly one implicit member, the current database owner, and membership in it cannot be granted.
- `pg_read_server_files`, `pg_write_server_files`, and `pg_execute_server_program` are high-risk server-file or program-execution capabilities.

No table-level ACL review will show these paths. Auditing effective access therefore includes one more question: who is a member of a `pg_*` role?

pgroles can declare memberships in a predefined role, including an explicit complete-member assertion. See [predefined and external granted roles](/docs/memberships#predefined-and-external-granted-roles) for the managed declaration and its adoption behavior.

## Capstone: prove the repair

The lab presents a path that is easy to miss: an ordinary login reaches a function through `PUBLIC`, a `SECURITY DEFINER` function runs with its owner's authority, or a delegated grant survives a cleanup by the wrong grantor. Explain that path before changing the YAML. Then remove the unexpected route, apply the plan, and repeat the same query as the affected login. The negative test must now fail.

A `SECURITY DEFINER` function needs review of its owner, body, fixed `search_path`, callable surface, and `PUBLIC` exposure. `WITH GRANT OPTION` needs separate review of who can delegate. See [memberships](/docs/memberships) and [grants](/docs/grants) for the managed declarations and their limits.

One more finding costs nothing to write down: Acme’s application still connects with the founder-era admin credentials, and a superuser bypasses every check in this chapter. No grant, policy, or RLS rule constrains that connection—pgroles cannot manage it away. Moving the application onto a scoped login, the way `reporting_app` was built in chapter 2, is the remediation an auditor will ask for first.

**Desired ACLs are necessary; effective-access tests tell you whether every other path agrees with them.**

{% quick-links %}
{% quick-link title="Open the Acme playground" description="Investigate the finished database with any role and any SQL." icon="lightbulb" href="/docs/postgresql-playground" /%}
{% quick-link title="Limits and boundaries" description="Review unmanaged column grants, grant options, and effective access." icon="plugins" href="/docs/limitations" /%}
{% /quick-links %}
