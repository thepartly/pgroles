---
title: PostgresPolicyCandidate
description: Generated field reference for the served v1alpha1 API.
---

[CRD API reference](/docs/operator-api-reference) · Served version `v1alpha1`.

Required fields apply when their containing object is present. Defaults shown are API-server defaults; null requires `nullable`. Standard metadata follows [Kubernetes conventions](https://kubernetes.io/docs/concepts/overview/working-with-objects/). Status is controller-owned except documented decisions.

For workflows, see [operator guidance](/docs/operator), [approval](/docs/operator-plan-approval), [candidates](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access).

## Spec

| Path | Definition |
| --- | --- |
| ` spec ` | **object; required.** A one-shot, immutable proposal of policy content.  The operator plans a candidate in its parent policy's execution context and publishes a &#96;PostgresPolicyPlan&#96; for review; the active policy keeps enforcing throughout. A candidate never executes SQL in any state, and its spec cannot be edited — revising a proposal means creating a successor that names the earlier one in &#96;spec.replaces&#96;.  See &#96;docs/src/pages/docs/operator-candidates.md&#96; for the behaviour and &#96;docs/design/adr-001-candidate-api.md&#96; for the API mechanics. **Constraints:** ` {"required":["content","policyRef"]} `. |
| ` spec ` | **CEL:** ` {"message":"candidate spec is immutable","rule":"self == oldSelf"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` spec.content ` | **object; required.** The proposed policy content. |
| ` spec.content.default_owner ` | **string; optional.** Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app&#95;owner"). **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.default_privileges ` | **array; optional.** One-off default privileges. **Constraints:** ` {"maxItems":512} `. |
| ` spec.content.default_privileges[] ` | **object; item or branch.** Default privilege configuration.  The scope rules are also expressed as CEL so the API server rejects a bad entry at apply time. &#96;resolved&#95;scope&#96; enforces the same rules for the CLI, which has no admission step. **Constraints:** ` {"required":["grant"]} `. |
| ` spec.content.default_privileges[] ` | **CEL:** `` {"message":"exactly one of `schema` and `scope` must be set","rule":"has(self.schema) != has(self.scope)"} ``. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` spec.content.default_privileges[].grant ` | **array; required.** Grantee, privileges, and future object kind to reconcile. **Constraints:** ` {"maxItems":64} `. |
| ` spec.content.default_privileges[].grant[] ` | **object; item or branch.** A single default privilege grant entry. **Constraints:** ` {"required":["on_type","privileges"]} `. |
| ` spec.content.default_privileges[].grant[].ensure ` | **string; optional.** Desired privilege state: present grants it; absent explicitly revokes it. **Constraints:** ` {"enum":["present","absent"]} `. |
| ` spec.content.default_privileges[].grant[].on_type ` | **string; required.** Kind of future object affected by the default privilege. **Constraints:** ` {"enum":["table","view","materialized_view","sequence","function","schema","database","type"]} `. |
| ` spec.content.default_privileges[].grant[].privileges ` | **array; required.** PostgreSQL privileges to reconcile on the selected objects. **Constraints:** ` {"maxItems":16,"minItems":1} `. |
| ` spec.content.default_privileges[].grant[].privileges[] ` | **string; item or branch.** PostgreSQL privilege types. **Constraints:** ` {"enum":["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","EXECUTE","USAGE","CREATE","CONNECT","TEMPORARY"]} `. |
| ` spec.content.default_privileges[].grant[].role ` | **string; optional.** The role receiving the default privilege. Only used in top-level default&#95;privileges (in profiles, the role is determined by expansion). The exact-uppercase value &#96;PUBLIC&#96; means the PostgreSQL PUBLIC pseudo-role. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.default_privileges[].owner ` | **string; optional.** The role that owns newly created objects. If omitted, uses manifest's default&#95;owner. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.default_privileges[].schema ` | **string; optional.** Schema shorthand, equivalent to &#96;scope: {type: schema, schema: ...}&#96;. Exactly one of &#96;schema&#96; and &#96;scope&#96; must be set. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.default_privileges[].scope ` | **object; optional.** Where the defaults apply: one schema, or owner-wide (global). Global scope renders &#96;ALTER DEFAULT PRIVILEGES&#96; without an &#96;IN SCHEMA&#96; clause. **Constraints:** ` {"nullable":true,"required":["type"]} `. |
| ` spec.content.default_privileges[].scope ` | **CEL:** `` {"message":"`schema` is required when type is `schema` and forbidden when type is `global`","rule":"has(self.schema) == (self.type == 'schema')"} ``. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` spec.content.default_privileges[].scope.schema ` | **string; optional.** Schema name. Required for &#96;type: schema&#96;, forbidden for &#96;type: global&#96;. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.default_privileges[].scope.type ` | **string; required.** Global or per-schema scope of the default privilege. **Constraints:** ` {"enum":["global","schema"]} `. |
| ` spec.content.grants ` | **array; optional.** One-off grants. **Constraints:** ` {"maxItems":4096} `. |
| ` spec.content.grants[] ` | **object; item or branch.** A concrete grant on a specific object or wildcard. **Constraints:** ` {"required":["object","privileges","role"]} `. |
| ` spec.content.grants[].ensure ` | **string; optional.** Desired object privilege state: present grants it; absent explicitly revokes it. **Constraints:** ` {"enum":["present","absent"]} `. |
| ` spec.content.grants[].object ` | **object; required.** Object kind and target to which the privileges apply. **Constraints:** ` {"required":["type"]} `. |
| ` spec.content.grants[].object ` | **CEL:** `` {"message":"database grant targets must set `name`","rule":"self.type != 'database' \|\| has(self.name)"} ``. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` spec.content.grants[].object.name ` | **string; optional.** Object name, or "&#42;" for all objects. Omit for schema-level grants; required for database grants, where it names the connected database. **Constraints:** ` {"maxLength":256,"minLength":1,"nullable":true} `. |
| ` spec.content.grants[].object.schema ` | **string; optional.** Schema name. Required for most object types except database. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.grants[].object.type ` | **string; required.** PostgreSQL object kind. **Constraints:** ` {"enum":["table","view","materialized_view","sequence","function","schema","database","type"]} `. |
| ` spec.content.grants[].privileges ` | **array; required.** PostgreSQL privileges to reconcile on the selected objects. **Constraints:** ` {"maxItems":16,"minItems":1} `. |
| ` spec.content.grants[].privileges[] ` | **string; item or branch.** PostgreSQL privilege types. **Constraints:** ` {"enum":["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","EXECUTE","USAGE","CREATE","CONNECT","TEMPORARY"]} `. |
| ` spec.content.grants[].role ` | **string; required.** The grantee. The exact-uppercase value &#96;PUBLIC&#96; means the PostgreSQL PUBLIC pseudo-role; any other value is an ordinary role name. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.memberships ` | **array; optional.** Membership edges. **Constraints:** ` {"maxItems":2048} `. |
| ` spec.content.memberships[] ` | **object; item or branch.** A membership declaration — which members belong to a role. **Constraints:** ` {"required":["members","role"]} `. |
| ` spec.content.memberships[].exclusive ` | **boolean; optional.** Assert that &#96;members&#96; is the complete membership of &#96;role&#96;: plan a REVOKE for any live member not listed here. Only meaningful for predefined (&#96;pg&#95;&#42;&#96;) and &#96;external: true&#96; roles, whose undeclared members are otherwise left untouched — memberships of ordinary managed roles are already reconciled exhaustively. Defaults to &#96;false&#96; so that adopting pgroles never strips provider-granted memberships (for example &#96;pg&#95;monitor&#96; grants made by a cloud platform) without an explicit assertion. |
| ` spec.content.memberships[].members ` | **array; required.** Roles that should receive this membership. **Constraints:** ` {"maxItems":512} `. |
| ` spec.content.memberships[].members[] ` | **object; item or branch.** A single member of a role.  Both &#96;inherit&#96; and &#96;admin&#96; are optional. When omitted, they default to &#96;inherit: true&#96; and &#96;admin: false&#96; at resolution time (in &#96;RoleGraph&#96; construction). Keeping them optional in the CRD avoids Kubernetes injecting default values into the stored resource, which causes perpetual diffs in GitOps tools like ArgoCD. **Constraints:** ` {"required":["name"]} `. |
| ` spec.content.memberships[].members[].admin ` | **boolean; optional.** Whether the member can administer the role. Defaults to &#96;false&#96;. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.memberships[].members[].inherit ` | **boolean; optional.** Whether the member inherits the role's privileges. Defaults to &#96;true&#96;. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.memberships[].members[].name ` | **string; required.** PostgreSQL role receiving the membership. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.memberships[].role ` | **string; required.** PostgreSQL role granted to the listed members. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.profiles ` | **object; optional.** Reusable privilege profiles.  A &#96;BTreeMap&#96; rather than the policy's &#96;HashMap&#96;: the content digest is computed over a canonical serialization, and deterministic iteration order is one less thing that has to be normalised later. **Constraints:** ` {"maxProperties":128} `. |
| ` spec.content.profiles.<name> ` | **object; item or branch.** A reusable privilege profile. |
| ` spec.content.profiles.<name>.config ` | **object; optional.** Role-level configuration parameter defaults for generated roles, applied via &#96;ALTER ROLE ... SET parameter = value&#96;. Values support the &#96;{schema}&#96; and &#96;{profile}&#96; placeholders, substituted per &#96;schema x profile&#96; expansion (e.g. &#96;search&#95;path: "{schema}"&#96;). **Constraints:** ` {"maxProperties":32} `. |
| ` spec.content.profiles.<name>.config.<name> ` | **string; item or branch.** A role configuration parameter value.  Values are always strings — quote numbers and booleans (e.g. &#96;statement&#95;timeout: "30000"&#96;, &#96;jit: "off"&#96;). The Kubernetes CRD schema types config values as strings, and the CLI enforces the same rule so a manifest means the same thing whether it is applied with &#96;pgroles&#96; or &#96;kubectl&#96;. PostgreSQL coerces the string to the parameter's type. **Constraints:** ` {"maxLength":256} `. |
| ` spec.content.profiles.<name>.default_privileges ` | **array; optional.** Privileges to grant on future objects created by the configured owner. **Constraints:** ` {"maxItems":32} `. |
| ` spec.content.profiles.<name>.default_privileges[] ` | **object; item or branch.** Default privilege grant within a profile. **Constraints:** ` {"required":["on_type","privileges"]} `. |
| ` spec.content.profiles.<name>.default_privileges[].ensure ` | **string; optional.** Whether the privilege must be present or absent. Matches the top-level &#96;default&#95;privileges&#96; entries, which carry the same field. **Constraints:** ` {"enum":["present","absent"]} `. |
| ` spec.content.profiles.<name>.default_privileges[].on_type ` | **string; required.** Kind of future object affected by the default privilege. **Constraints:** ` {"enum":["table","view","materialized_view","sequence","function","schema","database","type"]} `. |
| ` spec.content.profiles.<name>.default_privileges[].privileges ` | **array; required.** PostgreSQL privileges to reconcile on the selected objects. **Constraints:** ` {"maxItems":16,"minItems":1} `. |
| ` spec.content.profiles.<name>.default_privileges[].privileges[] ` | **string; item or branch.** PostgreSQL privilege types. **Constraints:** ` {"enum":["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","EXECUTE","USAGE","CREATE","CONNECT","TEMPORARY"]} `. |
| ` spec.content.profiles.<name>.default_privileges[].role ` | **string; optional.** Grantee role; omitted values use the generated profile role. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.profiles.<name>.grants ` | **array; optional.** Object privilege templates expanded for each bound schema. **Constraints:** ` {"maxItems":64} `. |
| ` spec.content.profiles.<name>.grants[] ` | **object; item or branch.** Grant template within a profile. **Constraints:** ` {"required":["object","privileges"]} `. |
| ` spec.content.profiles.<name>.grants[].ensure ` | **string; optional.** Whether the privilege must be present or absent. Matches the top-level &#96;grants&#96; entries, which carry the same field. Profiles are additive templates, so validation rejects &#96;absent&#96;; the schema accepts it so the API server does not prune the value before that check can name it. **Constraints:** ` {"enum":["present","absent"]} `. |
| ` spec.content.profiles.<name>.grants[].object ` | **object; required.** Object kind and target to which the privileges apply. **Constraints:** ` {"required":["type"]} `. |
| ` spec.content.profiles.<name>.grants[].object.name ` | **string; optional.** Object name; omission selects the object-kind scope supported by the profile. **Constraints:** ` {"maxLength":256,"minLength":1,"nullable":true} `. |
| ` spec.content.profiles.<name>.grants[].object.type ` | **string; required.** PostgreSQL object kind. **Constraints:** ` {"enum":["table","view","materialized_view","sequence","function","schema","database","type"]} `. |
| ` spec.content.profiles.<name>.grants[].privileges ` | **array; required.** PostgreSQL privileges to reconcile on the selected objects. **Constraints:** ` {"maxItems":16,"minItems":1} `. |
| ` spec.content.profiles.<name>.grants[].privileges[] ` | **string; item or branch.** PostgreSQL privilege types. **Constraints:** ` {"enum":["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","EXECUTE","USAGE","CREATE","CONNECT","TEMPORARY"]} `. |
| ` spec.content.profiles.<name>.inherit ` | **boolean; optional.** Whether privileges from role memberships are inherited automatically. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.profiles.<name>.login ` | **boolean; optional.** Whether the role may initiate database sessions. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.reconciliation_mode ` | **string; optional.** Convergence strategy: how aggressively to converge the database. **Constraints:** ` {"enum":["authoritative","additive","adopt"]} `. |
| ` spec.content.retirements ` | **array; optional.** Explicit role-retirement workflows for roles that should be removed. **Constraints:** ` {"maxItems":512} `. |
| ` spec.content.retirements[] ` | **object; item or branch.** Declarative workflow for retiring an existing role. **Constraints:** ` {"required":["role"]} `. |
| ` spec.content.retirements[].drop_owned ` | **boolean; optional.** Whether to run &#96;DROP OWNED BY&#96; before dropping the role. |
| ` spec.content.retirements[].reassign_owned_to ` | **string; optional.** Optional successor role for &#96;REASSIGN OWNED BY ... TO ...&#96;. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.retirements[].role ` | **string; required.** The role to retire and ultimately drop. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.retirements[].terminate_sessions ` | **boolean; optional.** Whether to terminate other active sessions for the role before drop. |
| ` spec.content.role_pattern ` | **string; optional.** Default role naming pattern. Schema bindings can override it. Supports &#96;{schema}&#96; and requires &#96;{profile}&#96;; falls back to &#96;{schema}-{profile}&#96;. **Constraints:** ` {"maxLength":128,"minLength":1,"nullable":true} `. |
| ` spec.content.roles ` | **array; optional.** One-off role definitions. **Constraints:** ` {"maxItems":1024} `. |
| ` spec.content.roles[] ` | **object; item or branch.** A concrete PostgreSQL role definition. **Constraints:** ` {"required":["name"]} `. |
| ` spec.content.roles[].bypassrls ` | **boolean; optional.** Whether the role bypasses row-level security. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].comment ` | **string; optional.** Descriptive PostgreSQL role comment. **Constraints:** ` {"maxLength":256,"nullable":true} `. |
| ` spec.content.roles[].config ` | **object; optional.** Role-level configuration parameter defaults, applied via &#96;ALTER ROLE ... SET parameter = value&#96; (e.g. &#96;role: combined&#96;, &#96;search&#95;path: app&#96;). Settings present on the role in the database but absent here are RESET in authoritative mode. **Constraints:** ` {"maxProperties":32} `. |
| ` spec.content.roles[].config.<name> ` | **string; item or branch.** A role configuration parameter value.  Values are always strings — quote numbers and booleans (e.g. &#96;statement&#95;timeout: "30000"&#96;, &#96;jit: "off"&#96;). The Kubernetes CRD schema types config values as strings, and the CLI enforces the same rule so a manifest means the same thing whether it is applied with &#96;pgroles&#96; or &#96;kubectl&#96;. PostgreSQL coerces the string to the parameter's type. **Constraints:** ` {"maxLength":256} `. |
| ` spec.content.roles[].connection_limit ` | **integer; optional.** Maximum concurrent connections for the role; -1 means unlimited. **Constraints:** ` {"format":"int32","nullable":true} `. |
| ` spec.content.roles[].createdb ` | **boolean; optional.** Whether the role may create databases. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].createrole ` | **boolean; optional.** Whether the role may create and administer roles, subject to server-version rules. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].external ` | **boolean; optional.** Treat this role as externally managed. The operator may reference it in grants, ownership, and memberships, but will not create, alter, drop, or password-manage it. Declared membership edges remain managed. |
| ` spec.content.roles[].inherit ` | **boolean; optional.** Whether privileges from role memberships are inherited automatically. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].login ` | **boolean; optional.** Whether the role may initiate database sessions. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].name ` | **string; required.** PostgreSQL role name. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.roles[].password ` | **object; optional.** Password source for this role. Either a reference to an existing Secret or a request for the operator to generate one. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].password.generate ` | **object; optional.** Generate a random password and store it in a new Kubernetes Secret. Mutually exclusive with &#96;secretRef&#96;. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].password.generate.length ` | **integer; optional.** Password length. Defaults to 32. Minimum 16, maximum 128. **Constraints:** ` {"format":"uint32","minimum":0.0,"nullable":true} `. |
| ` spec.content.roles[].password.generate.secretKey ` | **string; optional.** Key within the generated Secret. Defaults to &#96;password&#96;. **Constraints:** ` {"maxLength":253,"minLength":1,"nullable":true} `. |
| ` spec.content.roles[].password.generate.secretName ` | **string; optional.** Override the generated Secret name. Defaults to &#96;{policy}-pgr-{role}&#96;. **Constraints:** ` {"maxLength":253,"minLength":1,"nullable":true} `. |
| ` spec.content.roles[].password.secretKey ` | **string; optional.** Key within the referenced Secret. Defaults to the role name. Only used with &#96;secretRef&#96;. **Constraints:** ` {"maxLength":253,"minLength":1,"nullable":true} `. |
| ` spec.content.roles[].password.secretRef ` | **object; optional.** Reference to an existing Kubernetes Secret containing the password. Mutually exclusive with &#96;generate&#96;. **Constraints:** ` {"nullable":true,"required":["name"]} `. |
| ` spec.content.roles[].password.secretRef.name ` | **string; required.** Name of the Secret. **Constraints:** ` {"maxLength":253,"minLength":1} `. |
| ` spec.content.roles[].password_valid_until ` | **string; optional.** Password expiration timestamp (ISO 8601, e.g. "2025-12-31T00:00:00Z"). **Constraints:** ` {"maxLength":64,"nullable":true} `. |
| ` spec.content.roles[].preserve_undeclared_grants ` | **boolean; optional.** Preserve this role's undeclared in-scope object grants during convergence. Revokes against the role are skipped unless the revoked privileges are explicitly asserted absent (&#96;ensure: absent&#96;). |
| ` spec.content.roles[].replication ` | **boolean; optional.** Whether the role may initiate replication connections. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.roles[].superuser ` | **boolean; optional.** Whether the role bypasses PostgreSQL permission checks as a superuser. **Constraints:** ` {"nullable":true} `. |
| ` spec.content.schemas ` | **array; optional.** Schema bindings that expand profiles into concrete roles/grants. **Constraints:** ` {"maxItems":1024} `. |
| ` spec.content.schemas[] ` | **object; item or branch.** Associates a PostgreSQL schema with one or more reusable privilege profiles. **Constraints:** ` {"required":["name"]} `. |
| ` spec.content.schemas[].name ` | **string; required.** PostgreSQL schema name. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.schemas[].owner ` | **string; optional.** Override default&#95;owner for this schema's default privileges. **Constraints:** ` {"maxLength":63,"minLength":1,"nullable":true} `. |
| ` spec.content.schemas[].profiles ` | **array; optional.** Profile names to expand for this schema. **Constraints:** ` {"maxItems":64} `. |
| ` spec.content.schemas[].profiles[] ` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** ` {"maxLength":63,"minLength":1} `. |
| ` spec.content.schemas[].role_pattern ` | **string; optional.** Role naming pattern. Supports &#96;{schema}&#96; and &#96;{profile}&#96; placeholders. Overrides the policy pattern; otherwise inherits it, falling back to &#96;"{schema}-{profile}"&#96;. **Constraints:** ` {"maxLength":128,"minLength":1,"nullable":true} `. |
| ` spec.policyRef ` | **object; required.** The &#96;PostgresPolicy&#96; this candidate proposes content for. Resolved in the candidate's own namespace: an owner reference cannot cross namespaces, so neither can this. **Constraints:** ` {"required":["name"]} `. |
| ` spec.policyRef.name ` | **string; required.** Name of the referenced resource in the same namespace. **Constraints:** ` {"maxLength":253,"minLength":1} `. |
| ` spec.replaces ` | **string; optional.** Name of an earlier candidate this one supersedes.  Supersession is always explicit. The operator never infers it from creator identity, because CI typically files every team's candidates under one service account. **Constraints:** ` {"maxLength":253,"minLength":1,"nullable":true} `. |
| ` spec.target ` | **object; optional.** Preview the content against a different connection than the parent policy's. Credentials, locking and the plan's bound target identity all follow the override, which is why such a plan is a preview and never a migration step. **Constraints:** ` {"nullable":true,"required":["connectionRef"]} `. |
| ` spec.target.connectionRef ` | **object; required.** Connection information for the candidate evaluation target. **Constraints:** ` {"required":["key","secretName"]} `. |
| ` spec.target.connectionRef.key ` | **string; required.** Key within the Secret holding the connection URL. **Constraints:** ` {"maxLength":253,"minLength":1} `. |
| ` spec.target.connectionRef.secretName ` | **string; required.** Name of the Secret in the candidate's namespace. **Constraints:** ` {"maxLength":253,"minLength":1} `. |

## Status (read-only except decisions)

| Path | Definition |
| --- | --- |
| ` status ` | **object; optional.** Status of a &#96;PostgresPolicyCandidate&#96;.  &#96;phase&#96; is a printable summary; conditions are the source of truth. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions ` | **array; optional.** Controller observations about candidate validity, planning, approval, and promotion. **Default:** ` [] `. **Constraints:** ` {"maxItems":16} `. |
| ` status.conditions[] ` | **object; item or branch.** A condition on the &#96;PostgresPolicy&#96; resource. **Constraints:** ` {"required":["status","type"]} `. |
| ` status.conditions[].last_transition_time ` | **string; optional.** Last time the condition transitioned. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].message ` | **string; optional.** Human-readable message. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].reason ` | **string; optional.** Human-readable reason for the condition. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].status ` | **string; required.** Status: "True", "False", or "Unknown". |
| ` status.conditions[].type ` | **string; required.** Controller-defined condition type, such as Ready, Reconciling, or Degraded. This is an open vocabulary; consult status guidance for operational meanings. |
| ` status.contentDigest ` | **string; optional.** Canonical digest of &#96;spec.content&#96;, computed by &#96;pgroles&#95;core::candidate::compute&#95;content&#95;digest&#96;. This is what promotion is verified against. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` status.executorAuthority ` | **object; optional.** Read-only executor-authority preflight for the current review SQL. Absent when no current check is available. Apply rechecks fresh state; NoKnownBlockers describes targeted checks, not guaranteed SQL success. **Constraints:** ` {"nullable":true,"required":["eligibility","evaluatedAt","issues","parentState"]} `. |
| ` status.executorAuthority.eligibility ` | **string; required.** Whether the shared apply preflight found any known authority blockers. **Constraints:** ` {"enum":["NoKnownBlockers","Blocked"]} `. |
| ` status.executorAuthority.evaluatedAt ` | **string; required.** RFC 3339 time the preflight ran. A consumer that needs a result newer than some event (its own start, a migration, a restore) compares this. |
| ` status.executorAuthority.issues ` | **array; required.** Known blockers, with stable diagnostic codes and readable details. |
| ` status.executorAuthority.issues[] ` | **object; item or branch.** One known executor-authority blocker. **Constraints:** ` {"required":["code","message"]} `. |
| ` status.executorAuthority.issues[].code ` | **string; required.** Stable kind returned by the shared authority preflight. |
| ` status.executorAuthority.issues[].message ` | **string; required.** Readable explanation naming the affected roles or objects. |
| ` status.executorAuthority.parentGeneration ` | **integer; optional.** The parent policy's &#96;metadata.generation&#96; during evaluation. A result for an older generation does not describe the current parent. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.executorAuthority.parentState ` | **string; required.** The parent policy's state during evaluation. **Constraints:** ` {"enum":["Converged","ExecutorAuthorityBlocked"]} `. |
| ` status.observedGeneration ` | **integer; optional.** The &#96;.metadata.generation&#96; that was last observed. A candidate spec is immutable, so this advances at most once. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.phase ` | **string; optional.** Current candidate evaluation and promotion phase. **Default:** ` "Pending" `. **Constraints:** ` {"enum":["Pending","Planned","Promoted","Superseded","Stale"]} `. |
| ` status.planRef ` | **object; optional.** The &#96;PostgresPolicyPlan&#96; produced for this candidate. **Constraints:** ` {"nullable":true,"required":["name"]} `. |
| ` status.planRef.name ` | **string; required.** Name of the PostgresPolicyPlan in the same namespace. |

[Download the complete served OpenAPI schema](/crd-reference/postgrespolicycandidate-v1alpha1.json) for structural composition and all Kubernetes extensions.

Generated with `crdgen --docs-dir`; edit the Rust schema descriptions to change this reference.
