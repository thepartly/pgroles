---
title: PostgresPolicyPlan
description: Generated field reference for the served v1alpha1 API.
---

[CRD API reference](/docs/operator-api-reference) · Served version `v1alpha1`.

Required fields apply when their containing object is present. Defaults shown are API-server defaults; null requires `nullable`. Standard metadata follows [Kubernetes conventions](https://kubernetes.io/docs/concepts/overview/working-with-objects/). Status is controller-owned except documented decisions.

For workflows, see [operator guidance](/docs/operator), [approval](/docs/operator-plan-approval), [candidates](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access).

## Spec

| Path | Definition |
| --- | --- |
| ` spec ` | **object; required.** Spec for a &#96;PostgresPolicyPlan&#96; custom resource.  Represents a computed reconciliation plan for a &#96;PostgresPolicy&#96;. Plans are created by the operator and may require explicit approval before execution. **Constraints:** ` {"required":["managedDatabaseIdentity","policyGeneration","policyRef","reconciliationMode"]} `. |
| ` spec ` | **CEL:** ` {"message":"plan origin is immutable once set","rule":"!has(oldSelf.origin) \|\| (has(self.origin) && self.origin == oldSelf.origin)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` spec.managedDatabaseIdentity ` | **string; required.** Database identity string for disambiguation in multi-db setups. |
| ` spec.origin ` | **object; optional.** Origin of this plan. Omitted for ordinary durable reconciliation plans. **Constraints:** ` {"nullable":true,"required":["kind","name","uid"]} `. |
| ` spec.origin.baseContentDigest ` | **string; optional.** Canonical content digest of the &#42;policy&#42; content this candidate plan was computed against — the applied base. A candidate is a complete desired-state snapshot, so an approval is only meaningful against the base it was reviewed on: identical SQL effects do not prove the snapshot still preserves everything the base has come to manage since. Promotion refuses to adopt a plan whose base pin no longer matches the content the policy carried before the merge, and planning supersedes the plan as soon as the base moves. Absent for non-candidate origins. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` spec.origin.contentDigest ` | **string; optional.** Canonical content digest of the originating candidate, and the encoding it was computed under.  This is what binds the reviewed plan to the content that will later be promoted. It lives on the origin rather than in an annotation because a promotion check that can be edited by anyone holding &#96;patch&#96; is not a binding at all. Both fields are absent for non-candidate origins. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` spec.origin.contentDigestEncoding ` | **string; optional.** Version tag of the encoding &#96;contentDigest&#96; was computed under. Digests from different encodings are never comparable, so promotion recognition only matches digests carrying the same tag. Absent for non-candidate origins. **Constraints:** ` {"maxLength":64,"nullable":true} `. |
| ` spec.origin.kind ` | **string; required.** Kind of the resource that requested this plan. **Constraints:** ` {"maxLength":63} `. |
| ` spec.origin.name ` | **string; required.** Name of the originating resource. **Constraints:** ` {"maxLength":253} `. |
| ` spec.origin.policyUid ` | **string; optional.** UID of the &#96;PostgresPolicy&#96; the candidate proposes content for. The plan's &#96;spec.policyRef&#96; names it; the UID is what survives a delete-and-recreate of the same name. **Constraints:** ` {"maxLength":63,"nullable":true} `. |
| ` spec.origin.uid ` | **string; required.** UID binding the plan to this exact originating resource. **Constraints:** ` {"maxLength":63} `. |
| ` spec.ownedRoles ` | **array; optional.** Roles that this plan covers. **Default:** ` [] `. |
| ` spec.ownedRoles[] ` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. |
| ` spec.ownedSchemas ` | **array; optional.** Schemas that this plan covers. **Default:** ` [] `. |
| ` spec.ownedSchemas[] ` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. |
| ` spec.policyGeneration ` | **integer; required.** The policy's &#96;.metadata.generation&#96; at plan time. **Constraints:** ` {"format":"int64"} `. |
| ` spec.policyRef ` | **object; required.** Reference to the policy that generated this plan. **Constraints:** ` {"required":["name"]} `. |
| ` spec.policyRef.name ` | **string; required.** Name of the originating PostgresPolicy in the same namespace. |
| ` spec.reconciliationMode ` | **string; required.** Reconciliation mode used for this plan. **Constraints:** ` {"enum":["authoritative","additive","adopt"]} `. |
| ` spec.scope ` | **object; optional.** Narrow execution scope for a non-durable plan. **Constraints:** ` {"nullable":true,"required":["bundleHash","kind","operation"]} `. |
| ` spec.scope.bundleHash ` | **string; required.** Digest binding an ephemeral plan to its resolved membership bundle. |
| ` spec.scope.kind ` | **string; required.** Execution scope identifier for the ephemeral membership bundle. |
| ` spec.scope.operation ` | **string; required.** Ephemeral bundle operation, when this is an ephemeral plan. **Constraints:** ` {"enum":["Activate","Revoke"]} `. |

## Status (read-only except decisions)

| Path | Definition |
| --- | --- |
| ` status ` | **object; optional.** Status of a &#96;PostgresPolicyPlan&#96; resource.  The decision rules below are the same grammar &#96;EphemeralAccessRequest&#96; uses: a decision is terminal, &#96;Approved&#96; and &#96;Denied&#96; cannot both be true, and the deciding identity is recorded in the same admitted write. What CEL cannot do is check &#42;who&#42; is writing — see &#91;&#96;DecisionActor&#96;&#93;. **Constraints:** ` {"nullable":true} `. |
| ` status ` | **CEL:** ` {"message":"Approved=True and Denied=True are mutually exclusive","rule":"!(self.conditions.exists(c, c.type == 'Approved' && c.status == 'True') && self.conditions.exists(c, c.type == 'Denied' && c.status == 'True'))"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"plan decisions are terminal","rule":"oldSelf.conditions.filter(c, (c.type == 'Approved' \|\| c.type == 'Denied') && c.status == 'True').map(c, c.type) == self.conditions.filter(c, (c.type == 'Approved' \|\| c.type == 'Denied') && c.status == 'True').map(c, c.type) \|\| oldSelf.conditions.filter(c, (c.type == 'Approved' \|\| c.type == 'Denied') && c.status == 'True').size() == 0"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"decision identity is write-once","rule":"!has(oldSelf.decidedBy) \|\| (has(self.decidedBy) && self.decidedBy == oldSelf.decidedBy)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"a terminal plan decision and decidedBy identity must be recorded together","rule":"self.conditions.exists(c, (c.type == 'Approved' \|\| c.type == 'Denied') && c.status == 'True') == has(self.decidedBy)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"changeDigest is write-once","rule":"!has(oldSelf.changeDigest) \|\| (has(self.changeDigest) && self.changeDigest == oldSelf.changeDigest)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"changeDigestEncoding is write-once","rule":"!has(oldSelf.changeDigestEncoding) \|\| (has(self.changeDigestEncoding) && self.changeDigestEncoding == oldSelf.changeDigestEncoding)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"targetPhysicalIdentity is write-once","rule":"!has(oldSelf.targetPhysicalIdentity) \|\| (has(self.targetPhysicalIdentity) && self.targetPhysicalIdentity == oldSelf.targetPhysicalIdentity)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"targetLogicalFingerprint is write-once","rule":"!has(oldSelf.targetLogicalFingerprint) \|\| (has(self.targetLogicalFingerprint) && self.targetLogicalFingerprint == oldSelf.targetLogicalFingerprint)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status ` | **CEL:** ` {"message":"physicalIdentityAvailable is write-once","rule":"!has(oldSelf.physicalIdentityAvailable) \|\| (has(self.physicalIdentityAvailable) && self.physicalIdentityAvailable == oldSelf.physicalIdentityAvailable)"} `. Evaluated with self at this path; oldSelf refers to the previous value on update. |
| ` status.appliedAt ` | **string; optional.** Timestamp when the plan was applied (if applicable). **Constraints:** ` {"nullable":true} `. |
| ` status.applyingSince ` | **string; optional.** Timestamp when the plan entered Applying phase (for stuck detection). **Constraints:** ` {"nullable":true} `. |
| ` status.changeDigest ` | **string; optional.** Canonical semantic digest of the plan's typed effects, bound to the reconciliation mode and target database identity.  This is the approval identity: a decision approves these effects, and execution proceeds only when the recomputed digest still matches. It is stable across recomputation of unchanged effects — notably for password changes, which bind the password &#42;source&#42; rather than the derived verifier. See &#96;pgroles&#95;core::approval&#96;. **Constraints:** ` {"nullable":true} `. |
| ` status.changeDigestEncoding ` | **string; optional.** Version tag of the encoding &#96;change&#95;digest&#96; was computed under. Digests from different encodings are never comparable. **Constraints:** ` {"nullable":true} `. |
| ` status.changeSummary ` | **object; optional.** Summary of changes in this plan. **Constraints:** ` {"nullable":true} `. |
| ` status.changeSummary.default_privileges_revoked ` | **integer; optional.** Number of default privilege revoke steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.default_privileges_set ` | **integer; optional.** Number of default privilege grant steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.grants_added ` | **integer; optional.** Number of object privilege grant steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.grants_revoked ` | **integer; optional.** Number of object privilege revoke steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.members_added ` | **integer; optional.** Number of membership additions. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.members_options_changed ` | **integer; optional.** Number of grantor-attributed membership option changes. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.members_removed ` | **integer; optional.** Number of membership removals. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.passwords_set ` | **integer; optional.** Number of password updates. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.roles_altered ` | **integer; optional.** Number of role attribute or configuration changes. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.roles_created ` | **integer; optional.** Number of role creations. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.roles_dropped ` | **integer; optional.** Number of role drops. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.schema_owners_altered ` | **integer; optional.** Number of schema ownership changes. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.schemas_created ` | **integer; optional.** Number of schema creations. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.sessions_terminated ` | **integer; optional.** Number of session-termination steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.changeSummary.total ` | **integer; optional.** Number of all planned change steps. **Default:** ` 0 `. **Constraints:** ` {"format":"int32"} `. |
| ` status.computedAt ` | **string; optional.** Timestamp when the plan was computed. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions ` | **array; optional.** Standard conditions: Computed, Applied, and the terminal decision conditions &#96;Approved&#96; / &#96;Denied&#96;. **Default:** ` [] `. **Constraints:** ` {"maxItems":16} `. |
| ` status.conditions[] ` | **object; item or branch.** A condition on the &#96;PostgresPolicy&#96; resource. **Constraints:** ` {"required":["status","type"]} `. |
| ` status.conditions[].last_transition_time ` | **string; optional.** Last time the condition transitioned. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].message ` | **string; optional.** Human-readable message. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].reason ` | **string; optional.** Human-readable reason for the condition. **Constraints:** ` {"nullable":true} `. |
| ` status.conditions[].status ` | **string; required.** Status: "True", "False", or "Unknown". |
| ` status.conditions[].type ` | **string; required.** Controller-defined condition type, such as Ready, Reconciling, or Degraded. This is an open vocabulary; consult status guidance for operational meanings. |
| ` status.decidedBy ` | **object; optional.** Kubernetes identity which approved or denied this plan.  Written in the same status update as the terminal decision, and write-once thereafter. The supplied Kyverno reference policy overwrites it from authenticated admission &#96;userInfo&#96;; without that admission layer it is an assertion by whoever wrote the status, not a verified identity. **Constraints:** ` {"nullable":true,"required":["username"]} `. |
| ` status.decidedBy.groups ` | **array; optional.** Kubernetes groups recorded for this actor. **Default:** ` [] `. **Constraints:** ` {"maxItems":64} `. |
| ` status.decidedBy.groups[] ` | **string; item or branch.** Constraints on this array item, map value, or conditional schema. **Constraints:** ` {"maxLength":256,"minLength":1} `. |
| ` status.decidedBy.uid ` | **string; optional.** Optional Kubernetes user UID recorded by admission. **Constraints:** ` {"maxLength":128,"nullable":true} `. |
| ` status.decidedBy.username ` | **string; required.** Kubernetes username asserted for this actor; authenticated only when enforced by admission. **Constraints:** ` {"maxLength":512,"minLength":1} `. |
| ` status.failedAt ` | **string; optional.** Timestamp when the plan entered Failed phase (for dedup window). **Constraints:** ` {"nullable":true} `. |
| ` status.lastError ` | **string; optional.** Error message if apply failed. **Constraints:** ` {"nullable":true} `. |
| ` status.passwordSourceDigest ` | **string; optional.** Diagnostic SHA-256 digest of the password source-version map. Contains no password material. A mismatch identifies credential-source changes; approval remains bound by changeDigest. Absent on older plans. **Constraints:** ` {"nullable":true} `. |
| ` status.phase ` | **string; optional.** Phase: Pending, Approved, Applying, Applied, Failed, Superseded. **Default:** ` "Pending" `. **Constraints:** ` {"enum":["Pending","Approved","Applying","Applied","Failed","Superseded","Rejected"]} `. |
| ` status.physicalIdentityAvailable ` | **boolean; optional.** Whether the physical identity was readable when this plan was computed.  Recorded explicitly rather than inferred from &#96;target&#95;physical&#95;identity&#96; being set, so that "the identifier could not be read" is distinguishable from "this plan predates the field". The difference matters at execution: a plan that had the identifier and now does not is a downgrade and fails closed. **Constraints:** ` {"nullable":true} `. |
| ` status.redactedSqlHash ` | **string; optional.** SHA-256 hash of the redacted SQL preview bytes. This is for storage integrity only; approval and deduplication use &#96;change&#95;digest&#96;. **Constraints:** ` {"nullable":true} `. |
| ` status.revalidatedAt ` | **string; optional.** When the plan was most recently confirmed current. **Constraints:** ` {"nullable":true} `. |
| ` status.revalidatedGeneration ` | **integer; optional.** The owning object's &#96;.metadata.generation&#96; this plan was most recently confirmed current against — the policy's for an ordinary plan, the candidate's for a candidate-origin plan.  A pending policy plan is revalidated on every reconcile. When the policy changes but the resulting effects do not, the plan — and any decision recorded on it — is retained and this advances to the new generation. A candidate's spec is immutable, so a candidate plan's provenance is stamped once at creation; its ongoing revalidation is the digest deduplication itself. It is provenance, never approval identity: &#96;change&#95;digest&#96; is what a decision binds. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.sqlHash ` | **string; optional.** SHA-256 hash of the planned SQL. Retained as a diagnostic for the preview artifact; it is &#42;&#42;not&#42;&#42; the approval identity, because rendered SQL embeds a freshly salted SCRAM verifier for every password change. Use &#96;change&#95;digest&#96; for approval and deduplication. **Constraints:** ` {"nullable":true} `. |
| ` status.sqlInline ` | **string; optional.** Inline SQL for small plans (below a size threshold). **Constraints:** ` {"nullable":true} `. |
| ` status.sqlOriginalBytes ` | **integer; optional.** Uncompressed byte length of the redacted SQL preview. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.sqlRef ` | **object; optional.** Reference to ConfigMap containing the full SQL (for large plans). **Constraints:** ` {"nullable":true,"required":["key","name"]} `. |
| ` status.sqlRef.compression ` | **string; optional.** Compression used for the referenced SQL content. Missing means older uncompressed ConfigMap data. **Constraints:** ` {"enum":["gzip",null],"nullable":true} `. |
| ` status.sqlRef.key ` | **string; required.** Data key containing SQL in the referenced ConfigMap. |
| ` status.sqlRef.name ` | **string; required.** Name of the ConfigMap containing the rendered SQL. |
| ` status.sqlStatements ` | **integer; optional.** Number of SQL statements in the plan (after wildcard expansion). May be significantly larger than &#96;changeSummary.total&#96; when wildcard grants expand to many per-object statements. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.sqlStoredBytes ` | **integer; optional.** Stored byte length of the SQL preview after inline/truncation/compression. **Constraints:** ` {"format":"int64","nullable":true} `. |
| ` status.sqlTruncated ` | **boolean; optional.** True when the SQL preview was truncated because the full redacted SQL could not be persisted within Kubernetes object limits. **Default:** ` false `. |
| ` status.targetLogicalFingerprint ` | **string; optional.** Fingerprint of the resolved connection endpoint (host, port, database) this plan was computed against. **Constraints:** ` {"nullable":true} `. |
| ` status.targetPhysicalIdentity ` | **string; optional.** &#96;pg&#95;control&#95;system().system&#95;identifier&#96; as read from the target when this plan was computed — the storage lineage the approval is bound to. Absent on engines that do not expose it. **Constraints:** ` {"nullable":true} `. |

[Download the complete served OpenAPI schema](/crd-reference/postgrespolicyplan-v1alpha1.json) for structural composition and all Kubernetes extensions.

Generated with `crdgen --docs-dir`; edit the Rust schema descriptions to change this reference.
