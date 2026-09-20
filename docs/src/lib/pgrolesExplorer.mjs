const SCHEMA_VERSION = 'pgroles.explorer.v1'
const REVIEW_SCHEMA_VERSION = 'pgroles.review-artifact.v1'
export const MAX_SNAPSHOT_FILE_BYTES = 4_194_304

let enginePromise

export function wasmModuleUrl(basePath = '') {
  return `${basePath}/wasm/pgroles_wasm.js`
}

export function loadPolicyEngine(basePath = '', importer = (url) => import(/* webpackIgnore: true */ url)) {
  enginePromise ??= importer(wasmModuleUrl(basePath))
    .then(async (module) => {
      await module.default()
      return module
    })
    .catch((error) => {
      enginePromise = undefined
      throw error
    })
  return enginePromise
}

export async function loadAnalyzer(basePath = '', importer) {
  return (await loadPolicyEngine(basePath, importer)).analyze
}

export function policyRequest(desiredYaml) {
  return { schema_version: 'pgroles.policy.v1', desired_yaml: desiredYaml }
}

export function resetAnalyzerForTests() {
  enginePromise = undefined
}

export function analyzeRequest({
  current,
  desiredYaml,
  mode,
  executorRole,
  executorSuperuser = false,
  executorMemberships = [],
  newMembershipSetRole = 'unknown',
  newRoleSetRole = 'unknown',
  newRoleInherit = 'unknown',
  newRoleAdminOption = 'unknown',
}) {
  return {
    schema_version: SCHEMA_VERSION,
    current,
    desired_yaml: desiredYaml,
    mode,
    executor: {
      role: executorRole,
      superuser: executorSuperuser,
      memberships: executorMemberships,
      new_membership_set_role: newMembershipSetRole,
      new_role_set_role: newRoleSetRole,
      new_role_inherit: newRoleInherit,
      new_role_admin_option: newRoleAdminOption,
    },
  }
}

export function readableWasmError(error) {
  if (typeof error === 'string') return error
  if (error instanceof Error && error.message) return error.message
  return String(error)
}

export function explorerImport(value) {
  if (value?.schema_version && value.schema_version !== SCHEMA_VERSION) {
    throw new Error(`unsupported explorer schema version: ${value.schema_version}`)
  }
  return { current: value?.current ?? value, executor: value?.executor }
}

export function validateSnapshotFileSize(size) {
  if (size > MAX_SNAPSHOT_FILE_BYTES) {
    throw new Error(`snapshot file is ${size} bytes; limit is ${MAX_SNAPSHOT_FILE_BYTES} bytes`)
  }
}

export function validateReviewArtifactFileSize(size) {
  if (size > MAX_SNAPSHOT_FILE_BYTES) {
    throw new Error(`review artifact file is ${size} bytes; limit is ${MAX_SNAPSHOT_FILE_BYTES} bytes`)
  }
}

export function reviewArtifactImport(value) {
  const isObject = (candidate) => candidate && typeof candidate === 'object' && !Array.isArray(candidate)
  const isString = (candidate) => typeof candidate === 'string'
  const isOneOf = (candidate, allowed) => isString(candidate) && allowed.includes(candidate)
  const hashPattern = /^sha256:[0-9a-f]{64}$/
  const modes = ['authoritative', 'additive', 'adopt']
  const checks = ['executor_authority', 'role_drop_safety', 'server_compatibility']
  const evidenceStatuses = ['passed', 'failed', 'not_run', 'unknown']
  const priorities = ['High', 'Review', 'Informational']
  const phases = ['create', 'alter', 'grant', 'membership_remove', 'membership_add', 'revoke', 'default_privilege_revoke', 'retire']
  const reachabilityStatuses = ['reachable', 'unreachable', 'unknown']
  const findingSeverities = ['info', 'warning', 'error']
  if (!isObject(value)) {
    throw new Error('review artifact must be a JSON object')
  }
  if (value.schema_version !== REVIEW_SCHEMA_VERSION) {
    throw new Error(`unsupported review artifact schema version: ${value.schema_version ?? 'missing'}`)
  }
  if (!value.provenance || !value.context || !value.recorded || !value.exploration) {
    throw new Error('review artifact is missing provenance, context, recorded, or exploration data')
  }
  if (typeof value.provenance.tool_version !== 'string' || typeof value.provenance.captured_at !== 'string' || typeof value.provenance.target_label !== 'string' || !Number.isSafeInteger(value.provenance.pg_major_version) || !hashPattern.test(value.provenance.policy?.content_digest)) {
    throw new Error('review artifact provenance is malformed')
  }
  if (value.provenance.policy.commit != null && !isString(value.provenance.policy.commit)) {
    throw new Error('review artifact policy provenance is malformed')
  }
  if (!isOneOf(value.context.mode, modes) || typeof value.context.inspector?.role !== 'string' || typeof value.context.intended_executor?.role !== 'string') {
    throw new Error('review artifact execution context is malformed')
  }
  if (![value.context.inspector.superuser, value.context.intended_executor.superuser].every((entry) => entry == null || typeof entry === 'boolean')) {
    throw new Error('review artifact execution identity is malformed')
  }
  if (!Array.isArray(value.preflight) || !Array.isArray(value.recorded.changes) || !Array.isArray(value.recorded.phases) || !Array.isArray(value.recorded.findings)) {
    throw new Error('review artifact recorded collections are malformed')
  }
  const isPreflightIssue = (issue) => isObject(issue) && isString(issue.code) && isString(issue.message) && (issue.role == null || isString(issue.role))
  const isPreflight = (item) => isObject(item)
    && isOneOf(item.check, checks)
    && isOneOf(item.status, evidenceStatuses)
    && (item.actor_role == null || isString(item.actor_role))
    && Number.isSafeInteger(item.issue_count) && item.issue_count >= 0
    && (item.issues == null ? item.issue_count === 0 : Array.isArray(item.issues) && item.issues.length === item.issue_count && item.issues.every(isPreflightIssue))
  if (!value.preflight.every(isPreflight)) {
    throw new Error('review artifact preflight evidence is malformed')
  }
  if (!value.recorded.changes.every((entry) => isObject(entry) && Number.isSafeInteger(entry.index) && entry.index >= 0 && isOneOf(entry.priority, priorities) && isObject(entry.change) && isString(entry.change.kind) && (!entry.source || (isObject(entry.source) && isString(entry.source.document) && isObject(entry.source.managed_key) && isString(entry.source.managed_key.kind))) && (!entry.omissions || (Array.isArray(entry.omissions) && entry.omissions.every((omission) => isObject(omission) && isString(omission.field) && omission.reason === 'sensitive_value'))))) {
    throw new Error('review artifact changes are malformed')
  }
  const changeIndices = new Set(value.recorded.changes.map((entry) => entry.index))
  const contiguousIndices = value.recorded.changes.every((entry, index) => entry.index === index)
  const isReachability = (entry) => isObject(entry) && isString(entry.role) && isOneOf(entry.status, reachabilityStatuses)
  if (!contiguousIndices || changeIndices.size !== value.recorded.changes.length || !value.recorded.phases.every((phase) => isObject(phase) && isOneOf(phase.phase, phases) && Array.isArray(phase.change_indices) && phase.change_indices.every((index) => changeIndices.has(index)) && Array.isArray(phase.executor_reachability) && phase.executor_reachability.every(isReachability) && Array.isArray(phase.executor_usage) && phase.executor_usage.every(isReachability))) {
    throw new Error('review artifact phases are malformed')
  }
  if (!value.recorded.findings.every((finding) => isObject(finding) && isString(finding.kind) && isOneOf(finding.severity, findingSeverities) && isString(finding.message) && (finding.phase == null || isOneOf(finding.phase, phases)) && (finding.change_index == null || changeIndices.has(finding.change_index)))) {
    throw new Error('review artifact findings are malformed')
  }
  if (!value.recorded.visual || !Array.isArray(value.recorded.visual.nodes) || !Array.isArray(value.recorded.visual.edges)) {
    throw new Error('review artifact visual graph is malformed')
  }
  if (!value.recorded.visual.nodes.every((node) => isObject(node) && isString(node.id) && isString(node.kind) && isString(node.label)) || !value.recorded.visual.edges.every((edge) => isObject(edge) && isString(edge.source) && isString(edge.target) && isString(edge.kind) && isString(edge.label))) {
    throw new Error('review artifact visual graph entries are malformed')
  }
  if (!hashPattern.test(value.recorded.review_fingerprint)) {
    throw new Error('review artifact fingerprint is malformed')
  }
  if (value.recorded.omissions && (!Array.isArray(value.recorded.omissions) || !value.recorded.omissions.every((omission) => isObject(omission) && isString(omission.field) && isString(omission.reason)))) {
    throw new Error('review artifact omissions are malformed')
  }
  if (!value.recorded.sql_preview || !['available', 'omitted'].includes(value.recorded.sql_preview.status)) {
    throw new Error('review artifact SQL preview is malformed')
  }
  if ((value.recorded.sql_preview.status === 'available' && !isString(value.recorded.sql_preview.sql)) || (value.recorded.sql_preview.status === 'omitted' && (value.recorded.sql_preview.reason !== 'sensitive_changes' || !Array.isArray(value.recorded.sql_preview.sensitive_change_indices) || !value.recorded.sql_preview.sensitive_change_indices.every((index) => changeIndices.has(index))))) {
    throw new Error('review artifact SQL preview content is malformed')
  }
  if (value.exploration.status !== 'omitted' || !['recorded_only_export', 'sensitive_inputs_removed'].includes(value.exploration.reason)) {
    throw new Error('review artifact exploration status is malformed')
  }
  return value
}
