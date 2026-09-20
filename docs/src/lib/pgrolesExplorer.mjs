const SCHEMA_VERSION = 'pgroles.explorer.v1'
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
