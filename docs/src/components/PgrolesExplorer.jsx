import { useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { Dialog, Modal, ModalOverlay } from 'react-aria-components'
import {
  IconAlertTriangle,
  IconChevronRight,
  IconFileUpload,
  IconLoader2,
  IconNetwork,
  IconPlayerPlay,
  IconZoomIn,
  IconZoomOut,
  IconX,
} from '@tabler/icons-react'

import {
  analyzeRequest,
  explorerImport,
  loadAnalyzer,
  readableWasmError,
  validateSnapshotFileSize,
} from '@/lib/pgrolesExplorer.mjs'
import { explorerScenarios, getExplorerScenario } from '@/lib/explorerScenarios.mjs'

const DEFAULT_SCENARIO = explorerScenarios[0]

function humanize(value = '') {
  return value
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replaceAll('_', ' ')
    .replace(/^./, (letter) => letter.toUpperCase())
}

function changeLabel(change) {
  const [kind, detail] = Object.entries(change)[0] ?? ['Change', {}]
  const subject = detail?.name ?? detail?.role ?? detail?.owner ?? detail?.from_role
  return subject ? `${humanize(kind)} · ${subject}` : humanize(kind)
}

function PhaseTimeline({ phases, focusPhase }) {
  if (!phases?.length) {
    return <p className="text-sm text-muted-foreground">No changes remain in this reconciliation mode.</p>
  }
  return (
    <ol className="relative ml-2 border-l border-stone-300 dark:border-stone-700">
      {phases.map((phase, index) => (
        <li key={`${phase.phase}-${index}`} className="relative pb-7 pl-7 last:pb-0">
          <span className="absolute top-1 -left-2 flex size-4 items-center justify-center rounded-full bg-amber-500 ring-4 ring-stone-100 dark:ring-stone-950" />
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="m-0 text-base font-semibold">{humanize(phase.phase)}</h3>
            <span className="text-xs text-muted-foreground">{phase.changes.length} change{phase.changes.length === 1 ? '' : 's'}</span>
          </div>
          <ul className="mt-2 space-y-1 text-sm">
            {phase.changes.map((change, changeIndex) => (
              <li key={changeIndex} className="rounded-md border bg-white px-3 py-2 font-mono text-xs dark:bg-stone-900">
                {changeLabel(change)}
              </li>
            ))}
          </ul>
          <details open={phase.phase === focusPhase} className="mt-2 rounded-md bg-stone-200/60 px-3 py-2 text-xs dark:bg-stone-800/60">
            <summary className="cursor-pointer font-medium">Executor access after this phase</summary>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <ReachabilityList label="Inherited usage" values={phase.executor_usage} />
              <ReachabilityList label="SET ROLE" values={phase.executor_reachability} />
            </div>
          </details>
        </li>
      ))}
    </ol>
  )
}

function ReachabilityList({ label, values = [] }) {
  return (
    <div>
      <p className="font-semibold text-muted-foreground">{label}</p>
      {values.length === 0 ? <p className="mt-1">No role paths</p> : (
        <ul className="mt-1 space-y-1">
          {values.map((value) => <li key={value.role} className="flex justify-between gap-2"><span className="truncate font-mono">{value.role}</span><span className={value.status === 'reachable' ? 'text-teal-700 dark:text-teal-300' : value.status === 'unknown' ? 'text-amber-700 dark:text-amber-300' : 'text-red-700 dark:text-red-300'}>{humanize(value.status)}</span></li>)}
        </ul>
      )}
    </div>
  )
}

function FindingItem({ finding, changes }) {
  const severity = finding.severity ?? 'warning'
  const tones = {
    error: 'border-red-300 bg-red-50 text-red-950 dark:border-red-900 dark:bg-red-950/30 dark:text-red-100',
    info: 'border-teal-300 bg-teal-50 text-teal-950 dark:border-teal-900 dark:bg-teal-950/30 dark:text-teal-100',
    warning: 'border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100',
  }
  const change = finding.change_index == null ? null : changes[finding.change_index]
  return (
    <li data-severity={severity} className={`flex gap-3 rounded-lg border p-3 text-sm ${tones[severity] ?? tones.warning}`}>
      <IconAlertTriangle className="mt-0.5 size-4 shrink-0" />
      <span>
        <span className="mb-1 block text-xs font-semibold uppercase">{humanize(severity)}</span>
        {(finding.phase || change) && <span className="mb-1 block text-xs font-semibold opacity-75">{finding.phase ? humanize(finding.phase) : 'Plan'}{change ? ` · ${changeLabel(change)}` : ''}</span>}
        {finding.message}
      </span>
    </li>
  )
}

function RoleSheet({ node, edges, onClose }) {
  if (!node) return null
  const connected = edges.filter((edge) => edge.source === node.id || edge.target === node.id)
  return (
    <ModalOverlay isOpen isDismissable onOpenChange={(open) => { if (!open) onClose() }} className="fixed inset-0 z-[70] flex items-end bg-stone-950/35 sm:items-center sm:justify-center">
      <Modal className="max-h-[75vh] w-full overflow-y-auto rounded-t-2xl border bg-white p-5 shadow-2xl outline-none sm:max-w-md sm:rounded-2xl dark:bg-stone-900">
      <Dialog aria-labelledby="role-sheet-title" className="outline-none">
        <div className="flex items-start justify-between gap-4">
          <div><p className="text-xs font-semibold tracking-wider text-amber-700 uppercase dark:text-amber-300">{humanize(node.kind)}</p><h3 id="role-sheet-title" className="mt-1 text-xl font-semibold">{node.label}</h3></div>
          <button type="button" onClick={onClose} aria-label="Close role details" className="rounded-md p-2 hover:bg-stone-100 dark:hover:bg-stone-800"><IconX className="size-5" /></button>
        </div>
        <dl className="mt-5 grid grid-cols-2 gap-3 text-sm">
          <div><dt className="text-muted-foreground">Login</dt><dd>{node.login == null ? 'Not applicable' : node.login ? 'Yes' : 'No'}</dd></div>
          <div><dt className="text-muted-foreground">Connections</dt><dd>{connected.length}</dd></div>
        </dl>
        {connected.length > 0 && <ul className="mt-5 space-y-2 text-sm">{connected.map((edge, index) => <li key={index} className="rounded-md border p-3"><span className="font-medium">{humanize(edge.kind)}</span><br/><span className="text-muted-foreground">{edge.label}</span></li>)}</ul>}
      </Dialog>
      </Modal>
    </ModalOverlay>
  )
}

const MAX_GRAPH_NODES = 48

function Graph({ visual, onSelect }) {
  const [zoom, setZoom] = useState(1)
  const nodes = visual.nodes.slice(0, MAX_GRAPH_NODES)
  const nodeIds = new Set(nodes.map((node) => node.id))
  const columns = Math.min(6, Math.max(1, Math.ceil(Math.sqrt(nodes.length))))
  const rows = Math.ceil(nodes.length / columns)
  const width = Math.min(1080, Math.max(360, columns * 170))
  const height = Math.min(720, Math.max(180, rows * 90))
  const positions = new Map(nodes.map((node, index) => {
    const column = index % columns
    const row = Math.floor(index / columns)
    return [node.id, { x: ((column + 0.5) * width) / columns, y: ((row + 0.5) * height) / rows }]
  }))
  return (
    <div className="rounded-xl border bg-[radial-gradient(circle_at_1px_1px,rgba(120,113,108,.22)_1px,transparent_0)] bg-[size:20px_20px]">
      <div className="flex justify-end gap-1 border-b bg-white/80 p-2 dark:bg-stone-900/80">
        <button type="button" aria-label="Zoom graph out" onClick={() => setZoom((value) => Math.max(.6, value - .2))} className="rounded p-2 hover:bg-stone-100 dark:hover:bg-stone-800"><IconZoomOut className="size-4" /></button>
        <span className="min-w-12 py-2 text-center text-xs text-muted-foreground">{Math.round(zoom * 100)}%</span>
        <button type="button" aria-label="Zoom graph in" onClick={() => setZoom((value) => Math.min(1.8, value + .2))} className="rounded p-2 hover:bg-stone-100 dark:hover:bg-stone-800"><IconZoomIn className="size-4" /></button>
      </div>
      <div className="overflow-auto p-3" style={{ touchAction: 'pan-x pan-y' }}>
        {visual.nodes.length > nodes.length && <p className="mb-2 text-xs text-muted-foreground">Showing {nodes.length} of {visual.nodes.length} nodes. Use the role list for the complete result.</p>}
        <svg viewBox={`0 0 ${width} ${height}`} width={width * zoom} height={height * zoom} role="img" aria-label="Resulting role and privilege graph" data-node-count={nodes.length}>
          <defs><marker id="explorer-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" className="fill-teal-600" /></marker></defs>
          {visual.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)).map((edge, index) => {
            const source = positions.get(edge.source); const target = positions.get(edge.target)
            if (!source || !target) return null
            return <line key={index} x1={source.x} y1={source.y} x2={target.x} y2={target.y} className="stroke-teal-600" strokeWidth="2" markerEnd="url(#explorer-arrow)" />
          })}
          {nodes.map((node) => {
            const point = positions.get(node.id)
            return <g key={node.id} role="button" tabIndex="0" aria-label={`${humanize(node.kind)} ${node.label}`} onClick={() => onSelect(node)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') onSelect(node) }} className="cursor-pointer outline-none">
              <rect x={point.x - 70} y={point.y - 28} width="140" height="56" rx="10" className="fill-white stroke-stone-400 hover:stroke-amber-500 dark:fill-stone-900 dark:stroke-stone-600" strokeWidth="2" />
              <text x={point.x} y={point.y - 4} textAnchor="middle" className="fill-stone-500 text-[9px] font-semibold uppercase dark:fill-stone-400">{humanize(node.kind)}</text>
              <text x={point.x} y={point.y + 14} textAnchor="middle" className="fill-stone-900 text-[12px] font-semibold dark:fill-stone-100">{node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label}</text>
            </g>
          })}
        </svg>
      </div>
    </div>
  )
}

function RoleAdjacency({ visual, onSelect }) {
  const labels = new Map(visual.nodes.map((node) => [node.id, node.label]))
  const roles = visual.nodes.filter((node) => node.kind === 'role' || node.kind === 'external_principal')
  return (
    <section>
      <h2 className="font-display text-xl font-semibold">Role index</h2>
      <p className="mt-1 text-sm text-muted-foreground">A compact, complete list of roles and their nearest connections.</p>
      <ul className="mt-3 max-h-[28rem] space-y-2 overflow-y-auto pr-1">
        {roles.map((role) => {
          const connections = visual.edges.filter((edge) => edge.source === role.id || edge.target === role.id)
          return <li key={role.id}><button type="button" onClick={() => onSelect(role)} className="w-full rounded-lg border bg-white p-3 text-left dark:bg-stone-900"><span className="font-mono text-sm font-semibold">{role.label}</span><span className="mt-1 block text-xs text-muted-foreground">{connections.length === 0 ? 'No connections' : connections.slice(0, 3).map((edge) => labels.get(edge.source === role.id ? edge.target : edge.source) ?? edge.label).join(' · ')}{connections.length > 3 ? ` · +${connections.length - 3} more` : ''}</span></button></li>
        })}
      </ul>
    </section>
  )
}

export function PgrolesExplorer() {
  const router = useRouter()
  const fileInput = useRef(null)
  const analysisRun = useRef(0)
  const loadedScenario = useRef(null)
  const initial = DEFAULT_SCENARIO
  const initialExecutor = initial.request.executor
  const [activeScenarioId, setActiveScenarioId] = useState(initial.id)
  const [activeCaseId, setActiveCaseId] = useState('')
  const [scenarioNotice, setScenarioNotice] = useState('')
  const [desiredYaml, setDesiredYaml] = useState(initial.request.desired_yaml)
  const [snapshot, setSnapshot] = useState(initial.request.current)
  const [snapshotName, setSnapshotName] = useState(initial.title)
  const [executorRole, setExecutorRole] = useState(initialExecutor.role)
  const [executorSuperuser, setExecutorSuperuser] = useState(initialExecutor.superuser)
  const [executorMemberships, setExecutorMemberships] = useState(initialExecutor.memberships)
  const [newMembershipSetRole, setNewMembershipSetRole] = useState(initialExecutor.new_membership_set_role)
  const [newRoleSetRole, setNewRoleSetRole] = useState(initialExecutor.new_role_set_role)
  const [newRoleInherit, setNewRoleInherit] = useState(initialExecutor.new_role_inherit)
  const [newRoleAdminOption, setNewRoleAdminOption] = useState(initialExecutor.new_role_admin_option)
  const [mode, setMode] = useState(initial.request.mode)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showGraph, setShowGraph] = useState(false)
  const [selectedNode, setSelectedNode] = useState(null)

  const snapshotRoles = snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot.roles) && snapshot.roles && typeof snapshot.roles === 'object' ? snapshot.roles : null
  const executorInSnapshot = snapshotRoles !== null && Object.prototype.hasOwnProperty.call(snapshotRoles, executorRole)
  const effectiveExecutorSuperuser = executorInSnapshot ? snapshotRoles[executorRole]?.superuser === true : executorSuperuser
  const findingsBySeverity = useMemo(() => result?.findings ?? [], [result])
  const errorCount = useMemo(() => findingsBySeverity.filter((finding) => finding.severity === 'error').length, [findingsBySeverity])
  const activeScenario = getExplorerScenario(activeScenarioId) ?? initial

  function clearAnalysis() {
    analysisRun.current += 1
    setResult(null)
    setSelectedNode(null)
    setLoading(false)
  }

  useEffect(() => {
    if (!router.isReady) return
    const queryValue = Array.isArray(router.query.scenario) ? router.query.scenario[0] : router.query.scenario
    const queryKey = queryValue ?? DEFAULT_SCENARIO.id
    if (loadedScenario.current === queryKey) return
    loadedScenario.current = queryKey
    const scenario = getExplorerScenario(queryValue) ?? DEFAULT_SCENARIO
    const requestExecutor = scenario.request.executor
    setScenarioNotice(queryValue && !getExplorerScenario(queryValue) ? `Unknown scenario “${queryValue}”. Showing ${DEFAULT_SCENARIO.title}.` : '')
    setActiveScenarioId(scenario.id)
    setActiveCaseId('')
    setDesiredYaml(scenario.request.desired_yaml)
    setSnapshot(scenario.request.current)
    setSnapshotName(scenario.title)
    setExecutorRole(requestExecutor.role)
    setExecutorSuperuser(requestExecutor.superuser)
    setExecutorMemberships(requestExecutor.memberships ?? [])
    setNewMembershipSetRole(requestExecutor.new_membership_set_role ?? 'unknown')
    setNewRoleSetRole(requestExecutor.new_role_set_role ?? 'unknown')
    setNewRoleInherit(requestExecutor.new_role_inherit ?? 'unknown')
    setNewRoleAdminOption(requestExecutor.new_role_admin_option ?? 'unknown')
    setMode(scenario.request.mode)
    analysisRun.current += 1
    setResult(null)
    setSelectedNode(null)
    setLoading(false)
    setError('')
  }, [router.isReady, router.query.scenario])

  function selectScenario(id) {
    router.push({ pathname: router.pathname, query: { scenario: id } }, undefined, { shallow: true })
  }

  function selectScenarioCase(caseId) {
    setActiveCaseId(caseId)
    const scenarioCase = activeScenario.cases?.find((candidate) => candidate.id === caseId)
    const overrides = scenarioCase?.requestOverrides ?? {}
    const caseExecutor = overrides.executor ?? activeScenario.request.executor
    setMode(overrides.mode ?? activeScenario.request.mode)
    setExecutorRole(caseExecutor.role)
    setExecutorSuperuser(caseExecutor.superuser)
    setExecutorMemberships(caseExecutor.memberships ?? [])
    setNewMembershipSetRole(caseExecutor.new_membership_set_role ?? 'unknown')
    setNewRoleSetRole(caseExecutor.new_role_set_role ?? 'unknown')
    setNewRoleInherit(caseExecutor.new_role_inherit ?? 'unknown')
    setNewRoleAdminOption(caseExecutor.new_role_admin_option ?? 'unknown')
    clearAnalysis()
    setError('')
  }

  async function importSnapshot(event) {
    const file = event.target.files?.[0]
    if (!file) return
    clearAnalysis()
    const run = analysisRun.current
    setError('')
    try {
      validateSnapshotFileSize(file.size)
      const parsed = explorerImport(JSON.parse(await file.text()))
      if (analysisRun.current !== run) return
      setSnapshot(parsed.current)
      setSnapshotName(file.name)
      setActiveCaseId('custom')
      if (parsed.executor?.role) setExecutorRole(parsed.executor.role)
      setExecutorSuperuser(Boolean(parsed.executor?.superuser))
      setExecutorMemberships(parsed.executor?.memberships ?? [])
      setNewMembershipSetRole(parsed.executor?.new_membership_set_role ?? 'unknown')
      setNewRoleSetRole(parsed.executor?.new_role_set_role ?? 'unknown')
      setNewRoleInherit(parsed.executor?.new_role_inherit ?? 'unknown')
      setNewRoleAdminOption(parsed.executor?.new_role_admin_option ?? 'unknown')
    } catch (readError) {
      if (analysisRun.current === run) {
        setError(`Could not read snapshot: ${readableWasmError(readError)}`)
      }
    } finally {
      event.target.value = ''
    }
  }

  async function runAnalysis() {
    const run = ++analysisRun.current
    setLoading(true)
    setError('')
    try {
      const analyze = await loadAnalyzer(router.basePath)
      const request = analyzeRequest({ current: snapshot, desiredYaml, mode, executorRole, executorSuperuser: effectiveExecutorSuperuser, executorMemberships, newMembershipSetRole, newRoleSetRole, newRoleInherit, newRoleAdminOption })
      const nextResult = analyze(request)
      if (analysisRun.current === run) setResult(nextResult)
    } catch (analysisError) {
      if (analysisRun.current === run) {
        setResult(null)
        setError(readableWasmError(analysisError))
      }
    } finally {
      if (analysisRun.current === run) setLoading(false)
    }
  }

  return (
    <div className="not-prose space-y-7">
      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100">
        Analysis runs in this browser. Snapshot and policy data are not uploaded, persisted, added to URLs, or included in telemetry.
      </div>

      {scenarioNotice && <div role="status" className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-100">{scenarioNotice}</div>}

      <section className="rounded-2xl border bg-white p-5 dark:bg-stone-900">
        <p className="text-xs font-semibold tracking-wider text-amber-700 uppercase dark:text-amber-300">Acme scenario</p>
        <h2 className="mt-1 font-display text-xl font-semibold">{activeScenario.title}</h2>
        <p className="mt-2 text-sm text-muted-foreground">{activeScenario.description}</p>
        <p className="mt-3 text-sm leading-6">{activeScenario.explanation}</p>
        <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-sm font-semibold">
          {activeScenario.relatedDocs.map((related) => <Link key={related.href} href={related.href} className="text-amber-700 underline-offset-4 hover:underline dark:text-amber-300">{related.label} <span aria-hidden="true">→</span></Link>)}
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,.8fr)]">
        <div className="overflow-hidden rounded-2xl border bg-white dark:bg-stone-900">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
            <div><h2 className="font-display text-base font-semibold">Desired YAML</h2><p className="text-xs text-muted-foreground">Edit locally, then analyze the plan.</p></div>
            <select aria-label="Load bundled scenario" value={activeScenarioId} onChange={(event) => selectScenario(event.target.value)} className="rounded-md border bg-transparent px-3 py-2 text-sm">{explorerScenarios.map((scenario) => <option key={scenario.id} value={scenario.id}>{scenario.title}</option>)}</select>
          </div>
          <textarea aria-label="Desired YAML" spellCheck="false" value={desiredYaml} onChange={(event) => { setDesiredYaml(event.target.value); clearAnalysis() }} className="min-h-[28rem] w-full resize-y bg-stone-950 p-4 font-mono text-[13px] leading-6 text-stone-100 outline-none" />
        </div>

        <div className="space-y-5">
          <section className="rounded-2xl border bg-white p-5 dark:bg-stone-900">
            <h2 className="font-display text-base font-semibold">Current snapshot</h2>
            <p className="mt-1 break-all text-sm text-muted-foreground">{snapshotName}</p>
            <input ref={fileInput} type="file" accept="application/json,.json" onChange={importSnapshot} className="sr-only" />
            <button type="button" onClick={() => fileInput.current?.click()} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-semibold hover:bg-stone-50 dark:hover:bg-stone-800"><IconFileUpload className="size-4" /> Import sanitized JSON</button>
          </section>
          <section className="space-y-4 rounded-2xl border bg-white p-5 dark:bg-stone-900">
            {activeScenario.cases?.some((scenarioCase) => scenarioCase.requestOverrides.executor) && (
              <div>
                <label className="block text-sm font-medium">
                  Executor facts
                  <select aria-label="Executor facts variant" value={activeCaseId} onChange={(event) => selectScenarioCase(event.target.value)} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 text-sm">
                    <option value="">Scenario default: INHERIT unknown</option>
                    <option value="custom" disabled>Custom / imported facts</option>
                    {activeScenario.cases.filter((scenarioCase) => scenarioCase.requestOverrides.executor).map((scenarioCase) => <option key={scenarioCase.id} value={scenarioCase.id}>{scenarioCase.title ?? humanize(scenarioCase.id)}</option>)}
                  </select>
                </label>
                {activeCaseId && activeCaseId !== 'custom' && <p className="mt-2 text-xs leading-5 text-muted-foreground">{activeScenario.cases.find((scenarioCase) => scenarioCase.id === activeCaseId)?.description}</p>}
              </div>
            )}
            <label className="block text-sm font-medium">Executor role<input value={executorRole} onChange={(event) => { setExecutorRole(event.target.value); setActiveCaseId('custom'); clearAnalysis() }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 font-mono text-sm" /></label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={effectiveExecutorSuperuser} disabled={executorInSnapshot} onChange={(event) => { setExecutorSuperuser(event.target.checked); setActiveCaseId('custom'); clearAnalysis() }} /> Executor is a superuser {executorInSnapshot && <span className="text-xs text-muted-foreground">From snapshot</span>}</label>
            <label className="block text-sm font-medium">New membership SET ROLE<select value={newMembershipSetRole} onChange={(event) => { setNewMembershipSetRole(event.target.value); setActiveCaseId('custom'); clearAnalysis() }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 text-sm"><option value="allowed">Allowed (PostgreSQL 16+ default)</option><option value="denied">Denied</option><option value="unknown">Unknown</option></select></label>
            <label className="block text-sm font-medium">Reconciliation mode<select value={mode} onChange={(event) => { setMode(event.target.value); clearAnalysis() }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 text-sm"><option value="authoritative">Authoritative</option><option value="additive">Additive</option><option value="adopt">Adopt</option></select></label>
            <button type="button" onClick={runAnalysis} disabled={loading || !executorRole.trim()} className="flex w-full items-center justify-center gap-2 rounded-lg bg-amber-500 px-4 py-3 font-semibold text-stone-950 hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50">
              {loading ? <IconLoader2 className="size-5 animate-spin" /> : <IconPlayerPlay className="size-5" />} {loading ? 'Loading analyzer…' : 'Analyze plan'}
            </button>
            <p className="text-xs leading-5 text-muted-foreground">The WASM module is downloaded only after you choose Analyze plan.</p>
          </section>
        </div>
      </section>

      {error && <div role="alert" className="flex gap-3 rounded-xl border border-red-300 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900 dark:bg-red-950/30 dark:text-red-100"><IconAlertTriangle className="mt-0.5 size-5 shrink-0" /><div><strong>Analysis failed</strong><p className="mt-1 whitespace-pre-wrap">{error}</p></div></div>}

      {result && <section aria-live="polite" className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-xl border bg-white p-4 dark:bg-stone-900"><span className="text-xs text-muted-foreground">Changes</span><strong className="mt-1 block text-2xl">{result.changes.length}</strong></div>
          <div className="rounded-xl border bg-white p-4 dark:bg-stone-900"><span className="text-xs text-muted-foreground">Findings</span><strong className="mt-1 block text-2xl">{result.findings.length}</strong>{errorCount > 0 && <span className="mt-1 block text-xs font-semibold text-red-700 dark:text-red-300">{errorCount} error{errorCount === 1 ? '' : 's'}</span>}</div>
          <div className="min-w-0 rounded-xl border bg-white p-4 dark:bg-stone-900"><span className="text-xs text-muted-foreground">Illustrative plan fingerprint</span><code className="mt-1 block truncate text-sm" title={result.plan_fingerprint}>{result.plan_fingerprint}</code></div>
        </div>
        <p className="rounded-lg bg-stone-200/60 px-4 py-3 text-xs leading-5 text-muted-foreground dark:bg-stone-800/60">This fingerprint identifies the effects, mode, and executor facts supplied to this browser analysis. It is not an approval token and does not include verified target identity or the full execution context.</p>

        {findingsBySeverity.length > 0 && <div><h2 className="font-display text-xl font-semibold">Authority findings</h2><ul className="mt-3 space-y-2">{findingsBySeverity.map((finding, index) => <FindingItem key={index} finding={finding} changes={result.changes} />)}</ul></div>}

        <div><h2 className="font-display text-xl font-semibold">Execution phases</h2><p className="mt-1 mb-5 text-sm text-muted-foreground">Each boundary is simulated by pgroles-core before the next phase is evaluated.</p><PhaseTimeline phases={result.phases} focusPhase={activeScenario.focusPhase} /></div>

        <RoleAdjacency visual={result.visual} onSelect={setSelectedNode} />
        <div>
          <button type="button" onClick={() => setShowGraph((visible) => !visible)} aria-expanded={showGraph} className="flex w-full items-center justify-between rounded-xl border bg-white p-4 text-left font-semibold dark:bg-stone-900"><span className="flex items-center gap-2"><IconNetwork className="size-5"/> Resulting role graph</span><IconChevronRight className={`size-5 transition ${showGraph ? 'rotate-90' : ''}`}/></button>
          {showGraph && <div className="mt-3"><p className="mb-2 text-xs text-muted-foreground">Scroll to explore. Select a node for role and connection details.</p><Graph visual={result.visual} onSelect={setSelectedNode}/></div>}
        </div>
      </section>}
      <RoleSheet node={selectedNode} edges={result?.visual?.edges ?? []} onClose={() => setSelectedNode(null)} />
    </div>
  )
}
