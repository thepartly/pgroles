import { useMemo, useRef, useState } from 'react'
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
} from '@/lib/pgrolesExplorer.mjs'

const examples = {
  onboarding: {
    label: 'Brownfield onboarding',
    executor: 'platform_admin',
    superuser: false,
    snapshot: {
      roles: {
        app_reader: {},
        analyst: { login: true },
      },
      schemas: { app: { owner: 'platform_admin' } },
      grants: [
        { role: 'app_reader', object_type: 'table', schema: 'app', name: '*', privileges: ['SELECT'] },
      ],
      memberships: [
        { role: 'app_reader', member: 'analyst', inherit: true, admin: false },
      ],
    },
    yaml: `default_owner: platform_admin

roles:
  - name: platform_admin
    external: true

profiles:
  reader:
    grants:
      - object: { type: schema }
        privileges: [USAGE]
      - object: { type: table, name: "*" }
        privileges: [SELECT]

schemas:
  - name: app
    profiles: [reader]

memberships:
  - role: app-reader
    members:
      - name: reporting_service
`,
  },
  empty: {
    label: 'New database',
    executor: 'postgres',
    superuser: true,
    snapshot: {},
    yaml: `default_owner: postgres

roles:
  - name: application
    login: true
  - name: application_reader

memberships:
  - role: application_reader
    members:
      - name: application
`,
  },
}

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

function PhaseTimeline({ phases }) {
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
          <details className="mt-2 rounded-md bg-stone-200/60 px-3 py-2 text-xs dark:bg-stone-800/60">
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

function Graph({ visual, onSelect }) {
  const [zoom, setZoom] = useState(1)
  const width = Math.max(720, visual.nodes.length * 150)
  const positions = new Map(visual.nodes.map((node, index) => {
    const angle = (index / Math.max(visual.nodes.length, 1)) * Math.PI * 2
    return [node.id, { x: width / 2 + Math.cos(angle) * width * 0.34, y: 230 + Math.sin(angle) * 165 }]
  }))
  return (
    <div className="rounded-xl border bg-[radial-gradient(circle_at_1px_1px,rgba(120,113,108,.22)_1px,transparent_0)] bg-[size:20px_20px]">
      <div className="flex justify-end gap-1 border-b bg-white/80 p-2 dark:bg-stone-900/80">
        <button type="button" aria-label="Zoom graph out" onClick={() => setZoom((value) => Math.max(.6, value - .2))} className="rounded p-2 hover:bg-stone-100 dark:hover:bg-stone-800"><IconZoomOut className="size-4" /></button>
        <span className="min-w-12 py-2 text-center text-xs text-muted-foreground">{Math.round(zoom * 100)}%</span>
        <button type="button" aria-label="Zoom graph in" onClick={() => setZoom((value) => Math.min(1.8, value + .2))} className="rounded p-2 hover:bg-stone-100 dark:hover:bg-stone-800"><IconZoomIn className="size-4" /></button>
      </div>
      <div className="overflow-auto p-3" style={{ touchAction: 'pan-x pan-y' }}>
        <svg viewBox={`0 0 ${width} 460`} width={width * zoom} height={460 * zoom} role="img" aria-label="Resulting role and privilege graph">
          <defs><marker id="explorer-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" className="fill-teal-600" /></marker></defs>
          {visual.edges.map((edge, index) => {
            const source = positions.get(edge.source); const target = positions.get(edge.target)
            if (!source || !target) return null
            return <line key={index} x1={source.x} y1={source.y} x2={target.x} y2={target.y} className="stroke-teal-600" strokeWidth="2" markerEnd="url(#explorer-arrow)" />
          })}
          {visual.nodes.map((node) => {
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

export function PgrolesExplorer() {
  const router = useRouter()
  const fileInput = useRef(null)
  const initial = examples.onboarding
  const [desiredYaml, setDesiredYaml] = useState(initial.yaml)
  const [snapshot, setSnapshot] = useState(initial.snapshot)
  const [snapshotName, setSnapshotName] = useState('Bundled example')
  const [executorRole, setExecutorRole] = useState(initial.executor)
  const [executorSuperuser, setExecutorSuperuser] = useState(initial.superuser)
  const [executorMemberships, setExecutorMemberships] = useState([])
  const [newMembershipSetRole, setNewMembershipSetRole] = useState('allowed')
  const [newRoleSetRole, setNewRoleSetRole] = useState('unknown')
  const [newRoleInherit, setNewRoleInherit] = useState('unknown')
  const [newRoleAdminOption, setNewRoleAdminOption] = useState('unknown')
  const [mode, setMode] = useState('authoritative')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showGraph, setShowGraph] = useState(false)
  const [selectedNode, setSelectedNode] = useState(null)

  const findingsBySeverity = useMemo(() => result?.findings ?? [], [result])

  function selectExample(key) {
    const example = examples[key]
    setDesiredYaml(example.yaml)
    setSnapshot(example.snapshot)
    setSnapshotName(example.label)
    setExecutorRole(example.executor)
    setExecutorSuperuser(example.superuser)
    setExecutorMemberships([])
    setNewMembershipSetRole('allowed')
    setNewRoleSetRole('unknown')
    setNewRoleInherit('unknown')
    setNewRoleAdminOption('unknown')
    setResult(null)
    setError('')
  }

  async function importSnapshot(event) {
    const file = event.target.files?.[0]
    if (!file) return
    try {
      const parsed = explorerImport(JSON.parse(await file.text()))
      setSnapshot(parsed.current)
      setSnapshotName(file.name)
      if (parsed.executor?.role) setExecutorRole(parsed.executor.role)
      setExecutorSuperuser(Boolean(parsed.executor?.superuser))
      setExecutorMemberships(parsed.executor?.memberships ?? [])
      setNewMembershipSetRole(parsed.executor?.new_membership_set_role ?? 'unknown')
      setNewRoleSetRole(parsed.executor?.new_role_set_role ?? 'unknown')
      setNewRoleInherit(parsed.executor?.new_role_inherit ?? 'unknown')
      setNewRoleAdminOption(parsed.executor?.new_role_admin_option ?? 'unknown')
      setResult(null)
      setError('')
    } catch (readError) {
      setError(`Could not read snapshot: ${readableWasmError(readError)}`)
    } finally {
      event.target.value = ''
    }
  }

  async function runAnalysis() {
    setLoading(true)
    setError('')
    try {
      const analyze = await loadAnalyzer(router.basePath)
      const request = analyzeRequest({ current: snapshot, desiredYaml, mode, executorRole, executorSuperuser, executorMemberships, newMembershipSetRole, newRoleSetRole, newRoleInherit, newRoleAdminOption })
      setResult(analyze(request))
    } catch (analysisError) {
      setResult(null)
      setError(readableWasmError(analysisError))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="not-prose space-y-7">
      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100">
        Analysis runs in this browser. Snapshot and policy data are not uploaded, persisted, added to URLs, or included in telemetry.
      </div>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,.8fr)]">
        <div className="overflow-hidden rounded-2xl border bg-white dark:bg-stone-900">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
            <div><h2 className="font-display text-base font-semibold">Desired YAML</h2><p className="text-xs text-muted-foreground">Edit locally, then analyze the plan.</p></div>
            <select aria-label="Load bundled example" defaultValue="onboarding" onChange={(event) => selectExample(event.target.value)} className="rounded-md border bg-transparent px-3 py-2 text-sm"><option value="onboarding">Brownfield example</option><option value="empty">New database example</option></select>
          </div>
          <textarea aria-label="Desired YAML" spellCheck="false" value={desiredYaml} onChange={(event) => { setDesiredYaml(event.target.value); setResult(null) }} className="min-h-[28rem] w-full resize-y bg-stone-950 p-4 font-mono text-[13px] leading-6 text-stone-100 outline-none" />
        </div>

        <div className="space-y-5">
          <section className="rounded-2xl border bg-white p-5 dark:bg-stone-900">
            <h2 className="font-display text-base font-semibold">Current snapshot</h2>
            <p className="mt-1 break-all text-sm text-muted-foreground">{snapshotName}</p>
            <input ref={fileInput} type="file" accept="application/json,.json" onChange={importSnapshot} className="sr-only" />
            <button type="button" onClick={() => fileInput.current?.click()} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-semibold hover:bg-stone-50 dark:hover:bg-stone-800"><IconFileUpload className="size-4" /> Import sanitized JSON</button>
          </section>
          <section className="space-y-4 rounded-2xl border bg-white p-5 dark:bg-stone-900">
            <label className="block text-sm font-medium">Executor role<input value={executorRole} onChange={(event) => { setExecutorRole(event.target.value); setResult(null) }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 font-mono text-sm" /></label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={executorSuperuser} onChange={(event) => { setExecutorSuperuser(event.target.checked); setResult(null) }} /> Executor is a superuser</label>
            <label className="block text-sm font-medium">New membership SET ROLE<select value={newMembershipSetRole} onChange={(event) => { setNewMembershipSetRole(event.target.value); setResult(null) }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 text-sm"><option value="allowed">Allowed (PostgreSQL 16+ default)</option><option value="denied">Denied</option><option value="unknown">Unknown</option></select></label>
            <label className="block text-sm font-medium">Reconciliation mode<select value={mode} onChange={(event) => { setMode(event.target.value); setResult(null) }} className="mt-1 block w-full rounded-md border bg-transparent px-3 py-2 text-sm"><option value="authoritative">Authoritative</option><option value="additive">Additive</option><option value="adopt">Adopt</option></select></label>
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
          <div className="rounded-xl border bg-white p-4 dark:bg-stone-900"><span className="text-xs text-muted-foreground">Findings</span><strong className="mt-1 block text-2xl">{result.findings.length}</strong></div>
          <div className="min-w-0 rounded-xl border bg-white p-4 dark:bg-stone-900"><span className="text-xs text-muted-foreground">Illustrative plan fingerprint</span><code className="mt-1 block truncate text-sm" title={result.plan_fingerprint}>{result.plan_fingerprint}</code></div>
        </div>
        <p className="rounded-lg bg-stone-200/60 px-4 py-3 text-xs leading-5 text-muted-foreground dark:bg-stone-800/60">This fingerprint identifies the effects, mode, and executor facts supplied to this browser analysis. It is not an approval token and does not include verified target identity or the full execution context.</p>

        {findingsBySeverity.length > 0 && <div><h2 className="font-display text-xl font-semibold">Authority findings</h2><ul className="mt-3 space-y-2">{findingsBySeverity.map((finding, index) => <li key={index} className="flex gap-3 rounded-lg border bg-white p-3 text-sm dark:bg-stone-900"><IconAlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-600"/><span>{(finding.phase || finding.change_index != null) && <span className="mb-1 block text-xs font-semibold text-muted-foreground">{finding.phase ? humanize(finding.phase) : 'Plan'}{finding.change_index != null && result.changes[finding.change_index] ? ` · ${changeLabel(result.changes[finding.change_index])}` : ''}</span>}{finding.message}</span></li>)}</ul></div>}

        <div><h2 className="font-display text-xl font-semibold">Execution phases</h2><p className="mt-1 mb-5 text-sm text-muted-foreground">Each boundary is simulated by pgroles-core before the next phase is evaluated.</p><PhaseTimeline phases={result.phases} /></div>

        <div>
          <button type="button" onClick={() => setShowGraph((visible) => !visible)} aria-expanded={showGraph} className="flex w-full items-center justify-between rounded-xl border bg-white p-4 text-left font-semibold dark:bg-stone-900"><span className="flex items-center gap-2"><IconNetwork className="size-5"/> Resulting role graph</span><IconChevronRight className={`size-5 transition ${showGraph ? 'rotate-90' : ''}`}/></button>
          {showGraph && <div className="mt-3"><p className="mb-2 text-xs text-muted-foreground">Scroll to explore. Select a node for role and connection details.</p><Graph visual={result.visual} onSelect={setSelectedNode}/></div>}
        </div>
      </section>}
      <RoleSheet node={selectedNode} edges={result?.visual?.edges ?? []} onClose={() => setSelectedNode(null)} />
    </div>
  )
}
