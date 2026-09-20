import { useEffect, useRef, useState } from 'react'

import { loadPolicyEngine, policyRequest, readableWasmError } from '@/lib/pgrolesExplorer.mjs'

export function PolicyAuthoring({ desiredYaml, basePath }) {
  const [response, setResponse] = useState(null)
  const [error, setError] = useState('')
  const [pending, setPending] = useState('')
  const requestNumber = useRef(0)

  useEffect(() => {
    requestNumber.current += 1
    setResponse(null)
    setError('')
    setPending('')
    return () => { requestNumber.current += 1 }
  }, [desiredYaml])

  async function run(operation) {
    const request = ++requestNumber.current
    setPending(operation)
    setResponse(null)
    setError('')
    try {
      const engine = await loadPolicyEngine(basePath)
      if (requestNumber.current !== request) return
      const result = engine[operation](policyRequest(desiredYaml))
      setResponse({ result, source: desiredYaml })
    } catch (failure) {
      if (requestNumber.current === request) setError(readableWasmError(failure))
    } finally {
      if (requestNumber.current === request) setPending('')
    }
  }

  const result = response?.source === desiredYaml ? response.result : null
  return (
    <section aria-label="Policy authoring" className="space-y-3 border-t p-4">
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => run('validate')} disabled={Boolean(pending)} className="rounded-lg border px-3 py-2 text-sm font-semibold hover:bg-stone-50 disabled:opacity-50 dark:hover:bg-stone-800">{pending === 'validate' ? 'Validating…' : 'Validate policy'}</button>
        <button type="button" onClick={() => run('compile')} disabled={Boolean(pending)} className="rounded-lg border px-3 py-2 text-sm font-semibold hover:bg-stone-50 disabled:opacity-50 dark:hover:bg-stone-800">{pending === 'compile' ? 'Compiling…' : 'Inspect expansion'}</button>
      </div>
      <p className="text-xs leading-5 text-muted-foreground">Validate and expand without a snapshot or executor. Password-source declarations are checked without reading environment variables or generating passwords; plan analysis excludes them.</p>
      {error && <p role="alert" className="break-words text-sm text-red-700 dark:text-red-300">Could not load policy tools: {error}</p>}
      {result && <div aria-live="polite" className="min-w-0 space-y-3">
        <h3 className="font-semibold">{result.policy ? 'Compiled policy' : 'Policy validation'}</h3>
        {result.diagnostics.length === 0
          ? <p className="text-sm text-green-800 dark:text-green-300">Policy is valid. No database state or execution authority has been checked.</p>
          : <ul className="space-y-2">{result.diagnostics.map((diagnostic, index) => <li key={index} className="break-words rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950/30 dark:text-red-100">
            <strong>{diagnostic.code}</strong>{diagnostic.path && <code className="ml-2">{diagnostic.path}</code>}
            <p className="mt-1">{diagnostic.message}</p>
          </li>)}</ul>}
        {result.policy && <>
          <p className="text-sm">{result.policy.expanded.roles.length} expanded roles · {result.policy.expanded.grants.length} grants · {result.policy.expanded.memberships.length} memberships</p>
          <ul aria-label="Expanded role names" className="flex flex-wrap gap-2">{result.policy.expanded.roles.map((role) => <li key={role.name} className="max-w-full break-all rounded bg-stone-100 px-2 py-1 font-mono text-xs dark:bg-stone-800">{role.name}</li>)}</ul>
          <details className="min-w-0 rounded-lg border p-3">
            <summary className="cursor-pointer text-sm font-semibold">Expanded policy and desired graph</summary>
            <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(result.policy, null, 2)}</pre>
          </details>
        </>}
      </div>}
    </section>
  )
}
