import Link from 'next/link'

import { getExplorerScenario } from '@/lib/explorerScenarios.mjs'

export function ExplorerScenario({ scenario }) {
  const item = getExplorerScenario(scenario)
  if (!item) return null
  return (
    <aside className="not-prose my-8 rounded-xl border border-teal-200 bg-teal-50 p-5 dark:border-teal-900 dark:bg-teal-950/30">
      <p className="text-sm font-semibold">Explore this change</p>
      <h2 className="mt-1 text-lg font-semibold">{item.title}</h2>
      <p className="mt-2 text-sm text-muted-foreground">{item.description}</p>
      <Link href={`/docs/explorer?scenario=${encodeURIComponent(item.id)}`} className="mt-4 inline-flex rounded-md bg-teal-700 px-3 py-2 text-sm font-semibold text-white">Open in explorer</Link>
    </aside>
  )
}
