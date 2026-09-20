import Head from 'next/head'

import { PgrolesExplorer } from '@/components/PgrolesExplorer'

export default function ExplorerPage() {
  return (
    <>
      <Head>
        <title>Plan explorer - pgroles docs</title>
        <meta name="description" content="Explore pgroles reconciliation plans locally in your browser." />
      </Head>
      <header className="mb-8">
        <h1 className="font-display text-4xl tracking-[-0.03em] text-stone-950 dark:text-stone-100">Plan explorer</h1>
        <p className="mt-4 max-w-3xl text-lg leading-8 text-muted-foreground">Compare desired policy with a sanitized database snapshot. The same Rust planner used by pgroles produces the ordered changes, phase analysis, findings, and graph.</p>
      </header>
      <PgrolesExplorer />
    </>
  )
}
