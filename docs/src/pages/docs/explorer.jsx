import Head from 'next/head'
import Link from 'next/link'

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
        <p className="mt-3 text-muted-foreground">Author a policy <span aria-hidden="true"> · </span> Compare a snapshot <span aria-hidden="true"> · </span> Open a recorded review</p>
        <p className="mt-4 max-w-3xl text-lg leading-8 text-muted-foreground">Validate a policy and inspect its expansion without a database snapshot. Then compare it with a sanitized snapshot: the same Rust planner used by pgroles produces ordered changes, phase analysis, findings, and a graph.</p>
        <p className="mt-3 text-muted-foreground">Reviewing a native plan? <Link href="/docs/recorded-reviews">Export a recorded review</Link> from the CLI, then open the file below without recalculating it.</p>
      </header>
      <PgrolesExplorer />
    </>
  )
}
