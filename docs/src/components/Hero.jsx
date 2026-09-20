import Link from 'next/link'
import { Badge } from '@partly/pitstop/badge'
import { buttonVariants } from '@partly/pitstop/button'
import { Card, CardContent, CardHeader, CardTitle } from '@partly/pitstop/card'

const manifestSnippet = `profiles:
  writer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, TRIGGER]
        object: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        object: { type: sequence, name: "*" }`

const planSnippet = `Plan: 4 change(s)
  1 role(s) to create
  2 grant(s) to add
  1 default privilege(s) to set`

const statusSnippet = `status:
  conditions:
    - type: Ready
      status: "True"
      reason: Planned
    - type: Drifted
      status: "True"`

export function Hero() {
  return (
    <div className="relative overflow-hidden bg-stone-100 text-stone-900 dark:bg-stone-950 dark:text-stone-100">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(245,158,11,0.18),transparent_24%),radial-gradient(circle_at_82%_12%,rgba(20,184,166,0.12),transparent_24%),linear-gradient(180deg,rgba(255,255,255,0.98),rgba(245,245,244,0.96))] dark:bg-[radial-gradient(circle_at_top_left,rgba(245,158,11,0.28),transparent_26%),radial-gradient(circle_at_78%_8%,rgba(20,184,166,0.2),transparent_24%),linear-gradient(180deg,rgba(12,10,9,0.96),rgba(12,10,9,0.92))]" />
      <div className="absolute inset-0 opacity-[0.08] [background-image:linear-gradient(rgba(28,25,23,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(28,25,23,0.08)_1px,transparent_1px)] [background-size:28px_28px] dark:opacity-[0.08] dark:[background-image:linear-gradient(rgba(255,255,255,0.14)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.14)_1px,transparent_1px)]" />
      <div className="absolute inset-x-0 bottom-0 h-20 bg-[linear-gradient(180deg,rgba(245,245,244,0)_0%,rgba(245,245,244,0.94)_86%,rgb(245,245,244)_100%)] dark:h-24 dark:bg-[linear-gradient(180deg,rgba(12,10,9,0)_0%,rgba(12,10,9,0.92)_88%,rgb(12,10,9)_100%)]" />

      <div className="relative py-14 sm:px-2 lg:py-16">
        <div className="mx-auto grid max-w-8xl grid-cols-1 gap-10 px-4 lg:grid-cols-[0.94fr_1.06fr] lg:gap-12 lg:px-8 xl:px-12">
          <div className="max-w-xl">
            <div className="flex flex-wrap gap-2 text-[11px] font-semibold tracking-[0.2em] uppercase">
              <Badge variant="outline" size="md" className="rounded-full bg-card">
                CLI
              </Badge>
              <Badge variant="outline" size="md" className="rounded-full bg-card">
                Operator
              </Badge>
              <Badge variant="outline" intent="warning" size="md" className="rounded-full">
                Plan before apply
              </Badge>
            </div>

            <h1 className="mt-5 max-w-2xl font-display text-[2.8rem] leading-[1.02] tracking-[-0.04em] text-stone-950 sm:text-[3.35rem] dark:text-stone-50">
              Treat PostgreSQL access like a control plane, not a pile of grants.
            </h1>

            <p className="mt-5 max-w-xl text-lg leading-8 text-stone-700 dark:text-stone-300">
              Define roles, memberships, schema profiles, and default privileges once. Review the exact SQL plan, then let pgroles converge the database and keep drift visible.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              {/* next/link rather than Pitstop's own link-button: React Aria
                  renders the href verbatim, which drops the site's basePath. */}
              <Link
                href="/docs/quick-start"
                className={buttonVariants({ size: 'lg' })}
              >
                Start with a diff
              </Link>
              <Link
                href="/docs/operator-quick-start"
                className={buttonVariants({ variant: 'outline', size: 'lg' })}
              >
                Try the operator
              </Link>
            </div>

            <dl className="mt-9 grid gap-5 border-t border-stone-300/90 pt-5 dark:border-stone-800/90 sm:grid-cols-3">
              <Stat label="Convergent model" value="Manifest is truth" />
              <Stat label="Preview path" value="CLI diff + operator plan" />
              <Stat label="Runtime" value="CI, OTLP, Kubernetes" />
            </dl>
          </div>

          <div className="grid gap-4 lg:pt-3">
            <ConsoleCard
              title="Policy manifest"
              eyebrow="Desired state"
              tone="amber"
              code={manifestSnippet}
            />
            <div className="grid gap-4 lg:grid-cols-[0.92fr_1.08fr]">
              <ConsoleCard
                title="Diff summary"
                eyebrow="Change plan"
                tone="teal"
                code={planSnippet}
              />
              <ConsoleCard
                title="Operator status"
                eyebrow="Control plane"
                tone="stone"
                code={statusSnippet}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">{label}</dt>
      <dd className="mt-2 font-display text-base text-stone-900 dark:text-stone-100">{value}</dd>
    </div>
  )
}

function ConsoleCard({ eyebrow, title, code, tone }) {
  const accents = {
    amber: 'bg-amber-500 dark:bg-amber-400',
    teal: 'bg-teal-500 dark:bg-teal-400',
    stone: 'bg-stone-500 dark:bg-stone-400',
  }

  const rings = {
    amber: 'ring-amber-400/50 dark:ring-amber-500/30',
    teal: 'ring-teal-400/50 dark:ring-teal-500/30',
    stone: 'ring-foreground/10',
  }

  return (
    <Card
      size="sm"
      className={`gap-4 bg-card/90 backdrop-blur ${rings[tone]}`}
    >
      <CardHeader className="flex items-center justify-between gap-4">
        <div>
          <p className="m-0 text-[11px] font-semibold tracking-[0.22em] text-muted-foreground uppercase">
            {eyebrow}
          </p>
          <CardTitle className="mt-2 font-display text-lg">{title}</CardTitle>
        </div>
        <div className="flex gap-1.5">
          <span className={`h-2.5 w-2.5 rounded-full ${accents[tone]}`} />
          <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40" />
          <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40" />
        </div>
      </CardHeader>
      <CardContent>
        <pre className="overflow-x-auto rounded-xl bg-stone-950 p-4 font-mono text-[13px] leading-6 text-stone-200">
          <code>{code}</code>
        </pre>
      </CardContent>
    </Card>
  )
}
