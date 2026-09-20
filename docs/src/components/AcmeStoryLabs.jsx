import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import Highlight, { defaultProps } from "prism-react-renderer";

import { chapters } from "./AcmeStoryData.mjs";
import { runLabStep } from "./labExecution.mjs";

const statusStyles = {
  pass: "border-emerald-400 bg-emerald-50 dark:border-emerald-700 dark:bg-emerald-950/25",
  blocked:
    "border-rose-400 bg-rose-50 dark:border-rose-700 dark:bg-rose-950/25",
  focus:
    "border-amber-400 bg-amber-50 dark:border-amber-600 dark:bg-amber-950/25",
  neutral:
    "border-stone-300 bg-stone-50 dark:border-stone-700 dark:bg-stone-800/50",
};

function normalizeSql(sql) {
  return sql
    .trim()
    .replace(/;+\s*$/, "")
    .replace(/\s+/g, " ")
    .toLowerCase();
}

function SqlEditor({ value, onChange, disabled }) {
  const highlightRef = useRef(null);
  return (
    <div className="relative min-h-[8rem] overflow-hidden rounded-xl border border-stone-700 bg-[#0c0e12] focus-within:border-amber-400 focus-within:ring-2 focus-within:ring-amber-400/20">
      <pre
        ref={highlightRef}
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 m-0 min-h-[8rem] overflow-hidden whitespace-pre p-4 font-mono text-xs leading-6 text-stone-200"
      >
        <code>
          <Highlight
            {...defaultProps}
            code={value || " "}
            language="sql"
            theme={undefined}
          >
            {({ tokens, getTokenProps }) =>
              tokens.map((line, lineIndex) => (
                <Fragment key={lineIndex}>
                  <span>
                    {line
                      .filter((token) => !token.empty)
                      .map((token, tokenIndex) => (
                        <span key={tokenIndex} {...getTokenProps({ token })} />
                      ))}
                  </span>
                  {lineIndex < tokens.length - 1 ? "\n" : null}
                </Fragment>
              ))
            }
          </Highlight>
        </code>
      </pre>
      <textarea
        aria-label="Editable SQL"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={(event) => {
          if (highlightRef.current) {
            highlightRef.current.scrollTop = event.currentTarget.scrollTop;
            highlightRef.current.scrollLeft = event.currentTarget.scrollLeft;
          }
        }}
        disabled={disabled}
        wrap="off"
        spellCheck="false"
        className="relative z-10 m-0 min-h-[8rem] w-full resize-y overflow-auto border-0 bg-transparent p-4 font-mono text-xs leading-6 text-transparent outline-none selection:bg-amber-300/30 disabled:cursor-wait"
        style={{ caretColor: "#f5f5f4", WebkitTextFillColor: "transparent" }}
      />
    </div>
  );
}

function ResultGrid({ result }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-stone-700">
      <table className="min-w-full border-collapse font-mono text-xs">
        <thead className="bg-stone-800 text-left text-stone-300">
          <tr>
            {result.fields.map((field) => (
              <th
                key={field}
                className="border-b border-stone-700 px-3 py-2 font-medium"
              >
                {field}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {result.rows.length ? (
            result.rows.map((row, index) => (
              <tr
                key={index}
                className="border-b border-stone-800 last:border-0"
              >
                {result.fields.map((field) => (
                  <td key={field} className="px-3 py-2 text-stone-200">
                    {row[field] === null ? "NULL" : String(row[field])}
                  </td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td
                colSpan={result.fields.length}
                className="px-3 py-3 text-stone-500"
              >
                (0 rows)
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Output({ output, running, expectedError }) {
  if (running)
    return (
      <p className="m-0 text-sm text-stone-300">
        Starting PostgreSQL and running the query…
      </p>
    );
  if (!output)
    return (
      <p className="m-0 text-sm text-stone-400">
        PostgreSQL’s rows, command tags, or exact error will appear here.
      </p>
    );
  return (
    <div className="space-y-3">
      {output.commands.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {output.commands.map((command, index) => (
            <span
              key={`${command}-${index}`}
              className="rounded-md border border-stone-700 bg-stone-800 px-2 py-1 font-mono text-[10px] text-stone-300"
            >
              {command}
            </span>
          ))}
        </div>
      )}
      {output.results.map((result, index) => (
        <ResultGrid key={index} result={result} />
      ))}
      {output.error && (
        <div
          className={`rounded-xl border px-4 py-3 font-mono text-xs ${
            expectedError
              ? "border-amber-700/70 bg-amber-950/35 text-amber-200"
              : "border-red-800 bg-red-950/40 text-red-200"
          }`}
        >
          <strong>ERROR:</strong> {output.error}
        </div>
      )}
    </div>
  );
}

function AccessPath({ cards }) {
  return (
    <figure className="m-0 rounded-2xl border border-stone-200 bg-stone-50/60 p-3 dark:border-stone-700 dark:bg-stone-950/30">
      <figcaption className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-stone-500 dark:text-stone-400">
        What PostgreSQL sees now
      </figcaption>
      <ol className="m-0 grid list-none gap-2 p-0 sm:auto-cols-fr sm:grid-flow-col">
        {cards.map(([label, value, status]) => (
          <li
            key={label}
            className={`m-0 rounded-lg border-l-4 px-3 py-2 ${statusStyles[status]}`}
          >
            <span className="block font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-stone-500 dark:text-stone-400">
              {label}
            </span>
            <span className="mt-1 block text-xs font-semibold text-stone-900 dark:text-stone-100">
              {value}
            </span>
          </li>
        ))}
      </ol>
    </figure>
  );
}

function ExecutionContext({ output }) {
  if (!output?.identity) return null;
  const before = output.identity.before;
  const after = output.identity.after;
  const actorInspection = output.actorInspection ?? {};
  return (
    <section aria-label="Execution identity" className="rounded-2xl border border-stone-200 bg-stone-50/60 p-4 dark:border-stone-700 dark:bg-stone-950/30">
      <h4 className="m-0 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-stone-500 dark:text-stone-400">Execution identity</h4>
      <p className="mb-0 mt-2 text-xs leading-5 text-stone-500 dark:text-stone-400">Before and after show the caller context. A SECURITY DEFINER function can use its owner as <code>current_user</code> while the function is running.</p>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        {[["Before SQL", before], ["After SQL", after]].map(([label, identity]) => (
          <div key={label} className="rounded-lg border border-stone-200 bg-white p-3 dark:border-stone-700 dark:bg-stone-900">
            <p className="m-0 text-xs font-semibold">{label}</p>
            <p className="mb-0 mt-2 font-mono text-xs"><span className="text-stone-500">session_user</span> {identity?.session_user ?? "unknown"} <span aria-hidden="true">→</span> <span className="text-stone-500">current_user</span> {identity?.current_user ?? "unknown"}</p>
          </div>
        ))}
      </div>
      {Object.hasOwn(actorInspection, "table_select") && (
        <dl className="mb-0 mt-3 grid gap-2 text-xs sm:grid-cols-2">
          <div className="rounded-lg border border-stone-200 bg-white p-3 dark:border-stone-700 dark:bg-stone-900"><dt className="font-semibold">Table SELECT</dt><dd className="mb-0 mt-1 font-mono">{actorInspection.table_select ? "allowed" : "denied"}</dd></div>
          <div className="rounded-lg border border-stone-200 bg-white p-3 dark:border-stone-700 dark:bg-stone-900"><dt className="font-semibold">Row security active</dt><dd className="mb-0 mt-1 font-mono">{actorInspection.row_security_active ? "yes" : "no"}</dd></div>
        </dl>
      )}
    </section>
  );
}

function AcmeStoryLab({ chapter }) {
  const lesson = chapters[chapter];
  const [index, setIndex] = useState(0);
  const [drafts, setDrafts] = useState(() =>
    lesson.steps.map((step) => step.sql)
  );
  const [roles, setRoles] = useState(() =>
    lesson.steps.map((step) => step.role)
  );
  const [outputs, setOutputs] = useState({});
  const [running, setRunning] = useState(false);
  const liveRef = useRef(true);
  // Render-scoped `running` cannot stop two clicks in the same tick, so the
  // in-flight guard lives in a ref.
  const runningRef = useRef(false);
  const step = lesson.steps[index];
  const output = outputs[index];
  const draft = drafts[index];
  const role = roles[index];
  const canonical =
    normalizeSql(draft) === normalizeSql(step.sql) && role === step.role;
  const completed = useMemo(
    () => lesson.steps.map((_, stepIndex) => outputs[stepIndex]?.passed),
    [lesson.steps, outputs]
  );

  useEffect(
    () => () => {
      liveRef.current = false;
    },
    []
  );

  async function run() {
    if (runningRef.current || !draft.trim()) return;
    runningRef.current = true;
    setRunning(true);
    try {
      const { PGlite } = await import("@electric-sql/pglite");
      const next = await runLabStep({
        createDatabase: () => PGlite.create(),
        setup: step.setup,
        role,
        sql: draft,
        inspect: step.inspect,
        inspectAsActor: step.inspectAsActor,
      });
      next.passed = canonical && Boolean(step.expect(next, next.inspection));
      if (liveRef.current)
        setOutputs((current) => ({ ...current, [index]: next }));
    } catch (error) {
      if (liveRef.current)
        setOutputs((current) => ({
          ...current,
          [index]: {
            commands: [],
            results: [],
            error: error.message,
            passed: false,
            inspection: null,
          },
        }));
    } finally {
      runningRef.current = false;
      if (liveRef.current) setRunning(false);
    }
  }

  function updateDraft(value) {
    setDrafts((current) =>
      current.map((item, itemIndex) => (itemIndex === index ? value : item))
    );
    setOutputs((current) => {
      const next = { ...current };
      delete next[index];
      return next;
    });
  }
  function updateRole(value) {
    setRoles((current) =>
      current.map((item, itemIndex) => (itemIndex === index ? value : item))
    );
    setOutputs((current) => {
      const next = { ...current };
      delete next[index];
      return next;
    });
  }
  function restore() {
    updateDraft(step.sql);
    setRoles((current) =>
      current.map((item, itemIndex) => (itemIndex === index ? step.role : item))
    );
  }
  function go(nextIndex) {
    if (running) return;
    setIndex(nextIndex);
    requestAnimationFrame(() =>
      document
        .getElementById(`acme-step-${chapter}`)
        ?.scrollIntoView({ behavior: "smooth", block: "start" })
    );
  }

  return (
    <div className="not-prose my-6 overflow-hidden rounded-[2rem] border border-stone-300/90 bg-white shadow-[0_30px_80px_-52px_rgba(28,25,23,0.5)] dark:border-stone-700 dark:bg-stone-900 dark:shadow-none sm:my-10">
      <header className="hidden border-b border-stone-300/80 bg-[linear-gradient(135deg,rgba(254,243,199,0.75),rgba(240,253,250,0.8))] px-5 py-5 dark:border-stone-700 dark:bg-[linear-gradient(135deg,rgba(120,53,15,0.2),rgba(19,78,74,0.2))] sm:block sm:px-7 sm:py-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="m-0 text-[10px] font-semibold uppercase tracking-[0.2em] text-amber-800 dark:text-amber-300">
            {lesson.eyebrow}
          </p>
          <a
            href="https://pglite.dev/"
            className="rounded-full border border-stone-300 bg-white/75 px-3 py-1 font-mono text-[9px] font-semibold text-stone-700 no-underline dark:border-stone-700 dark:bg-stone-900/70 dark:text-stone-300"
          >
            PostgreSQL 18.3 · PGlite ↗
          </a>
        </div>
        <h2 className="mb-0 mt-3 font-display text-2xl tracking-[-0.02em] text-stone-950 dark:text-white">
          {lesson.title}
        </h2>
        <p className="mb-0 mt-2 max-w-3xl text-sm leading-6 text-stone-700 dark:text-stone-300">
          {lesson.description}
        </p>
      </header>
      <div className="flex items-center justify-between gap-3 border-b border-stone-300/80 bg-[linear-gradient(135deg,rgba(254,243,199,0.75),rgba(240,253,250,0.8))] px-5 py-4 dark:border-stone-700 dark:bg-[linear-gradient(135deg,rgba(120,53,15,0.2),rgba(19,78,74,0.2))] sm:hidden">
        <p className="m-0 text-[9px] font-semibold uppercase tracking-[0.16em] text-amber-800 dark:text-amber-300">
          {lesson.eyebrow}
        </p>
        <span className="shrink-0 rounded-full border border-stone-300 bg-white/75 px-2.5 py-1 font-mono text-[9px] font-semibold text-stone-700 dark:border-stone-700 dark:bg-stone-900/70 dark:text-stone-300">
          PG 18.3
        </span>
      </div>
      <div className="border-b border-stone-200 px-5 py-4 dark:border-stone-800 sm:px-7">
        <div className="flex items-center justify-between gap-4">
          <p className="m-0 text-sm text-stone-600 dark:text-stone-300">
            Step {index + 1} of {lesson.steps.length}
          </p>
          <span className="hidden font-mono text-[10px] text-stone-500 sm:inline">
            Every step seeds its own database — jump anywhere
          </span>
        </div>
        <ol className="mt-3 flex gap-1.5" aria-label="Lesson progress">
          {lesson.steps.map((item, itemIndex) => (
            <li className="flex-1" key={item.title}>
              <button
                type="button"
                onClick={() => go(itemIndex)}
                disabled={running}
                className={`block h-2 w-full rounded-full ${
                  completed[itemIndex]
                    ? "bg-emerald-500"
                    : itemIndex === index
                    ? "bg-amber-400"
                    : "bg-stone-200 dark:bg-stone-700"
                } disabled:cursor-not-allowed`}
              >
                <span className="sr-only">{item.title}</span>
              </button>
            </li>
          ))}
        </ol>
      </div>
      <section
        id={`acme-step-${chapter}`}
        className="grid scroll-mt-24 gap-5 p-5 sm:p-7"
        aria-labelledby={`acme-step-title-${chapter}`}
      >
        <div>
          <p className="m-0 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-stone-500">
            Step {index + 1}
          </p>
          <h3
            id={`acme-step-title-${chapter}`}
            className="mb-0 mt-2 font-display text-2xl text-stone-950 dark:text-white"
          >
            {step.title}
          </h3>
          <p className="mb-0 mt-3 max-w-3xl text-base leading-7 text-stone-700 dark:text-stone-300">
            {step.why}
          </p>
          <p className="mb-0 mt-3 border-l-2 border-amber-400 pl-4 text-sm font-semibold leading-6 text-stone-900 dark:text-white">
            {step.prompt}
          </p>
        </div>
        {step.challenges && (
          <div className="flex flex-wrap gap-2" aria-label="Challenge queries">
            {step.challenges.map(([label, sql, challengeRole]) => (
              <button
                key={label}
                type="button"
                onClick={() => {
                  updateDraft(sql);
                  updateRole(challengeRole);
                }}
                className="rounded-full border border-stone-300 px-3 py-1.5 text-xs font-semibold text-stone-700 hover:border-amber-400 dark:border-stone-700 dark:text-stone-200"
              >
                {label}
              </button>
            ))}
          </div>
        )}
        <div className="overflow-hidden rounded-2xl border border-stone-700 bg-[#0c0e12]">
          <div className="flex flex-col gap-3 border-b border-stone-700 bg-stone-900 px-4 py-3 sm:flex-row sm:items-end sm:justify-between">
            <label className="grid gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-stone-400">
              Run as
              <select
                value={role}
                onChange={(event) => updateRole(event.target.value)}
                disabled={running}
                className="min-w-44 rounded-lg border border-stone-600 bg-stone-950 px-3 py-2 font-mono text-sm normal-case tracking-normal text-white"
              >
                {lesson.actors.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex gap-2">
              {!canonical && (
                <button
                  type="button"
                  onClick={restore}
                  disabled={running}
                  className="rounded-lg border border-stone-600 px-3 py-2 text-xs font-semibold text-stone-300 hover:border-amber-400"
                >
                  Restore example
                </button>
              )}
              <button
                type="button"
                onClick={run}
                disabled={running || !draft.trim()}
                className="rounded-xl border border-amber-300 bg-amber-300 px-5 py-2.5 font-mono text-xs font-bold text-stone-950 hover:bg-amber-200 disabled:cursor-wait disabled:border-stone-600 disabled:bg-stone-700 disabled:text-stone-400"
              >
                {running ? "Running SQL…" : "Run SQL"}
              </button>
            </div>
          </div>
          <div className="p-3 sm:p-4">
            <SqlEditor
              value={draft}
              onChange={updateDraft}
              disabled={running}
            />
          </div>
          <p className="m-0 border-t border-stone-800 bg-stone-950 px-4 py-3 text-xs leading-5 text-stone-400">
            Editable SQL · disposable browser database · changes are discarded
            after the run
          </p>
          <div
            className="border-t border-stone-800 bg-stone-950 px-4 py-5 text-stone-200"
            aria-live="polite"
            aria-busy={running}
          >
            <p className="mb-4 mt-0 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-stone-500">
              PostgreSQL output
            </p>
            <Output
              output={output}
              running={running}
              expectedError={output?.passed && Boolean(output?.error)}
            />
          </div>
        </div>
        {output?.inspection && (
          <AccessPath cards={step.cards(output.inspection, output)} />
        )}
        <ExecutionContext output={output} />
        {output?.passed && (
          <div className="rounded-2xl border border-emerald-200 bg-emerald-50/70 p-5 text-sm leading-6 text-stone-800 dark:border-emerald-900 dark:bg-emerald-950/25 dark:text-stone-200">
            <strong className="block font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-700 dark:text-emerald-300">
              What changed
            </strong>
            <span className="mt-2 block">{step.observation}</span>
          </div>
        )}
        {output && !output.passed && canonical && (
          <p className="m-0 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-200">
            This result did not match the step’s canonical PostgreSQL outcome.
            Restore the example to compare — or continue on; every step seeds
            its own database.
          </p>
        )}
        {output && !canonical && (
          <p className="m-0 rounded-xl border border-stone-200 bg-stone-50 p-4 text-sm text-stone-600 dark:border-stone-700 dark:bg-stone-950/30 dark:text-stone-300">
            That is PostgreSQL’s real response to your SQL. Restore the example
            when you want to see the guided story’s outcome.
          </p>
        )}
        <div className="flex flex-col-reverse gap-3 border-t border-stone-200 pt-5 dark:border-stone-800 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            onClick={() => go(index - 1)}
            disabled={running || index === 0}
            className="rounded-lg border border-stone-300 px-4 py-2 text-sm font-semibold text-stone-600 disabled:opacity-40 dark:border-stone-700 dark:text-stone-300"
          >
            ← Back
          </button>
          {index < lesson.steps.length - 1 ? (
            <button
              type="button"
              onClick={() => go(index + 1)}
              disabled={running}
              className="rounded-lg border border-stone-900 bg-stone-900 px-4 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:border-stone-200 disabled:bg-stone-100 disabled:text-stone-400 dark:border-white dark:bg-white dark:text-stone-900 dark:disabled:border-stone-700 dark:disabled:bg-stone-800 dark:disabled:text-stone-500"
            >
              Continue: {lesson.steps[index + 1].title} →
            </button>
          ) : lesson.debrief ? (
            <a
              href={lesson.debrief.href}
              className="rounded-lg border border-stone-900 bg-stone-900 px-4 py-2 text-sm font-semibold text-white no-underline dark:border-white dark:bg-white dark:text-stone-900"
            >
              {lesson.debrief.title} ↓
            </a>
          ) : lesson.next ? (
            <Link
              href={lesson.next.href}
              className="rounded-lg border border-stone-900 bg-stone-900 px-4 py-2 text-sm font-semibold text-white no-underline dark:border-white dark:bg-white dark:text-stone-900"
            >
              Next chapter: {lesson.next.title} →
            </Link>
          ) : (
            <span className="text-sm text-stone-500">Keep investigating.</span>
          )}
        </div>
      </section>
      <details className="border-t border-stone-200 px-5 py-4 dark:border-stone-800 sm:px-7">
        <summary className="cursor-pointer text-sm font-semibold text-stone-600 dark:text-stone-300">
          How the browser lab models roles
        </summary>
        <p className="mb-0 mt-3 text-sm leading-6 text-stone-500 dark:text-stone-400">
          The selector sets session authorization inside an isolated PGlite
          database. Statements run one at a time and autocommit, like psql:
          execution stops at the first error, and earlier statements keep their
          effect. PostgreSQL performs ordinary role, ownership, schema, and
          object checks; the diagram comes from catalog privilege queries after
          your SQL. This is not a password, CONNECT, pg_hba.conf, or
          concurrent-session test.
        </p>
      </details>
    </div>
  );
}

export function PostgresGatesLab() {
  return <AcmeStoryLab chapter="gates" />;
}
export function PostgresCapabilityRolesLab() {
  return <AcmeStoryLab chapter="capabilities" />;
}
export function PostgresAccessDriftLab() {
  return <AcmeStoryLab chapter="drift" />;
}
export function PostgresOwnershipLab() {
  return <AcmeStoryLab chapter="ownership" />;
}
export function PostgresDefaultPrivilegesLab() {
  return <AcmeStoryLab chapter="defaults" />;
}
export function PostgresOffboardingLab() {
  return <AcmeStoryLab chapter="offboarding" />;
}
export function PostgresMembershipMechanicsLab() {
  return <AcmeStoryLab chapter="mechanics" />;
}
export function PostgresSecurityReviewLab() {
  return <AcmeStoryLab chapter="security" />;
}
export function PostgresAcmePlayground() {
  return <AcmeStoryLab chapter="playground" />;
}
export function PostgresRowSecurityLab() {
  return <AcmeStoryLab chapter="rls" />;
}
