import { Fragment, useEffect, useId, useMemo, useRef, useState } from 'react'
import Highlight, { defaultProps } from 'prism-react-renderer'
import { IconCheck, IconCopy } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'

import {
  getPgrolesSemanticRanges,
  splitSemanticToken,
} from '@/components/PgrolesPolicyHighlight'

// The code surface is dark in both themes, so the button opts out of the
// token colors and is styled against that surface directly.
function CopyButton({ copied, onClick }) {
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      onPress={onClick}
      aria-label={copied ? 'Copied' : 'Copy code'}
      className="text-stone-400 hover:bg-stone-800 hover:text-white"
    >
      {copied ? <IconCheck /> : <IconCopy />}
    </Button>
  )
}

function HighlightedCode({ code, language, schema }) {
  const isPgrolesManifest = schema === 'pgroles-manifest'
  const legendId = useId()
  const semantic = useMemo(
    () =>
      isPgrolesManifest
        ? getPgrolesSemanticRanges(code)
        : { ranges: [], errors: [] },
    [code, isPgrolesManifest]
  )
  const lineStarts = useMemo(() => {
    let offset = 0
    return code.split('\n').map((line) => {
      const start = offset
      offset += line.length + 1
      return start
    })
  }, [code])

  return (
    <>
      {isPgrolesManifest && (
        <div
          id={legendId}
          className="flex flex-wrap gap-x-4 gap-y-1 border-b border-stone-800 bg-[#0c0e12] px-4 py-2 font-mono text-[9px] uppercase tracking-[0.1em] text-stone-400"
        >
          <span>
            <span className="font-semibold text-amber-300">Section</span>
          </span>
          <span>
            <span className="text-sky-300">Field</span>
          </span>
          <span>
            <span className="text-teal-200">Role / profile / setting</span>
          </span>
          <span>
            <span className="text-cyan-200">Object</span>
          </span>
          <span>
            <span className="font-semibold text-pink-300">
              Privilege / type
            </span>
          </span>
          <span>
            <span className="text-rose-300 underline decoration-wavy">
              Unknown
            </span>
          </span>
        </div>
      )}
      <Highlight
        {...defaultProps}
        code={code}
        language={isPgrolesManifest ? 'yaml' : language}
        theme={undefined}
      >
        {({ className, style, tokens, getTokenProps }) => (
          <pre
            className={`${className} m-0 rounded-none px-4 py-5`}
            style={style}
            aria-describedby={isPgrolesManifest ? legendId : undefined}
          >
            <code>
              {tokens.map((line, lineIndex) => {
                let tokenStart = lineStarts[lineIndex] || 0

                return (
                  <Fragment key={lineIndex}>
                    {line
                      .filter((token) => !token.empty)
                      .flatMap((token) => {
                        const pieces = splitSemanticToken(
                          token,
                          tokenStart,
                          semantic.ranges
                        )
                        tokenStart += token.content.length
                        return pieces
                      })
                      .map(({ token, start }) => {
                        // getTokenProps returns its own `key`, which React 19
                        // rejects when spread into JSX.
                        const { key: _prismKey, ...props } = getTokenProps({
                          token,
                        })
                        return (
                          <span
                            key={`${start}-${token.content}`}
                            {...props}
                            className={`${props.className || ''} ${
                              token.semanticClassName || ''
                            }`.trim()}
                            title={token.semanticTitle}
                          />
                        )
                      })}
                    {'\n'}
                  </Fragment>
                )
              })}
            </code>
          </pre>
        )}
      </Highlight>
      {semantic.errors.length > 0 && (
        <p
          className="m-0 border-t border-rose-900/70 bg-rose-950/40 px-4 py-3 font-mono text-xs text-rose-200"
          role="status"
        >
          YAML syntax: {semantic.errors[0]}
        </p>
      )}
    </>
  )
}

export function Fence({ children, language, schema, policy }) {
  const [copied, setCopied] = useState(false)
  const resetCopy = useRef()
  const code = String(children).trimEnd()
  const isPgrolesPolicy = schema === 'pgroles-manifest'
  const policyLabel = policy === 'fragment' ? 'Policy fragment' : 'pgroles.yaml'

  function onCopyCode() {
    // Copy the rendered (trimmed) code, and tolerate non-secure contexts or a
    // denied clipboard permission instead of throwing in the handler.
    if (!navigator.clipboard?.writeText) return
    navigator.clipboard.writeText(code).then(
      () => setCopied(true),
      () => setCopied(false)
    )
  }

  useEffect(() => {
    if (copied) resetCopy.current = setTimeout(() => setCopied(false), 2500)
    return () => clearTimeout(resetCopy.current)
  }, [copied])

  if (isPgrolesPolicy) {
    return (
      <div className="not-prose my-6 overflow-hidden rounded-2xl border border-stone-700 bg-[#0c0e12] shadow-sm">
        <div className="flex items-center justify-between gap-3 border-b border-stone-700 bg-stone-900 px-4 py-2.5">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-mono text-xs font-semibold text-stone-200">
              {policyLabel}
            </span>
            <span
              title="Recognizes documented policy fields and YAML syntax; it does not fully validate a policy."
              className="rounded-full border border-teal-800 bg-teal-950/60 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-teal-300"
            >
              Policy field guide
            </span>
          </div>
          <CopyButton copied={copied} onClick={onCopyCode} />
        </div>
        <HighlightedCode code={code} language={language} schema={schema} />
      </div>
    )
  }

  return (
    <div className="relative">
      <span className="absolute right-3 top-3 z-10">
        <CopyButton copied={copied} onClick={onCopyCode} />
      </span>
      <HighlightedCode code={code} language={language} />
    </div>
  )
}
