import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/router'
import {
  Dialog,
  DialogTrigger,
  Modal,
  ModalOverlay,
} from 'react-aria-components'
import { IconSearch, IconX } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'

import {
  bestSection,
  excerptText,
  loadSearch,
  resetSearch,
} from '@/lib/search.mjs'

function SearchContents({ basePath, onClose }) {
  const [query, setQuery] = useState('')
  const [contentType, setContentType] = useState('')
  const [destination, setDestination] = useState('')
  const [retry, setRetry] = useState(0)
  const [state, setState] = useState({ status: 'idle', results: [], total: 0 })
  const resultsRef = useRef(null)
  const moreButtonRef = useRef(null)
  const generation = useRef(0)
  const focusResult = useRef(null)

  useEffect(() => {
    const currentGeneration = ++generation.current
    const timer = window.setTimeout(async () => {
      if (!query.trim()) {
        setState({ status: 'idle', results: [], total: 0 })
        return
      }
      setState({ status: 'loading', results: [], total: 0 })
      try {
        const pagefind = await loadSearch(basePath)
        const filters = {}
        if (contentType) filters.content_type = contentType
        if (destination) filters.destination = destination
        const response = await pagefind.search(query, { filters })
        const results = await Promise.all(
          response.results.slice(0, 10).map((result) => result.data())
        )
        if (generation.current === currentGeneration)
          setState({
            status: 'ready',
            results,
            total: response.results.length,
          })
      } catch {
        if (generation.current === currentGeneration)
          setState({ status: 'error', results: [], total: 0 })
      }
    }, 150)
    return () => {
      generation.current += 1
      window.clearTimeout(timer)
    }
  }, [basePath, query, contentType, destination, retry])

  useEffect(() => {
    if (focusResult.current === null) return
    resultsRef.current
      ?.querySelectorAll('a')
      [focusResult.current]?.focus({ preventScroll: true })
    focusResult.current = null
  }, [state.results])

  async function loadMore() {
    if (state.status === 'loading-more') return
    const currentGeneration = generation.current
    const loadedCount = state.results.length
    if (state.status === 'more-error') resetSearch()
    setState((current) => ({ ...current, status: 'loading-more' }))
    try {
      const pagefind = await loadSearch(basePath)
      const filters = {}
      if (contentType) filters.content_type = contentType
      if (destination) filters.destination = destination
      const response = await pagefind.search(query, { filters })
      const additionalResults = await Promise.all(
        response.results
          .slice(loadedCount, loadedCount + 10)
          .map((result) => result.data())
      )
      if (generation.current !== currentGeneration) return
      if (
        document.activeElement === moreButtonRef.current &&
        additionalResults.length
      ) {
        focusResult.current = loadedCount
      }
      setState((current) => ({
        status: 'ready',
        results: [...current.results, ...additionalResults],
        total: response.results.length,
      }))
    } catch {
      if (generation.current === currentGeneration)
        setState((current) => ({ ...current, status: 'more-error' }))
    }
  }

  function updateQuery(value) {
    setQuery(value)
    setState({
      status: value.trim() ? 'loading' : 'idle',
      results: [],
      total: 0,
    })
  }

  function moveResultFocus(event) {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    const links = [...(resultsRef.current?.querySelectorAll('a') ?? [])]
    if (!links.length) return
    event.preventDefault()
    const current = links.indexOf(document.activeElement)
    const next =
      current < 0
        ? event.key === 'ArrowDown'
          ? 0
          : links.length - 1
        : (current + (event.key === 'ArrowDown' ? 1 : -1) + links.length) %
          links.length
    links[next].focus()
  }

  return (
    <Dialog
      aria-labelledby="documentation-search-title"
      className="flex max-h-[85dvh] flex-col outline-none"
    >
      <div className="border-b p-4 sm:p-6">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 id="documentation-search-title" className="font-display text-xl">
            Search documentation
          </h2>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Close search"
            onPress={onClose}
          >
            <IconX className="size-5" />
          </Button>
        </div>
        <label htmlFor="documentation-query" className="sr-only">
          Search docs and courses
        </label>
        <input
          id="documentation-query"
          type="search"
          autoFocus
          autoComplete="off"
          value={query}
          onChange={(event) => updateQuery(event.target.value)}
          onKeyDown={moveResultFocus}
          placeholder="Search docs and courses…"
          className="w-full rounded-lg border bg-transparent px-3 py-2 text-base outline-offset-2 focus-visible:outline-amber-600"
        />
        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
          <label className="min-w-0">
            Content type
            <select
              aria-label="Content type"
              value={contentType}
              onChange={(event) => {
                setContentType(event.target.value)
                setState({ status: 'loading', results: [], total: 0 })
              }}
              className="mt-1 w-full rounded-md border bg-white p-2 dark:bg-stone-900"
            >
              <option value="">All</option>
              {['Guide', 'Reference', 'Course'].map((type) => (
                <option key={type}>{type}</option>
              ))}
            </select>
          </label>
          <label className="min-w-0">
            Destination
            <select
              aria-label="Destination"
              value={destination}
              onChange={(event) => {
                setDestination(event.target.value)
                setState({ status: 'loading', results: [], total: 0 })
              }}
              className="mt-1 w-full rounded-md border bg-white p-2 dark:bg-stone-900"
            >
              <option value="">All</option>
              <option>Docs</option>
              <option>Learn PostgreSQL</option>
            </select>
          </label>
        </div>
      </div>
      <div className="min-h-0 overflow-y-auto p-4 sm:p-6">
        <p role="status" className="text-muted-foreground mb-3 text-sm">
          {state.status === 'idle' &&
            'Search across guides, references and PostgreSQL courses.'}
          {state.status === 'loading' && 'Searching…'}
          {['ready', 'loading-more', 'more-error'].includes(state.status) &&
            (state.total
              ? `${state.total} results`
              : 'No results. Try different words or clear the filters.')}
        </p>
        {state.status === 'error' && (
          <div role="alert" className="text-sm">
            <p>Search could not load. Check your connection and try again.</p>
            <Button
              variant="outline"
              onPress={() => {
                resetSearch()
                setRetry((current) => current + 1)
              }}
              className="mt-3"
            >
              Retry search
            </Button>
          </div>
        )}
        <ol
          ref={resultsRef}
          aria-label="Search results"
          className="space-y-3"
          onKeyDown={moveResultFocus}
        >
          {state.results.map((result) => {
            const section = bestSection(result)
            return (
              <li
                key={result.url}
                className="rounded-lg border p-3 [overflow-wrap:anywhere]"
              >
                <p className="text-muted-foreground mb-1 text-xs">
                  {result.meta.content_type} · {result.meta.destination}
                </p>
                <a
                  href={section?.url ?? result.url}
                  onClick={onClose}
                  className="font-semibold text-amber-800 underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-amber-600 dark:text-amber-300"
                >
                  {result.meta.title}
                  {section?.url.includes('#') && (
                    <span className="block text-sm font-normal">
                      {section.title}
                    </span>
                  )}
                </a>
                <p className="text-muted-foreground mt-1 text-sm">
                  {excerptText(
                    section?.plain_excerpt ?? result.plain_excerpt ?? ''
                  )}
                </p>
              </li>
            )
          })}
        </ol>
        {state.total > state.results.length && (
          <Button
            ref={moreButtonRef}
            variant="outline"
            className="mt-4"
            aria-disabled={state.status === 'loading-more'}
            onPress={loadMore}
          >
            {state.status === 'more-error'
              ? 'Retry more results'
              : 'Show more results'}
          </Button>
        )}
        {state.status === 'loading-more' && (
          <p role="status" className="mt-2 text-sm">
            Loading more results…
          </p>
        )}
        {state.status === 'more-error' && (
          <p role="alert" className="mt-2 text-sm">
            More results could not load. Your loaded results are still
            available.
          </p>
        )}
      </div>
    </Dialog>
  )
}

export function Search() {
  const { basePath, asPath } = useRouter()
  const [isOpen, setIsOpen] = useState(false)
  useEffect(() => setIsOpen(false), [asPath])
  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setIsOpen((current) => !current)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])
  return (
    <DialogTrigger isOpen={isOpen} onOpenChange={setIsOpen}>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Search documentation"
        aria-keyshortcuts="Control+k Meta+k"
      >
        <IconSearch className="size-5" />
      </Button>
      <ModalOverlay
        isDismissable
        className="bg-stone-950/40 fixed inset-0 z-[80] flex items-start justify-center px-2 pt-[5dvh] backdrop-blur-sm sm:px-6"
      >
        <Modal className="dark:bg-stone-950 w-full max-w-2xl rounded-xl border bg-white text-stone-900 shadow-2xl dark:text-stone-100">
          <SearchContents
            basePath={basePath}
            onClose={() => setIsOpen(false)}
          />
        </Modal>
      </ModalOverlay>
    </DialogTrigger>
  )
}
