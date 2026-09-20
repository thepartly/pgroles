import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { IconBrandGithub } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'
import { linkStyles } from '@partly/pitstop/link'
import clsx from 'clsx'

import { Hero } from '@/components/Hero'
import { Logo, Logomark } from '@/components/Logo'
import { MobileNavigation } from '@/components/MobileNavigation'
import { Navigation } from '@/components/Navigation'
import { Prose } from '@/components/Prose'
import { ThemeSelector } from '@/components/ThemeSelector'
import {
  DESTINATIONS,
  getNavigation,
  getReadingLinks,
  resolvePage,
} from '@/lib/navigation.mjs'

function Header({
  navigation,
  destination,
  pathname,
  readerChoices,
  restoredNavigation,
  onExpandedChange,
}) {
  const [isScrolled, setIsScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setIsScrolled(window.scrollY > 0)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <header
      className={clsx(
        'sticky top-0 z-50 flex min-h-[4.5rem] items-center border-b px-4 py-3 transition duration-300 sm:px-6 lg:px-8',
        isScrolled
          ? 'bg-stone-50/92 dark:bg-stone-950/88 border-stone-300 shadow-[0_10px_30px_-24px_rgba(28,25,23,0.55)] backdrop-blur dark:border-stone-800 dark:shadow-none'
          : 'dark:bg-stone-950 border-transparent bg-stone-100/90'
      )}
    >
      <div className="bg-[linear-gradient(90deg,transparent,rgba(245,158,11,0.6),rgba(20,184,166,0.45),transparent)] pointer-events-none absolute inset-x-0 top-0 h-px" />
      <div className="mr-3 flex lg:hidden">
        <MobileNavigation
          navigation={navigation}
          destination={destination}
          pathname={pathname}
          readerChoices={readerChoices}
          restoredNavigation={restoredNavigation}
          onExpandedChange={onExpandedChange}
        />
      </div>
      <Link href="/" aria-label="Home page" className="shrink-0">
        <Logomark className="h-8 w-8 lg:hidden" />
        <Logo className="hidden lg:flex" />
      </Link>
      <nav
        aria-label="Destinations"
        className="ml-4 flex min-w-0 items-center gap-3 text-sm font-medium sm:ml-7 sm:gap-5"
      >
        {DESTINATIONS.map((item) => (
          <Link
            key={item.id}
            href={item.href}
            aria-current={item.id === destination.id ? 'location' : undefined}
            className={clsx(
              'hover:text-foreground whitespace-nowrap',
              item.id === destination.id
                ? 'text-amber-800 dark:text-amber-300'
                : 'text-muted-foreground'
            )}
          >
            <span
              className={
                item.id === 'learn' ? 'min-[440px]:inline hidden' : undefined
              }
            >
              {item.label}
            </span>
            {item.id === 'learn' && (
              <span className="min-[440px]:hidden">Learn</span>
            )}
          </Link>
        ))}
      </nav>
      <div className="ml-auto flex items-center gap-3 sm:gap-5">
        <ThemeSelector className="relative z-10" />
        <Button
          href="https://github.com/thepartly/pgroles"
          target="_blank"
          rel="noreferrer"
          variant="ghost"
          size="icon"
          aria-label="GitHub"
          className="text-muted-foreground hover:text-amber-700 dark:hover:text-amber-300"
        >
          <IconBrandGithub className="size-5" />
        </Button>
      </div>
    </header>
  )
}

function useTableOfContents(tableOfContents) {
  const [currentSection, setCurrentSection] = useState(tableOfContents[0]?.id)
  const getHeadings = useCallback(
    (items) =>
      items
        .flatMap((node) => [node.id, ...node.children.map((child) => child.id)])
        .map((id) => {
          const element = document.getElementById(id)
          if (!element) return undefined
          const top =
            window.scrollY +
            element.getBoundingClientRect().top -
            parseFloat(window.getComputedStyle(element).scrollMarginTop)
          return { id, top }
        })
        .filter(Boolean),
    []
  )
  useEffect(() => {
    if (!tableOfContents.length) return
    const headings = getHeadings(tableOfContents)
    const onScroll = () => {
      let current = headings[0]?.id
      for (const heading of headings) {
        if (window.scrollY >= heading.top) current = heading.id
        else break
      }
      setCurrentSection(current)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener('scroll', onScroll)
  }, [getHeadings, tableOfContents])
  return currentSection
}

function navigationWithGeneratedPage(navigation, page) {
  if (!page?.navigationParent) return navigation
  return navigation.map((section) => ({
    ...section,
    links: section.links?.map((link) =>
      link.href === page.navigationParent
        ? {
            ...link,
            children: [{ title: page.navigationTitle, href: page.href }],
          }
        : link
    ),
  }))
}

export function Layout({ children, title, tableOfContents }) {
  const router = useRouter()
  const pathname = router.pathname
  const page = resolvePage(pathname)
  const destination = DESTINATIONS.find(
    (item) => item.id === (page?.destination ?? 'docs')
  )
  const navigation = useMemo(
    () => navigationWithGeneratedPage(getNavigation(pathname), page),
    [pathname, page]
  )
  const [readerChoices, setReaderChoices] = useState({})
  const [restoredNavigation, setRestoredNavigation] = useState(null)
  useEffect(() => {
    const choices = {}
    for (const section of navigation) {
      const key = `${destination.id}.${section.title}`
      try {
        const stored = window.sessionStorage.getItem(
          `pgroles.navigation.${key}`
        )
        if (stored !== null) choices[key] = stored === 'true'
      } catch {}
    }
    setReaderChoices(choices)
    setRestoredNavigation(navigation)
  }, [destination.id, navigation])
  function onExpandedChange(key, isExpanded) {
    setReaderChoices((current) => ({ ...current, [key]: isExpanded }))
    try {
      window.sessionStorage.setItem(
        `pgroles.navigation.${key}`,
        String(isExpanded)
      )
    } catch {}
  }
  const reading = getReadingLinks(pathname)
  const currentSection = useTableOfContents(tableOfContents)
  const isHomePage = pathname === '/'
  const breadcrumb = page?.section ?? destination.label

  function isActive(section) {
    return section.id === currentSection || section.children?.some(isActive)
  }

  return (
    <>
      <Header
        navigation={navigation}
        destination={destination}
        pathname={pathname}
        readerChoices={readerChoices}
        restoredNavigation={restoredNavigation}
        onExpandedChange={onExpandedChange}
      />
      {isHomePage && <Hero />}
      <div className="dark:bg-stone-950 relative bg-stone-100 text-stone-900 dark:text-stone-100">
        <div className="max-w-8xl relative mx-auto flex justify-center sm:px-2 lg:px-8 xl:px-12">
          <aside className="hidden lg:relative lg:block lg:flex-none">
            <div
              data-navigation-scroll
              className="sticky top-[4.5rem] -ml-0.5 h-[calc(100vh-4.5rem)] overflow-y-auto overflow-x-hidden py-10 pl-0.5"
            >
              <Navigation
                navigation={navigation}
                destination={destination}
                pathname={pathname}
                readerChoices={readerChoices}
                restoredNavigation={restoredNavigation}
                onExpandedChange={onExpandedChange}
                className="dark:bg-stone-950/40 w-64 rounded-r-[2rem] border-r border-stone-300/80 bg-stone-50/70 pr-8 shadow-[8px_0_24px_-24px_rgba(28,25,23,0.3)] dark:border-stone-800 dark:shadow-none xl:w-72 xl:pr-16"
              />
            </div>
          </aside>
          <main className="min-w-0 max-w-2xl flex-auto px-4 py-16 lg:max-w-none lg:pr-0 lg:pl-8 xl:px-16">
            <article>
              {(title || page) && (
                <header className="mb-8 space-y-2">
                  <nav
                    aria-label="Breadcrumb"
                    className="font-display text-[11px] font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-300"
                  >
                    <span>{destination.label}</span>
                    <span aria-hidden="true"> / </span>
                    <span>{breadcrumb}</span>
                    {page && (
                      <>
                        <span aria-hidden="true"> / </span>
                        <span aria-current="page">{page.navigationTitle}</span>
                      </>
                    )}
                  </nav>
                  {title && (
                    <h1 className="font-display text-stone-950 text-4xl tracking-[-0.03em] dark:text-stone-100">
                      {title}
                    </h1>
                  )}
                </header>
              )}
              <Prose
                className={
                  pathname.startsWith('/docs/reference/')
                    ? 'crd-reference'
                    : undefined
                }
              >
                {children}
              </Prose>
            </article>
            {(reading.previous || reading.next) && (
              <dl className="mt-12 flex border-t border-stone-300 pt-6 dark:border-stone-800">
                {reading.previous && (
                  <div>
                    <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.14em] text-stone-500 dark:text-stone-400">
                      Previous
                    </dt>
                    <dd className="mt-1">
                      <Link
                        href={reading.previous.href}
                        className={clsx(
                          linkStyles({ variant: 'muted' }),
                          'text-base font-semibold hover:text-amber-700 dark:hover:text-amber-300'
                        )}
                      >
                        <span aria-hidden="true">&larr;</span>{' '}
                        {reading.previous.navigationTitle}
                      </Link>
                    </dd>
                  </div>
                )}
                {reading.next && (
                  <div className="ml-auto text-right">
                    <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.14em] text-stone-500 dark:text-stone-400">
                      Next
                    </dt>
                    <dd className="mt-1">
                      <Link
                        href={reading.next.href}
                        className={clsx(
                          linkStyles({ variant: 'muted' }),
                          'text-base font-semibold hover:text-amber-700 dark:hover:text-amber-300'
                        )}
                      >
                        {reading.next.navigationTitle}{' '}
                        <span aria-hidden="true">&rarr;</span>
                      </Link>
                    </dd>
                  </div>
                )}
              </dl>
            )}
          </main>
          {tableOfContents.length > 0 && (
            <aside className="hidden xl:sticky xl:top-[4.5rem] xl:-mr-6 xl:block xl:h-[calc(100vh-4.5rem)] xl:flex-none xl:overflow-y-auto xl:py-12 xl:pr-6">
              <nav
                aria-labelledby="on-this-page-title"
                className="w-56 rounded-[1.75rem] border border-stone-300/80 bg-white/80 p-5 shadow-[0_18px_40px_-34px_rgba(28,25,23,0.45)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none"
              >
                <>
                  <h2
                    id="on-this-page-title"
                    className="font-display text-[11px] font-semibold uppercase tracking-[0.14em] text-stone-500 dark:text-stone-400"
                  >
                    On this page
                  </h2>
                  <ol role="list" className="mt-4 space-y-3 text-sm">
                    {tableOfContents.map((section) => (
                      <li key={section.id}>
                        <h3>
                          <Link
                            href={`#${section.id}`}
                            className={
                              isActive(section)
                                ? 'text-amber-700 dark:text-amber-300'
                                : 'font-normal text-stone-600 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-200'
                            }
                          >
                            {section.title}
                          </Link>
                        </h3>
                        {section.children.length > 0 && (
                          <ol
                            role="list"
                            className="mt-2 space-y-3 pl-5 text-stone-500 dark:text-stone-500"
                          >
                            {section.children.map((subSection) => (
                              <li key={subSection.id}>
                                <Link
                                  href={`#${subSection.id}`}
                                  className={
                                    isActive(subSection)
                                      ? 'text-amber-700 dark:text-amber-300'
                                      : 'hover:text-stone-900 dark:hover:text-stone-200'
                                  }
                                >
                                  {subSection.title}
                                </Link>
                              </li>
                            ))}
                          </ol>
                        )}
                      </li>
                    ))}
                  </ol>
                </>
              </nav>
            </aside>
          )}
        </div>
      </div>
    </>
  )
}
