import { useCallback, useEffect, useRef } from 'react'
import Link from 'next/link'
import { IconChevronRight } from '@tabler/icons-react'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@partly/pitstop/collapsible'

import { cn } from '@/lib/utils'

function SectionHeading({ children, className }) {
  return (
    <h2
      className={cn(
        'font-display text-muted-foreground text-[11px] font-semibold uppercase tracking-[0.14em]',
        className
      )}
    >
      {children}
    </h2>
  )
}

function SectionLinks({ links, pathname, activeLinkRef }) {
  return (
    <ul role="list" className="mt-2 space-y-1 border-l">
      {links.map((link) => {
        const isActive = link.href === pathname
        return (
          <li key={link.href} className="relative">
            <Link
              href={link.href}
              ref={isActive ? activeLinkRef : undefined}
              aria-current={isActive ? 'page' : undefined}
              className={cn(
                'block w-full rounded-r-lg py-1.5 pr-3 pl-4 leading-snug transition before:pointer-events-none before:absolute before:top-0 before:-left-px before:h-full before:w-px',
                isActive
                  ? 'dark:bg-card bg-amber-50/80 font-semibold text-amber-800 before:bg-amber-500 dark:text-amber-300 dark:before:bg-amber-400'
                  : 'text-muted-foreground before:bg-border hover:bg-muted hover:text-foreground before:hidden hover:before:block'
              )}
            >
              {link.title}
            </Link>
            {link.children && (
              <SectionLinks
                links={link.children}
                pathname={pathname}
                activeLinkRef={activeLinkRef}
              />
            )}
          </li>
        )
      })}
    </ul>
  )
}

function NavGroup({ group, pathname, activeLinkRef }) {
  return (
    <div className="pt-3 first:pt-0">
      <SectionHeading className="tracking-[0.12em]">
        {group.title}
      </SectionHeading>
      <SectionLinks
        links={group.links}
        pathname={pathname}
        activeLinkRef={activeLinkRef}
      />
    </div>
  )
}

function NavSection({
  section,
  pathname,
  destination,
  activeLinkRef,
  readerChoices,
  onExpandedChange,
}) {
  const links = [
    ...(section.links ?? []),
    ...(section.groups ?? []).flatMap((group) => group.links),
  ]
  const containsCurrent = links.some(
    (link) =>
      link.href === pathname ||
      link.children?.some((child) => child.href === pathname)
  )
  const storageKey = `${destination.id}.${section.title}`
  const readerChoice = readerChoices[storageKey]

  const isExpanded =
    readerChoice ?? (containsCurrent || destination.id === 'learn')
  function setExpanded(expanded) {
    onExpandedChange(storageKey, expanded)
  }

  const contents = (
    <>
      {section.links && (
        <SectionLinks
          links={section.links}
          pathname={pathname}
          activeLinkRef={activeLinkRef}
        />
      )}
      {section.groups && (
        <div className="mt-2">
          {section.groups.map((group) => (
            <NavGroup
              key={group.title}
              group={group}
              pathname={pathname}
              activeLinkRef={activeLinkRef}
            />
          ))}
        </div>
      )}
    </>
  )

  if (destination.id === 'learn' && !section.collapsible)
    return (
      <li>
        <SectionHeading>{section.title}</SectionHeading>
        {contents}
      </li>
    )
  return (
    <li>
      <Collapsible isExpanded={isExpanded} onExpandedChange={setExpanded}>
        <CollapsibleTrigger className="group flex w-full items-center justify-between gap-2 rounded-sm text-left">
          <SectionHeading>{section.title}</SectionHeading>
          <IconChevronRight className="size-3.5 text-muted-foreground group-expanded/collapsible:rotate-90 shrink-0 transition-transform" />
        </CollapsibleTrigger>
        <CollapsibleContent>{contents}</CollapsibleContent>
      </Collapsible>
    </li>
  )
}

export function Navigation({
  navigation,
  destination,
  pathname,
  readerChoices,
  onExpandedChange,
  restoredNavigation,
  className,
}) {
  const activeLinkRef = useRef(null)

  const scrollActiveLink = useCallback(() => {
    const activeLink = activeLinkRef.current
    const scroller = activeLink?.closest('[data-navigation-scroll]')
    if (!activeLink || !scroller) return
    const link = activeLink.getBoundingClientRect()
    const bounds = scroller.getBoundingClientRect()
    if (link.top < bounds.top || link.bottom > bounds.bottom)
      scroller.scrollTo({
        top:
          scroller.scrollTop +
          link.top -
          bounds.top -
          bounds.height / 2 +
          link.height / 2,
        behavior: 'instant',
      })
  }, [])

  useEffect(() => {
    const frame = window.requestAnimationFrame(scrollActiveLink)
    window.addEventListener('resize', scrollActiveLink)
    return () => {
      window.cancelAnimationFrame(frame)
      window.removeEventListener('resize', scrollActiveLink)
    }
  }, [pathname, navigation, restoredNavigation, scrollActiveLink])

  return (
    <nav
      aria-label={`${destination.label} navigation`}
      className={cn('text-base lg:text-sm', className)}
    >
      <ul role="list" className="space-y-6">
        {navigation.map((section) => (
          <NavSection
            key={section.title}
            section={section}
            pathname={pathname}
            destination={destination}
            activeLinkRef={activeLinkRef}
            readerChoices={readerChoices}
            onExpandedChange={onExpandedChange}
          />
        ))}
      </ul>
    </nav>
  )
}
