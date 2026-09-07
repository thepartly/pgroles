import {useCallback, useEffect, useState} from 'react'
import Link from 'next/link'
import {useRouter} from 'next/router'
import {IconBrandGithub} from '@tabler/icons-react'
import {Button} from '@partly/pitstop/button'
import {linkStyles} from '@partly/pitstop/link'
import clsx from 'clsx'

import {Hero} from '@/components/Hero'
import {Logo, Logomark} from '@/components/Logo'
import {MobileNavigation} from '@/components/MobileNavigation'
import {Navigation} from '@/components/Navigation'
import {Prose} from '@/components/Prose'
import {Search} from '@/components/Search'
import {ThemeSelector} from '@/components/ThemeSelector'

const navigation = [
    {
        title: 'Introduction',
        links: [
            {title: 'Getting started', href: '/'},
            {title: 'CLI quick start', href: '/docs/quick-start'},
            {title: 'Operator quick start', href: '/docs/operator-quick-start'},
        ],
    },
    {
        title: 'Learn PostgreSQL Roles',
        collapsible: true,
        links: [
            {title: '1. The permission chain', href: '/docs/postgresql-access-model'},
            {title: '2. Capability roles', href: '/docs/postgresql-capability-roles'},
            {title: '3. Access drift', href: '/docs/postgresql-access-drift'},
            {title: '4. Ownership', href: '/docs/postgresql-ownership'},
            {title: '5. Future objects', href: '/docs/postgresql-default-privileges'},
            {title: '6. Offboarding an owner', href: '/docs/postgresql-offboarding'},
            {title: '7. Membership mechanics', href: '/docs/postgresql-role-hierarchy'},
            {title: '8. The security review', href: '/docs/postgresql-security-review'},
            {title: 'The Acme playground', href: '/docs/postgresql-playground'},
        ],
    },
    {
        title: 'Kubernetes operator',
        links: [
            {title: 'Kubernetes operator', href: '/docs/operator'},
            {title: 'Operator quick start', href: '/docs/operator-quick-start'},
            {title: 'Install the operator', href: '/docs/operator-install'},
            {title: 'The PostgresPolicy resource', href: '/docs/operator-postgrespolicy'},
            {title: 'Database connections', href: '/docs/operator-connections'},
            {title: 'Plan and approval', href: '/docs/operator-plan-approval'},
            {title: 'Candidates and promotion', href: '/docs/operator-candidates'},
            {title: 'Running the operator', href: '/docs/operator-operations'},
            {title: 'CRD API reference', href: '/docs/operator-api-reference'},
            {title: 'Upgrading', href: '/docs/operator-upgrades'},
            {title: 'Status and telemetry', href: '/docs/operator-status'},
            {title: 'Monitoring', href: '/docs/operator-monitoring'},
            {title: 'Troubleshooting index', href: '/docs/operator-troubleshooting'},
            {title: 'RBAC and security', href: '/docs/operator-security'},
            {title: 'Production status', href: '/docs/operator-production-status'},
            {title: 'Ephemeral access', href: '/docs/ephemeral-access'},
            {title: 'Securing ephemeral access', href: '/docs/ephemeral-access-security'},
            {title: 'Operator architecture', href: '/docs/operator-architecture'},
        ],
    },
    {
        title: 'Writing policy',
        links: [
            {title: 'Manifest guide', href: '/docs/manifest-format'},
            {title: 'Profiles & schemas', href: '/docs/profiles'},
            {title: 'Grants & privileges', href: '/docs/grants'},
            {title: 'Default privileges', href: '/docs/default-privileges'},
            {title: 'Memberships', href: '/docs/memberships'},
            {title: 'Bundle composition', href: '/docs/bundle-composition'},
            {title: 'Application access patterns', href: '/docs/tooling'},
            {title: 'Manifest reference', href: '/docs/manifest-reference'},
        ],
    },
    {
        title: 'Connecting to PostgreSQL',
        links: [
            {title: 'Executor privileges', href: '/docs/executor-privileges'},
            {title: 'Staged adoption', href: '/docs/adoption'},
            {title: 'Google Cloud SQL', href: '/docs/google-cloud-sql'},
            {title: 'AWS RDS & Aurora', href: '/docs/aws-rds'},
        ],
    },
    {
        title: 'CLI',
        links: [
            {title: 'Install the CLI', href: '/docs/installation'},
            {title: 'CLI commands', href: '/docs/cli'},
            {title: 'CI/CD integration', href: '/docs/ci-cd'},
        ],
    },
    {
        title: 'Reference',
        links: [
            {title: 'Architecture', href: '/docs/architecture'},
            {title: 'Limitations', href: '/docs/limitations'},
            {title: 'Related tools', href: '/docs/alternatives'},
        ],
    },
]


function Header({navigation}) {
    let [isScrolled, setIsScrolled] = useState(false)

    useEffect(() => {
        function onScroll() {
            setIsScrolled(window.scrollY > 0)
        }

        onScroll()
        window.addEventListener('scroll', onScroll, {passive: true})
        return () => {
            window.removeEventListener('scroll', onScroll, {passive: true})
        }
    }, [])

    return (
        <header
            className={clsx(
                'sticky top-0 z-50 flex flex-wrap items-center justify-between border-b px-4 py-4 transition duration-300 sm:px-6 lg:px-8',
                isScrolled
                    ? 'border-stone-300 bg-stone-50/92 shadow-[0_10px_30px_-24px_rgba(28,25,23,0.55)] backdrop-blur dark:border-stone-800 dark:bg-stone-950/88 dark:shadow-none'
                    : 'border-transparent bg-stone-100/90 dark:bg-stone-950'
            )}
        >
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(245,158,11,0.6),rgba(20,184,166,0.45),transparent)]" />
            <div className="mr-6 flex lg:hidden">
                <MobileNavigation navigation={navigation}/>
            </div>
            <div className="relative flex flex-grow basis-0 items-center">
                <Link href="/" aria-label="Home page">
                    <Logomark className="h-9 w-9 lg:hidden"/>
                    <Logo className="hidden lg:flex"/>
                </Link>
            </div>
            <div className="-my-5 mr-6 sm:mr-8 md:mr-0">
                <Search/>
            </div>
            <div className="relative flex basis-0 justify-end gap-6 sm:gap-8 md:flex-grow">
                <ThemeSelector className="relative z-10"/>
                <Button
                    href="https://github.com/thepartly/pgroles"
                    target="_blank"
                    rel="noreferrer"
                    variant="ghost"
                    size="icon"
                    aria-label="GitHub"
                    className="text-muted-foreground hover:text-amber-700 dark:hover:text-amber-300"
                >
                    <IconBrandGithub className="size-6"/>
                </Button>
            </div>
        </header>
    )
}

function useTableOfContents(tableOfContents) {
    let [currentSection, setCurrentSection] = useState(tableOfContents[0]?.id)

    let getHeadings = useCallback((tableOfContents) => {
        return tableOfContents
            .flatMap((node) => [node.id, ...node.children.map((child) => child.id)])
            .map((id) => {
                let el = document.getElementById(id)
                if (!el) return

                let style = window.getComputedStyle(el)
                let scrollMt = parseFloat(style.scrollMarginTop)

                let top = window.scrollY + el.getBoundingClientRect().top - scrollMt
                return {id, top}
            })
    }, [])

    useEffect(() => {
        if (tableOfContents.length === 0) return
        let headings = getHeadings(tableOfContents)

        function onScroll() {
            let top = window.scrollY
            let current = headings[0].id
            for (let heading of headings) {
                if (top >= heading.top) {
                    current = heading.id
                } else {
                    break
                }
            }
            setCurrentSection(current)
        }

        window.addEventListener('scroll', onScroll, {passive: true})
        onScroll()
        return () => {
            window.removeEventListener('scroll', onScroll, {passive: true})
        }
    }, [getHeadings, tableOfContents])

    return currentSection
}

export function Layout({children, title, tableOfContents}) {
    let router = useRouter()
    let isHomePage = router.pathname === '/'
    let allLinks = navigation.flatMap((section) => section.links)
    let linkIndex = allLinks.findIndex((link) => link.href === router.pathname)
    let previousPage = allLinks[linkIndex - 1]
    let nextPage = allLinks[linkIndex + 1]
    let section = navigation.find((section) =>
        section.links.find((link) => link.href === router.pathname)
    )
    let currentSection = useTableOfContents(tableOfContents)

    function isActive(section) {
        if (section.id === currentSection) {
            return true
        }
        if (!section.children) {
            return false
        }
        return section.children.findIndex(isActive) > -1
    }

    return (
        <>
            <Header navigation={navigation}/>

            {isHomePage && <Hero/>}

            <div className="relative bg-stone-100 text-stone-900 dark:bg-stone-950 dark:text-stone-100">
            <div className="relative mx-auto flex max-w-8xl justify-center sm:px-2 lg:px-8 xl:px-12">
                <div className="hidden lg:relative lg:block lg:flex-none">
                    <div
                        className="sticky top-[4.5rem] -ml-0.5 h-[calc(100vh-4.5rem)] overflow-y-auto overflow-x-hidden py-16 pl-0.5">
                        <Navigation
                            navigation={navigation}
                            className="w-64 rounded-r-[2rem] border-r border-stone-300/80 bg-stone-50/70 pr-8 shadow-[8px_0_24px_-24px_rgba(28,25,23,0.3)] xl:w-72 xl:pr-16 dark:border-stone-800 dark:bg-stone-950/40 dark:shadow-none"
                        />
                    </div>
                </div>
                <div className="min-w-0 max-w-2xl flex-auto px-4 py-16 lg:max-w-none lg:pr-0 lg:pl-8 xl:px-16">
                    <article>
                        {(title || section) && (
                            <header className="mb-10 space-y-2">
                                {section && (
                                    <p className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-amber-700 dark:text-amber-300">
                                        {section.title}
                                    </p>
                                )}
                                {title && (
                                    <h1 className="font-display text-4xl tracking-[-0.03em] text-stone-950 dark:text-stone-100">
                                        {title}
                                    </h1>
                                )}
                            </header>
                        )}
                        <Prose className={router.pathname.startsWith('/docs/reference/') ? 'crd-reference' : undefined}>{children}</Prose>
                    </article>
                    <dl className="mt-12 flex border-t border-stone-300 pt-6 dark:border-stone-800">
                        {previousPage && (
                            <div>
                                <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
                                    Previous
                                </dt>
                                <dd className="mt-1">
                                    <Link
                                        href={previousPage.href}
                                        className={clsx(
                                            linkStyles({variant: 'muted'}),
                                            'text-base font-semibold hover:text-amber-700 dark:hover:text-amber-300'
                                        )}
                                    >
                                        <span aria-hidden="true">&larr;</span> {previousPage.title}
                                    </Link>
                                </dd>
                            </div>
                        )}
                        {nextPage && (
                            <div className="ml-auto text-right">
                                <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
                                    Next
                                </dt>
                                <dd className="mt-1">
                                    <Link
                                        href={nextPage.href}
                                        className={clsx(
                                            linkStyles({variant: 'muted'}),
                                            'text-base font-semibold hover:text-amber-700 dark:hover:text-amber-300'
                                        )}
                                    >
                                        {nextPage.title} <span aria-hidden="true">&rarr;</span>
                                    </Link>
                                </dd>
                            </div>
                        )}
                    </dl>
                </div>
                <div
                    className="hidden xl:sticky xl:top-[4.5rem] xl:-mr-6 xl:block xl:h-[calc(100vh-4.5rem)] xl:flex-none xl:overflow-y-auto xl:py-16 xl:pr-6">
                    <nav aria-labelledby="on-this-page-title" className="w-56 rounded-[1.75rem] border border-stone-300/80 bg-white/80 p-5 shadow-[0_18px_40px_-34px_rgba(28,25,23,0.45)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none">
                        {tableOfContents.length > 0 && (
                            <>
                                <h2
                                    id="on-this-page-title"
                                    className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-stone-500 dark:text-stone-400"
                                >
                                    On this page
                                </h2>
                                <ol role="list" className="mt-4 space-y-3 text-sm">
                                    {tableOfContents.map((section) => (
                                        <li key={section.id}>
                                            <h3>
                                                <Link
                                                    href={`#${section.id}`}
                                                    className={clsx(
                                                        isActive(section)
                                                            ? 'text-amber-700 dark:text-amber-300'
                                                            : 'font-normal text-stone-600 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-200'
                                                    )}
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
                        )}
                    </nav>
                </div>
            </div>
            </div>
        </>
    )
}
