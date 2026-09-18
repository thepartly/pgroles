import Head from 'next/head'
import { useRouter } from 'next/router'
import { IBM_Plex_Mono, IBM_Plex_Sans, Space_Grotesk } from 'next/font/google'
import { slugifyWithCounter } from '@sindresorhus/slugify'
import { RouterProvider } from 'react-aria-components'

import { Layout } from '@/components/Layout'
import { withBasePath } from '@/lib/routing.mjs'

import '@/styles/tailwind.css'

const sans = IBM_Plex_Sans({
  subsets: ['latin'],
  variable: '--font-plex-sans',
})

const display = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-space-grotesk',
})

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-plex-mono',
})

function getNodeText(node) {
  let text = ''
  for (let child of node.children ?? []) {
    if (typeof child === 'string') {
      text += child
    }
    text += getNodeText(child)
  }
  return text
}

function collectHeadings(nodes, slugify = slugifyWithCounter()) {
  let sections = []

  for (let node of nodes) {
    if (node.name === 'h2' || node.name === 'h3') {
      let title = getNodeText(node)
      if (title) {
        let id = slugify(title)
        node.attributes.id = id
        if (node.name === 'h3') {
          if (!sections[sections.length - 1]) {
            throw new Error(
              'Cannot add `h3` to table of contents without a preceding `h2`'
            )
          }
          sections[sections.length - 1].children.push({
            ...node.attributes,
            title,
          })
        } else {
          sections.push({ ...node.attributes, title, children: [] })
        }
      }
    }

    sections.push(...collectHeadings(node.children ?? [], slugify))
  }

  return sections
}

export default function App({ Component, pageProps }) {
  let router = useRouter()
  let { basePath = '' } = router
  let title = pageProps.markdoc?.frontmatter.title

  let pageTitle =
    pageProps.markdoc?.frontmatter.pageTitle ||
    `${pageProps.markdoc?.frontmatter.title} - pgroles docs`

  let description = pageProps.markdoc?.frontmatter.description

  let tableOfContents = pageProps.markdoc?.content
    ? collectHeadings(pageProps.markdoc.content)
    : []

  return (
    // React Aria renders an href verbatim, so `useHref` adds the basePath the
    // static export is deployed under to root-relative links. External URLs,
    // protocol-relative URLs, and fragments must remain unchanged. Internal
    // navigation through next/link handles the basePath and trailing slash
    // itself; this covers any Pitstop component given an `href` directly.
    <RouterProvider
      navigate={(href) => router.push(href)}
      useHref={(href) => withBasePath(basePath, href)}
    >
      {/* `font-sans` is applied here, where the font variables are defined, so
          the whole tree inherits IBM Plex rather than the fallback stack that
          `html` resolves to. */}
      <div
        className={`${sans.variable} ${display.variable} ${mono.variable} font-sans`}
      >
        <Head>
          <title>{pageTitle}</title>
          <link rel="icon" href={`${basePath}/logo.svg`} type="image/svg+xml" />
          {description && <meta name="description" content={description} />}
        </Head>
        <Layout title={title} tableOfContents={tableOfContents}>
          <Component {...pageProps} />
        </Layout>
      </div>
    </RouterProvider>
  )
}
