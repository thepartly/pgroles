import { Fence } from '@/components/Fence'
import { nodes as defaultNodes } from '@markdoc/markdoc'
import Link from 'next/link'

function MarkdocLink({ href, children, ...props }) {
  if (href?.startsWith('/')) {
    return (
      <Link href={href} {...props}>
        {children}
      </Link>
    )
  }

  return (
    <a href={href} {...props}>
      {children}
    </a>
  )
}

function MarkdocTable({ children }) {
  return (
    <div
      role="region"
      aria-label="Table"
      tabIndex={0}
      className="my-6 max-w-full overflow-x-auto rounded-sm focus-visible:outline-2 focus-visible:outline-amber-600"
    >
      <table>{children}</table>
    </div>
  )
}

const nodes = {
  table: {
    ...defaultNodes.table,
    render: MarkdocTable,
  },
  document: {
    render: undefined,
  },
  th: {
    ...defaultNodes.th,
    attributes: {
      ...defaultNodes.th.attributes,
      scope: {
        type: String,
        default: 'col',
      },
    },
  },
  fence: {
    render: Fence,
    attributes: {
      language: {
        type: String,
      },
      schema: {
        type: String,
        matches: ['pgroles-manifest'],
      },
      policy: {
        type: String,
        matches: ['complete', 'fragment'],
      },
    },
  },
  link: {
    ...defaultNodes.link,
    render: MarkdocLink,
  },
}

export default nodes
