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

const nodes = {
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
