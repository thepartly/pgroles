import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, relative } from 'node:path'

const root = resolve('out')
const basePath = process.env.DOCS_TEST_BASE_PATH ?? '/pgroles/pr-preview/pr-236'
const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
}

createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  if (!pathname.startsWith(`${basePath}/`) && pathname !== basePath) {
    response.writeHead(404).end()
    return
  }
  const suffix = pathname.slice(basePath.length).replace(/^\//, '')
  const candidate = resolve(root, suffix.endsWith('/') || !suffix ? `${suffix}index.html` : suffix)
  if (relative(root, candidate).startsWith('..')) {
    response.writeHead(404).end()
    return
  }
  try {
    const body = await readFile(candidate)
    const extension = candidate.slice(candidate.lastIndexOf('.'))
    response.writeHead(200, { 'content-type': contentTypes[extension] || 'application/octet-stream' }).end(body)
  } catch {
    response.writeHead(404).end()
  }
}).listen(3210, '127.0.0.1')
