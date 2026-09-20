import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import Markdoc from '@markdoc/markdoc'

import { getPgrolesSemanticRanges } from '../src/components/PgrolesPolicyHighlight.js'

const pagesDirectory = fileURLToPath(new URL('../src/pages/docs/', import.meta.url))
const policyFixtureDirectory = fileURLToPath(
  new URL('../public/examples/acme-policy/', import.meta.url)
)

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return markdownFiles(path)
    return entry.name.endsWith('.md') ? [path] : []
  })
}

function schemaFences(node) {
  return [
    ...(node.type === 'fence' && node.attributes.schema === 'pgroles-manifest'
      ? [node]
      : []),
    ...(node.children ?? []).flatMap(schemaFences),
  ]
}

function rangesForKey(code, key) {
  return getPgrolesSemanticRanges(code).ranges.filter(
    (range) => code.slice(range.start, range.end) === key
  )
}

function assertRecognizedPolicy(code, source) {
  const semantic = getPgrolesSemanticRanges(code)
  assert.deepEqual(semantic.errors, [], `${source}: invalid YAML`)
  const unrecognized = semantic.ranges.filter(
    (range) => range.className === 'pgroles-unrecognized'
  )
  assert.deepEqual(
    unrecognized,
    [],
    `${source}: unrecognized policy fields: ${unrecognized
      .map((range) => code.slice(range.start, range.end))
      .join(', ')}`
  )
}

test('every schema-tagged documentation example has recognized policy fields', () => {
  let fenceCount = 0
  for (const file of markdownFiles(pagesDirectory)) {
    const markdown = readFileSync(file, 'utf8')
    const document = Markdoc.parse(markdown)
    assert.deepEqual(document.errors, [], `${file}: invalid Markdoc`)

    for (const fence of schemaFences(document)) {
      fenceCount += 1
      assertRecognizedPolicy(fence.attributes.content, file)
    }
  }
  assert(fenceCount > 0, 'expected at least one schema-tagged policy fence')
})

test('complete downloadable chapter policies have recognized fields', () => {
  const fixtures = readdirSync(policyFixtureDirectory).filter((file) =>
    /^chapter-.*\.yaml$/.test(file)
  )
  assert(fixtures.length > 0, 'expected downloadable chapter policy fixtures')
  for (const fixture of fixtures) {
    assertRecognizedPolicy(
      readFileSync(join(policyFixtureDirectory, fixture), 'utf8'),
      fixture
    )
  }
})

test('recognizes membership exclusivity and brownfield grant preservation', () => {
  const code = `roles:
  - name: warehouse_reader
    preserve_undeclared_grants: true
  - name: auditor
memberships:
  - role: pg_read_all_data
    exclusive: true
    members:
      - name: auditor
`

  for (const key of ['preserve_undeclared_grants', 'exclusive']) {
    const [range] = rangesForKey(code, key)
    assert.equal(range.className, 'pgroles-field')
    assert.match(range.title, /Additive mode skips|Explicit ensure: absent/)
  }
})

test('marks fields outside their supported policy paths as unrecognized', () => {
  const code = `roles:
  - name: warehouse_reader
    exclusive: true
memberships:
  - role: pg_read_all_data
    members:
      - name: auditor
        exclusive: true
        boguskey: true
`
  const unrecognized = getPgrolesSemanticRanges(code).ranges
    .filter((range) => range.className === 'pgroles-unrecognized')
    .map((range) => code.slice(range.start, range.end))
  assert.deepEqual(unrecognized, ['exclusive', 'exclusive', 'boguskey'])
})
