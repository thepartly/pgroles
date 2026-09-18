import assert from 'node:assert/strict'
import test from 'node:test'

import { withBasePath } from '../src/lib/routing.mjs'

test('adds the docs base path to root-relative links', () => {
  assert.equal(withBasePath('/pgroles', '/'), '/pgroles/')
  assert.equal(
    withBasePath('/pgroles', '/docs/quick-start'),
    '/pgroles/docs/quick-start'
  )
  assert.equal(withBasePath('', '/docs/quick-start'), '/docs/quick-start')
})

test('leaves links outside the docs site unchanged', () => {
  for (let href of [
    'https://github.com/thepartly/pgroles',
    'http://example.com',
    '//cdn.example.com/asset.js',
    'mailto:hello@example.com',
    'tel:+6400000000',
    '#installation',
  ]) {
    assert.equal(withBasePath('/pgroles', href), href)
  }
})
