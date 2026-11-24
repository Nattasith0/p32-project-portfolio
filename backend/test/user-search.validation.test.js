import test from 'node:test'
import assert from 'node:assert/strict'
import { parseUserSearchQuery } from '../src/modules/users/user-search.validation.js'

const AFTER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

test('trims the search term, keeps its case and applies bounded defaults without mutation', () => {
  const input = { q: '  Student Demo  ' }
  assert.deepEqual(parseUserSearchQuery(input), {
    searchTerm: 'Student Demo',
    limit: 20,
    after: null,
  })
  assert.deepEqual(input, { q: '  Student Demo  ' })
})

test('accepts canonical page size and normalizes the UUID cursor', () => {
  assert.deepEqual(
    parseUserSearchQuery({ q: 'นักศึกษา', limit: '50', after: AFTER.toUpperCase() }),
    {
      searchTerm: 'นักศึกษา',
      limit: 50,
      after: AFTER,
    },
  )
  assert.equal(parseUserSearchQuery({ q: 'ab', limit: '1' }).limit, 1)
})

test('requires an own q field and rejects non-object query values', () => {
  for (const input of [
    undefined,
    null,
    [],
    'admin',
    1,
    true,
    {},
    Object.create({ q: 'admin' }),
  ]) {
    assert.equal(parseUserSearchQuery(input), null)
  }
})

test('accepts a null-prototype query object from a request parser', () => {
  const input = Object.assign(Object.create(null), { q: 'admin', limit: '20' })
  assert.deepEqual(parseUserSearchQuery(input), {
    searchTerm: 'admin',
    limit: 20,
    after: null,
  })
})

test('rejects unknown query fields rather than accepting identity or projection instructions', () => {
  for (const key of [
    'userId',
    'role',
    'includePassword',
    'offset',
    'sort',
    'q[name]',
    '__proto__',
  ]) {
    const input = Object.assign(Object.create(null), { q: 'admin', [key]: 'unexpected' })
    assert.equal(parseUserSearchQuery(input), null)
  }
})

test('rejects repeated or structured search terms and blank or too-short text', () => {
  for (const q of [
    null,
    undefined,
    123,
    ['admin', 'student'],
    { name: 'admin' },
    '',
    ' ',
    'a',
    '  a  ',
    '\u0085\u0085',
  ]) {
    assert.equal(parseUserSearchQuery({ q }), null)
  }
})

test('counts Unicode code points at the search length boundaries', () => {
  assert.equal(parseUserSearchQuery({ q: '😀😀' }).searchTerm, '😀😀')
  assert.equal(parseUserSearchQuery({ q: '😀'.repeat(100) }).searchTerm.length, 200)
  assert.equal(parseUserSearchQuery({ q: '😀' }), null)
  assert.equal(parseUserSearchQuery({ q: '😀'.repeat(101) }), null)
})

test('rejects NUL and malformed UTF-16 before values can reach PostgreSQL', () => {
  for (const q of ['ad\0min', '\ud800x', 'x\udfff'])
    assert.equal(parseUserSearchQuery({ q }), null)
})

test('preserves literal wildcard, escape and SQL-looking characters as search data', () => {
  for (const q of ['50%', '_demo', 'a!b', String.raw`a\b`, "x' OR 1=1 --"]) {
    assert.equal(parseUserSearchQuery({ q }).searchTerm, q)
  }
})

test('rejects noncanonical, repeated and out-of-range page sizes', () => {
  for (const limit of [
    undefined,
    null,
    20,
    ['20'],
    {},
    '',
    '0',
    '51',
    '-1',
    '01',
    '+1',
    '1.0',
    '1e1',
    ' 1',
    '1\n',
    'Infinity',
    '100',
  ]) {
    assert.equal(parseUserSearchQuery({ q: 'admin', limit }), null)
  }
})

test('rejects malformed, blank and repeated cursors', () => {
  for (const after of [
    undefined,
    null,
    1,
    [],
    [AFTER],
    {},
    '',
    'invalid',
    ' ' + AFTER,
    AFTER + '\n',
  ]) {
    assert.equal(parseUserSearchQuery({ q: 'admin', after }), null)
  }
})
