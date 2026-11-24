import test from 'node:test'
import assert from 'node:assert/strict'
import { parseUserRolesUserId } from '../src/modules/users/user-roles.validation.js'

const ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

test('accepts a UUID string and normalizes hexadecimal case', () => {
  assert.equal(parseUserRolesUserId(ID), ID)
  assert.equal(parseUserRolesUserId(ID.toUpperCase()), ID)
})

test('rejects values that are not primitive UUID strings without coercion', () => {
  for (const value of [
    undefined,
    null,
    true,
    123,
    [],
    [ID],
    {},
    { userId: ID },
    new String(ID),
  ]) {
    assert.equal(parseUserRolesUserId(value), null)
  }
  let conversions = 0
  assert.equal(
    parseUserRolesUserId({
      toString() {
        conversions += 1
        return ID
      },
    }),
    null,
  )
  assert.equal(conversions, 0)
})

test('rejects malformed, padded, overlong and SQL-looking identifiers', () => {
  for (const value of [
    '',
    'invalid',
    ID.replace(/-/g, ''),
    ID.replace('4ccc', 'zzzz'),
    ` ${ID}`,
    `${ID} `,
    `${ID}\n`,
    `${ID}\0`,
    ID.slice(0, -1),
    ID + '0',
    "x' OR 1=1 --",
  ]) {
    assert.equal(parseUserRolesUserId(value), null)
  }
})

test('validates UUID syntax without requiring a version or deciding whether the account exists', () => {
  assert.equal(
    parseUserRolesUserId('00000000-0000-0000-0000-000000000000'),
    '00000000-0000-0000-0000-000000000000',
  )
  assert.equal(
    parseUserRolesUserId('11111111-2222-3333-4444-555555555555'),
    '11111111-2222-3333-4444-555555555555',
  )
})
