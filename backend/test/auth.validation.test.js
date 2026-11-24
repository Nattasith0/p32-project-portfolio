import test from 'node:test'
import assert from 'node:assert/strict'
import { parseLoginInput } from '../src/modules/auth/auth.validation.js'

// ข้อมูลสมมติสำหรับทดสอบเท่านั้น
const validInput = {
    username: 'student_demo',
    password: 'Example test password!',
}

test('normalizes username and preserves password and original input', () => {
    const input = {
        username: ' Student_Demo ',
        password: ' Keep My Spaces! ',
    }

    const original = { ...input }

    assert.deepEqual(parseLoginInput(input), {
        username: 'student_demo',
        password: ' Keep My Spaces! ',
    })

    assert.deepEqual(input, original)
})

test('rejects bodies that are not objects', () => {
    for (const input of [undefined, null, [], 'text', 123, true]) {
        assert.equal(parseLoginInput(input), null)
    }
})

test('requires both fields and rejects additional fields', () => {
    const invalidInputs = [
        {},
        { username: validInput.username },
        { password: validInput.password },
        { ...validInput, role: 'system_admin' },
    ]

    for (const input of invalidInputs) {
        assert.equal(parseLoginInput(input), null)
    }
})

test('rejects invalid field types and empty values', () => {
    const invalidInputs = [
        { ...validInput, username: null },
        { ...validInput, username: '' },
        { ...validInput, username: '   ' },
        { ...validInput, password: 123 },
        { ...validInput, password: [] },
        { ...validInput, password: '' },
    ]

    for (const input of invalidInputs) {
        assert.equal(parseLoginInput(input), null)
    }
})

test('accepts length boundaries and rejects oversized values', () => {
    assert.ok(parseLoginInput({
        username: 'a'.repeat(128),
        password: 'x'.repeat(1024),
    }))

    assert.equal(parseLoginInput({
        ...validInput,
        username: 'a'.repeat(129),
    }), null)

    assert.equal(parseLoginInput({
        ...validInput,
        password: 'x'.repeat(1025),
    }), null)
})

test('counts Unicode code points and keeps login separate from password setup', () => {
    const password = '🔑'.repeat(1024)

    assert.equal(
        parseLoginInput({ ...validInput, password }).password,
        password
    )

    assert.equal(parseLoginInput({
        ...validInput,
        password: '🔑'.repeat(1025),
    }), null)

    assert.equal(
        parseLoginInput({ ...validInput, password: 'x' }).password,
        'x'
    )
})