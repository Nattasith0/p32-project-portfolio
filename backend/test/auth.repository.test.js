import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthRepository } from '../src/modules/auth/auth.repository.js'

test('passes username as a SQL parameter and keeps private fields inside the repository', async () => {
    const username = "' OR 1=1 --"
    const row = { user_id: 'test-user', password_hash: 'TEST_ONLY_PRIVATE_HASH' }
    const repository = createAuthRepository({
        async query(sql, values) {
            assert.match(sql, /WHERE username = \$1/)
            assert.equal(sql.includes(username), false)
            assert.deepEqual(values, [username])
            return { rows: [row] }
        },
    })
    assert.equal(await repository.findUserByUsername(username), row)
})

test('returns null when the database has no matching user', async () => {
    const repository = createAuthRepository({ query: async () => ({ rows: [] }) })
    assert.equal(await repository.findUserByUsername('missing_user'), null)
})

test('propagates query failures instead of returning a user', async () => {
    const failure = new Error('TEST_ONLY_DATABASE_FAILURE')
    const repository = createAuthRepository({ query: async () => { throw failure } })
    await assert.rejects(repository.findUserByUsername('student_demo'), (error) => error === failure)
})

test('requires a database query executor', () => {
    for (const database of [undefined, null, {}, { query: 123 }]) {
        assert.throws(() => createAuthRepository(database), TypeError)
    }
})
