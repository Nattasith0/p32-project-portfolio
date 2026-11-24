import { createReadOnlyTransaction } from '../../database/read-only-transaction.js'
import { createUserSearchRepository } from './user-search.repository.js'

export function createUserSearchRuntimeRepository(pool) {
  const runReadOnly = createReadOnlyTransaction(pool)

  return {
    searchUsers(search) {
      return runReadOnly((database) =>
        createUserSearchRepository(database).searchUsers(search),
      )
    },
  }
}
