import { createReadOnlyTransaction } from '../../database/read-only-transaction.js'
import { createUserRolesRepository } from './user-roles.repository.js'

export function createUserRolesRuntimeRepository(pool) {
  const runReadOnly = createReadOnlyTransaction(pool)

  return {
    findUserRolesByUserId(userId) {
      return runReadOnly((database) =>
        createUserRolesRepository(database).findUserRolesByUserId(userId),
      )
    },
  }
}
