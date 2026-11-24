export function createRoleRepository(database) {
  if (typeof database?.query !== 'function') {
    throw new TypeError('A database query executor is required')
  }

  async function findAllRoles() {
    const result = await database.query(`
      SELECT role_code, role_name
      FROM p32.roles
      ORDER BY role_code
    `)

    return result.rows
  }

  return { findAllRoles }
}
