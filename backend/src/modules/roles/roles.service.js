export function createRoleService({ roleRepository } = {}) {
  if (typeof roleRepository?.findAllRoles !== 'function') {
    throw new TypeError('A role repository is required')
  }

  async function listRoles() {
    const rows = await roleRepository.findAllRoles()

    if (!Array.isArray(rows)) {
      throw new TypeError('Invalid role catalog result')
    }

    return Array.from(rows, (row) => {
      if (
        !row ||
        typeof row.role_code !== 'string' ||
        row.role_code !== row.role_code.trim() ||
        !/^[a-z][a-z0-9_]*$/.test(row.role_code) ||
        typeof row.role_name !== 'string' ||
        row.role_name.trim().length === 0
      ) {
        throw new TypeError('Invalid role catalog row')
      }

      return {
        roleCode: row.role_code,
        roleName: row.role_name,
      }
    })
  }

  return { listRoles }
}
