export function createRoleController({ roleService } = {}) {
  if (typeof roleService?.listRoles !== 'function') {
    throw new TypeError('A role service is required')
  }

  async function getRoles(request, response) {
    response.set('Cache-Control', 'no-store')
    const roles = await roleService.listRoles()

    if (!Array.isArray(roles)) {
      throw new TypeError('Invalid role catalog response')
    }

    return response.status(200).json({ roles })
  }

  return { getRoles }
}
