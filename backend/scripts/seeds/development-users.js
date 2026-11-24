const ADMIN_DEMO_USER_ID = '00000000-0000-4000-8000-000000000001'

export const DEVELOPMENT_USERS = [
    {
        userId: ADMIN_DEMO_USER_ID,
        username: 'admin_demo',
        email: 'admin_demo@example.test',
        displayName: 'ผู้ดูแลระบบทดสอบ',
        roleCode: 'system_admin',
        assignedByUserId: ADMIN_DEMO_USER_ID,
        passwordEnvName: 'P32_SEED_ADMIN_PASSWORD',
    },
    {
        userId: '00000000-0000-4000-8000-000000000002',
        username: 'student_demo',
        email: 'student_demo@example.test',
        displayName: 'นักศึกษาทดสอบ',
        roleCode: 'student',
        assignedByUserId: ADMIN_DEMO_USER_ID,
        passwordEnvName: 'P32_SEED_STUDENT_PASSWORD',
    },
]