import { Pool } from 'pg'

const requiredVariables = [
    'PGHOST',
    'PGPORT',
    'PGDATABASE',
    'PGUSER',
    'PGPASSWORD',
]

for (const name of requiredVariables) {
    if (!process.env[name]) {
        throw new Error(`Missing database setting: ${name}`)
    }
}

const port = Number(process.env.PGPORT)

if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PGPORT must be an integer between 1 and 65535')
}

export const pool = new Pool({
    host: process.env.PGHOST,
    port,
    database: process.env.PGDATABASE,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    max: 5,
    connectionTimeoutMillis: 5000,
})

pool.on('error', (error) => {
    console.error('Database pool error:', error.code ?? 'UNKNOWN')
})