export async function getApiHealth(signal?: AbortSignal): Promise<{ status: 'ok'; system: 'P32'; message: string }> {
    const response = await fetch('/api/health', { signal })

    if (!response.ok) {
        throw new Error('Health request failed')
    }

    const data: unknown = await response.json()

    if (
        typeof data !== 'object' || data === null ||
        !('status' in data) || data.status !== 'ok' ||
        !('system' in data) || !('message' in data) ||
        data?.system !== 'P32' ||
        typeof data?.message !== 'string'
    ) {
        throw new Error('Invalid health response')
    }

    return { status: 'ok', system: 'P32', message: data.message }
}