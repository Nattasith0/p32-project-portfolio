'use client'

import { useEffect, useState } from 'react'
import { getApiHealth } from '../../api/healthApi'

export default function ApiStatus() {
    const [apiState, setApiState] = useState({
        status: 'loading',
        message: '',
    })

    useEffect(() => {
        const controller = new AbortController()

        async function loadApiHealth() {
            try {
                const data = await getApiHealth(controller.signal)

                if (!controller.signal.aborted) {
                    setApiState({
                        status: 'success',
                        message: data.message,
                    })
                }
            } catch {
                if (!controller.signal.aborted) {
                    setApiState({
                        status: 'error',
                        message: 'ยังไม่สามารถติดต่อบริการ P32 ได้',
                    })
                }
            }
        }

        loadApiHealth()

        return () => {
            controller.abort()
        }
    }, [])

    if (apiState.status === 'loading') {
        return <p role="status">กำลังตรวจการเชื่อมต่อ...</p>
    }

    if (apiState.status === 'error') {
        return <p role="alert">{apiState.message}</p>
    }

    return <p role="status">{apiState.message}</p>
}