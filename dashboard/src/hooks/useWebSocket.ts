import { useCallback, useEffect, useRef } from 'react'

const WS_RECONNECT_DELAY = 3000

export function useWebSocket(
  url: string,
  onMessage: (data: unknown) => void,
  enabled = true,
) {
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<ReturnType<typeof setTimeout>>()
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    if (!enabled) return
    try {
      ws.current = new WebSocket(url)

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessageRef.current(data)
        } catch {
          // ignore non-JSON frames
        }
      }

      ws.current.onclose = () => {
        // Reconnect after 3s backoff
        reconnectTimeout.current = setTimeout(connect, WS_RECONNECT_DELAY)
      }

      ws.current.onerror = () => {
        ws.current?.close()
      }
    } catch {
      reconnectTimeout.current = setTimeout(connect, WS_RECONNECT_DELAY)
    }
  }, [url, enabled])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimeout.current)
      ws.current?.close()
    }
  }, [connect])
}
