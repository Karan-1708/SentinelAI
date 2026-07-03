import { useCallback, useEffect, useRef } from 'react'

const INITIAL_BACKOFF_MS = 250
const MAX_BACKOFF_MS = 8000

/**
 * Wrapper around the browser WebSocket with:
 *   * a single-in-flight guard (concurrent connect() calls collapse to one)
 *   * exponential backoff on reconnect
 *   * automatic pause when the tab is hidden (avoids wake-up storms)
 */
export function useWebSocket(
  url: string,
  onMessage: (data: unknown) => void,
  enabled = true,
) {
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffMs = useRef(INITIAL_BACKOFF_MS)
  const connecting = useRef(false)
  const disposed = useRef(false)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const clearTimer = () => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
  }

  const scheduleReconnect = useCallback((connect: () => void) => {
    clearTimer()
    reconnectTimer.current = setTimeout(() => {
      backoffMs.current = Math.min(backoffMs.current * 2, MAX_BACKOFF_MS)
      connect()
    }, backoffMs.current)
  }, [])

  const connect = useCallback(() => {
    if (!enabled || disposed.current) return
    if (connecting.current) return
    if (ws.current && (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING)) {
      return
    }
    if (document.visibilityState === 'hidden') {
      // Don't try to reconnect while the tab is backgrounded. The
      // visibilitychange listener will retry when we come back.
      return
    }

    connecting.current = true
    try {
      const socket = new WebSocket(url)
      ws.current = socket

      socket.onopen = () => {
        connecting.current = false
        backoffMs.current = INITIAL_BACKOFF_MS
      }

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessageRef.current(data)
        } catch {
          // Ignore non-JSON frames (ping/pong sentinels)
        }
      }

      socket.onclose = () => {
        connecting.current = false
        ws.current = null
        if (!disposed.current) scheduleReconnect(connect)
      }

      socket.onerror = () => {
        // Force onclose to fire so the reconnect path is exercised once.
        socket.close()
      }
    } catch {
      connecting.current = false
      scheduleReconnect(connect)
    }
  }, [url, enabled, scheduleReconnect])

  useEffect(() => {
    disposed.current = false
    connect()

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        // Reset backoff on foreground so the first retry is snappy.
        backoffMs.current = INITIAL_BACKOFF_MS
        connect()
      }
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      disposed.current = true
      document.removeEventListener('visibilitychange', onVisibilityChange)
      clearTimer()
      ws.current?.close()
      ws.current = null
    }
  }, [connect])
}
