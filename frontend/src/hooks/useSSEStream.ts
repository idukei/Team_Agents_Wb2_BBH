import { useEffect, useRef } from 'react'
import { useRunStore } from '../stores/runStore'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export function useSSEStream(threadId: string | null) {
  const esRef           = useRef<EventSource | null>(null)
  const retryRef        = useRef(0)
  const addEvent        = useRunStore((s) => s.addEvent)
  const setPhase        = useRunStore((s) => s.setPhase)
  const addInterrupt    = useRunStore((s) => s.addInterrupt)
  const updateAgent     = useRunStore((s) => s.updateAgentStatus)
  const setLoadouts     = useRunStore((s) => s.setAgentLoadouts)
  const setIsStreaming  = useRunStore((s) => s.setIsStreaming)
  const setRun          = useRunStore((s) => s.setRun)

  useEffect(() => {
    if (!threadId) return

    function connect() {
      if (esRef.current) esRef.current.close()

      const es = new EventSource(`${API_BASE}/api/runs/${threadId}/stream`)
      esRef.current = es
      setIsStreaming(true)

      es.onmessage = (e) => {
        retryRef.current = 0
        try {
          const data = JSON.parse(e.data)
          addEvent(data)

          if (data.type === 'hitl_pending') {
            addInterrupt(data)
          }
          if (data.phase) {
            setPhase(data.phase)
          }
          if (data.type === 'agent_status' && data.agent_id) {
            updateAgent(data.agent_id, {
              phase:          data.status?.phase          || '',
              iteration:      data.status?.iteration      || 0,
              last_finding:   data.status?.last_finding   || null,
              active:         data.status?.active         ?? false,
              findings_count: data.status?.findings_count || 0,
            })
          }
          if (data.type === 'loadouts_updated' && data.agent_loadouts) {
            setLoadouts(data.agent_loadouts)
          }
          if (data.type === 'state_snapshot' && data.state) {
            setRun({ state: data.state })
          }
        } catch { }
      }

      es.onerror = () => {
        es.close()
        setIsStreaming(false)
        const delay = Math.min(1000 * 2 ** retryRef.current, 30000)
        retryRef.current++
        setTimeout(connect, delay)
      }
    }

    connect()
    return () => {
      esRef.current?.close()
      setIsStreaming(false)
    }
  }, [threadId])
}
