import { useRunStore } from '../stores/runStore'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export function useHITL() {
  const threadId = useRunStore((s) => s.threadId)
  const setRun   = useRunStore((s) => s.setRun)

  async function respondToInterrupt(
    hitlType: string,
    response: Record<string, unknown>,
    stateUpdates?: Record<string, unknown>,
  ) {
    if (!threadId) throw new Error('No active thread')
    const res = await fetch(
      `${API_BASE}/api/runs/${threadId}/interrupt/${hitlType}/respond`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ response, state_updates: stateUpdates ?? {} }),
      },
    )
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async function injectState(updates: Record<string, unknown>) {
    if (!threadId) throw new Error('No active thread')
    const res = await fetch(`${API_BASE}/api/runs/${threadId}/state`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(updates),
    })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async function getCheckpoints(): Promise<
    Array<{ checkpoint_id: string; phase: string; timestamp: string; step: number }>
  > {
    if (!threadId) return []
    const res = await fetch(`${API_BASE}/api/runs/${threadId}/checkpoints`)
    if (!res.ok) return []
    const data = await res.json()
    return data.checkpoints ?? []
  }

  async function rollback(checkpointId: string) {
    if (!threadId) throw new Error('No active thread')
    const res = await fetch(
      `${API_BASE}/api/runs/${threadId}/rollback/${checkpointId}`,
      { method: 'POST' },
    )
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  return { respondToInterrupt, injectState, getCheckpoints, rollback }
}
