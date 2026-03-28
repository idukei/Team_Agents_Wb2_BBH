const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status}: ${text}`)
  }
  return res.json()
}

export const startRun = (body: {
  target_brief: string
  scope_rules?:  Record<string, unknown>
  run_config?:   Record<string, unknown>
}) => request<{ thread_id: string; status: string }>('/api/runs', {
  method: 'POST',
  body:   JSON.stringify(body),
})

export const getRun = (threadId: string) =>
  request<Record<string, unknown>>(`/api/runs/${threadId}`)

export const patchState = (threadId: string, updates: Record<string, unknown>) =>
  request(`/api/runs/${threadId}/state`, {
    method: 'PATCH',
    body:   JSON.stringify(updates),
  })

export const respondInterrupt = (
  threadId:      string,
  hitlType:      string,
  response:      Record<string, unknown>,
  stateUpdates?: Record<string, unknown>,
) => request(`/api/runs/${threadId}/interrupt/${hitlType}/respond`, {
  method: 'POST',
  body:   JSON.stringify({ response, state_updates: stateUpdates ?? {} }),
})
