import { useRunStore } from '../stores/runStore'

const TYPE_COLOR: Record<string, string> = {
  hitl_pending:    '#f6ad55',
  state_snapshot:  '#63b3ed',
  agent_status:    '#68d391',
  heartbeat:       '#2a2a2a',
  loadouts_updated:'#b794f4',
  error:           '#fc8181',
}

const s: Record<string, React.CSSProperties> = {
  wrap:    { display: 'flex', flexDirection: 'column' as const, gap: 1, maxHeight: 480, overflowY: 'auto' as const },
  row:     { display: 'flex', gap: 10, padding: '4px 8px', borderRadius: 4, alignItems: 'flex-start' },
  ts:      { fontSize: 10, color: '#333', fontFamily: 'monospace', minWidth: 80, paddingTop: 1 },
  type:    (t: string): React.CSSProperties => ({
             fontSize: 10, fontFamily: 'monospace', minWidth: 120,
             color: TYPE_COLOR[t] || '#555', paddingTop: 1,
           }),
  content: { fontSize: 11, color: '#888', flex: 1, wordBreak: 'break-all' as const },
  empty:   { color: '#333', fontSize: 12, textAlign: 'center' as const, padding: 32 },
}

export default function EventLog() {
  const events = useRunStore((s) => s.events) as Record<string, unknown>[]

  if (events.length === 0) {
    return <div style={s.empty}>Waiting for events…</div>
  }

  const visible = [...events].reverse().slice(0, 100)

  return (
    <div style={s.wrap}>
      {visible.map((ev, i) => {
        const t    = ev.type as string || 'event'
        const ts   = ev.timestamp as string || ''
        const time = ts ? new Date(ts).toLocaleTimeString() : ''

        if (t === 'heartbeat') return null

        const preview = t === 'state_snapshot'
          ? `phase: ${ev.phase as string || '?'}`
          : t === 'agent_status'
          ? `${ev.agent_id as string} → ${(ev.status as Record<string,unknown> || {}).phase || '?'} [iter: ${(ev.status as Record<string,unknown> || {}).iteration || 0}]`
          : t === 'hitl_pending'
          ? `⚠ ${ev.label as string || ev.interrupt_type as string}`
          : JSON.stringify(ev).slice(0, 120)

        return (
          <div key={i} style={{ ...s.row, background: i % 2 === 0 ? '#0d0d0d' : 'transparent' }}>
            <span style={s.ts}>{time}</span>
            <span style={s.type(t)}>{t}</span>
            <span style={s.content}>{preview}</span>
          </div>
        )
      })}
    </div>
  )
}
