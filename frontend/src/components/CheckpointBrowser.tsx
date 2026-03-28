import { useState, useEffect } from 'react'
import { useHITL } from '../hooks/useHITL'
import { useRunStore } from '../stores/runStore'

type Checkpoint = { checkpoint_id: string; phase: string; timestamp: string; step: number }

const s: Record<string, React.CSSProperties> = {
  wrap:   { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16 },
  title:  { fontSize: 11, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 },
  row:    { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #111' },
  phase:  { fontSize: 11, fontFamily: 'monospace', color: '#63b3ed' },
  ts:     { fontSize: 10, color: '#555' },
  step:   { fontSize: 10, color: '#333', fontFamily: 'monospace' },
  btn:    { background: '#2d1a1a', border: '1px solid #fc818144', color: '#fc8181', borderRadius: 4, padding: '2px 10px', fontSize: 10, cursor: 'pointer' },
  modal:  { position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
  mCard:  { background: '#111', border: '1px solid #333', borderRadius: 8, padding: 24, maxWidth: 400, width: '90%' },
  mTitle: { fontSize: 14, color: '#fc8181', fontWeight: 700, marginBottom: 10 },
  mText:  { fontSize: 12, color: '#888', marginBottom: 16 },
  mBtns:  { display: 'flex', gap: 10 },
  mConf:  { background: '#2d1a1a', border: '1px solid #fc818144', color: '#fc8181', borderRadius: 5, padding: '6px 18px', fontSize: 12, cursor: 'pointer' },
  mCanc:  { background: 'transparent', border: '1px solid #333', color: '#555', borderRadius: 5, padding: '6px 18px', fontSize: 12, cursor: 'pointer' },
  empty:  { color: '#333', fontSize: 12, textAlign: 'center', padding: 24 },
  load:   { background: '#1a1a2d', border: '1px solid #2a2a4d', color: '#63b3ed', borderRadius: 5, padding: '4px 12px', fontSize: 11, cursor: 'pointer', marginBottom: 10 },
}

export default function CheckpointBrowser() {
  const [checkpoints, setCheckpoints] = useState<Checkpoint[]>([])
  const [confirm,     setConfirm]     = useState<Checkpoint | null>(null)
  const [loading,     setLoading]     = useState(false)
  const { getCheckpoints, rollback }  = useHITL()
  const threadId                      = useRunStore((s) => s.threadId)

  async function load() {
    setLoading(true)
    try {
      const cps = await getCheckpoints()
      setCheckpoints(cps)
    } finally {
      setLoading(false)
    }
  }

  async function handleRollback(cp: Checkpoint) {
    setConfirm(null)
    setLoading(true)
    try {
      await rollback(cp.checkpoint_id)
    } finally {
      setLoading(false)
    }
  }

  if (!threadId) return null

  return (
    <div style={s.wrap}>
      <div style={s.title}>Time Travel — Checkpoints</div>

      <button style={s.load} onClick={load} disabled={loading}>
        {loading ? 'Loading...' : '↻ Load Checkpoints'}
      </button>

      {checkpoints.length === 0 && !loading && (
        <div style={s.empty}>No checkpoints loaded</div>
      )}

      {checkpoints.map((cp, i) => (
        <div key={i} style={s.row}>
          <div>
            <span style={s.phase}>{cp.phase || 'unknown'}</span>
            <span style={{ ...s.step, marginLeft: 8 }}>step {cp.step}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={s.ts}>{cp.timestamp ? new Date(cp.timestamp).toLocaleTimeString() : '—'}</span>
            <button style={s.btn} onClick={() => setConfirm(cp)}>⏪ Rollback</button>
          </div>
        </div>
      ))}

      {confirm && (
        <div style={s.modal}>
          <div style={s.mCard}>
            <div style={s.mTitle}>⚠ Confirm Rollback</div>
            <div style={s.mText}>
              Roll back to checkpoint at phase <strong style={{ color: '#63b3ed' }}>{confirm.phase}</strong> (step {confirm.step})?
              All progress after this point will be lost.
            </div>
            <div style={s.mBtns}>
              <button style={s.mConf} onClick={() => handleRollback(confirm)}>⏪ Confirm Rollback</button>
              <button style={s.mCanc} onClick={() => setConfirm(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
