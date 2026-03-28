import { useState } from 'react'
import { useHITL } from '../hooks/useHITL'

interface Props {
  interrupt: {
    interrupt_type: string
    hitl_id:        string
    label:          string
    description:    string
    operator_can:   string[]
    payload:        Record<string, unknown>
  }
  onResolved?: () => void
}

const s: Record<string, React.CSSProperties> = {
  card:    { background: '#111', border: '1px solid #f6ad5544', borderRadius: 8, padding: 20, marginBottom: 12 },
  header:  { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  badge:   { display: 'inline-block', background: '#2d2a1a', color: '#f6ad55', border: '1px solid #f6ad5544', borderRadius: 4, padding: '2px 10px', fontSize: 11, fontWeight: 700 },
  label:   { fontSize: 14, fontWeight: 700, color: '#fbd38d' },
  desc:    { fontSize: 12, color: '#888', marginBottom: 12 },
  canDo:   { fontSize: 11, color: '#555', marginBottom: 14 },
  canItem: { display: 'inline-block', background: '#1a1a1a', border: '1px solid #222', borderRadius: 3, padding: '2px 8px', marginRight: 6, marginBottom: 4 },
  payload: { background: '#0a0a0a', border: '1px solid #1a1a1a', borderRadius: 6, padding: 10, fontSize: 10, fontFamily: 'monospace', color: '#718096', maxHeight: 200, overflow: 'auto', marginBottom: 12 },
  textarea:{ width: '100%', background: '#0a0a0a', border: '1px solid #333', borderRadius: 6, padding: 8, color: '#e0e0e0', fontFamily: 'monospace', fontSize: 11, resize: 'vertical', minHeight: 80, marginBottom: 12, boxSizing: 'border-box' },
  actions: { display: 'flex', gap: 8 },
  btnApprove: { background: '#1a3a1a', border: '1px solid #68d391', color: '#68d391', borderRadius: 6, padding: '8px 20px', fontSize: 12, cursor: 'pointer', fontWeight: 700 },
  btnReject:  { background: '#3a1a1a', border: '1px solid #fc8181', color: '#fc8181', borderRadius: 6, padding: '8px 20px', fontSize: 12, cursor: 'pointer', fontWeight: 700 },
  btnEdit:    { background: '#1a1a3a', border: '1px solid #63b3ed', color: '#63b3ed', borderRadius: 6, padding: '8px 20px', fontSize: 12, cursor: 'pointer', fontWeight: 700 },
  error:   { color: '#fc8181', fontSize: 12, marginTop: 8 },
}

export default function InterruptCard({ interrupt, onResolved }: Props) {
  const { respondToInterrupt } = useHITL()
  const [editJson, setEditJson] = useState('')
  const [showEdit, setShowEdit] = useState(false)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')

  async function handleApprove() {
    setLoading(true)
    setError('')
    try {
      await respondToInterrupt(interrupt.interrupt_type, { action: 'approve' })
      onResolved?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  async function handleReject() {
    setLoading(true)
    setError('')
    try {
      await respondToInterrupt(interrupt.interrupt_type, { action: 'reject' })
      onResolved?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  async function handleEdit() {
    if (!editJson.trim()) return
    setLoading(true)
    setError('')
    try {
      const parsed = JSON.parse(editJson)
      await respondToInterrupt(interrupt.interrupt_type, { action: 'edit', ...parsed })
      onResolved?.()
    } catch (e) {
      setError(e instanceof SyntaxError ? 'Invalid JSON' : String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={s.card}>
      <div style={s.header}>
        <div>
          <span style={s.badge}>{interrupt.hitl_id}</span>
          <span style={{ ...s.label, marginLeft: 10 }}>{interrupt.label}</span>
        </div>
        <span style={{ fontSize: 11, color: '#555', fontFamily: 'monospace' }}>{interrupt.interrupt_type}</span>
      </div>

      <div style={s.desc}>{interrupt.description}</div>

      <div style={s.canDo}>
        Operator can:&nbsp;
        {(interrupt.operator_can || []).map((c, i) => (
          <span key={i} style={s.canItem}>{c}</span>
        ))}
      </div>

      <div style={s.payload}>{JSON.stringify(interrupt.payload, null, 2)}</div>

      {showEdit && (
        <textarea
          style={s.textarea}
          value={editJson}
          onChange={(e) => setEditJson(e.target.value)}
          placeholder={`Paste edited JSON here, e.g.:\n{\n  "agent_loadouts": { ... },\n  "scope_rules": { ... }\n}`}
        />
      )}

      <div style={s.actions}>
        <button style={s.btnApprove} onClick={handleApprove} disabled={loading}>
          {loading ? '...' : '✓ Approve'}
        </button>
        <button style={s.btnReject} onClick={handleReject} disabled={loading}>
          ✗ Reject
        </button>
        <button style={s.btnEdit} onClick={() => {
          setShowEdit(!showEdit)
          if (!editJson) setEditJson(JSON.stringify(interrupt.payload, null, 2))
        }} disabled={loading}>
          ✎ Edit
        </button>
        {showEdit && editJson && (
          <button style={{ ...s.btnEdit, background: '#1a2d1a', borderColor: '#68d391', color: '#68d391' }}
            onClick={handleEdit} disabled={loading}>
            ↑ Submit Edit
          </button>
        )}
      </div>

      {error && <div style={s.error}>⚠ {error}</div>}
    </div>
  )
}
