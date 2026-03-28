import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { startRun } from '../api/client'
import { useRunStore } from '../stores/runStore'

const EXAMPLES = [
  'https://app.example.com — SaaS B2B dashboard with JWT auth',
  'https://shop.example.com — E-commerce with Stripe payments',
  'https://api.example.com — REST API with OAuth2 Google SSO',
]

const s: Record<string, React.CSSProperties> = {
  wrap:     { maxWidth: 640 },
  label:    { fontSize: 11, color: '#555', textTransform: 'uppercase' as const, letterSpacing: 1, marginBottom: 6, display: 'block' },
  textarea: { width: '100%', background: '#0a0a0a', border: '1px solid #333', borderRadius: 6, padding: 12, color: '#e0e0e0', fontFamily: 'system-ui', fontSize: 13, resize: 'vertical' as const, minHeight: 90, marginBottom: 14, boxSizing: 'border-box' as const },
  examples: { display: 'flex', flexDirection: 'column' as const, gap: 6, marginBottom: 16 },
  exBtn:    { background: 'transparent', border: '1px solid #222', color: '#444', borderRadius: 5, padding: '5px 10px', fontSize: 11, cursor: 'pointer', textAlign: 'left' as const },
  row:      { display: 'flex', gap: 10, marginBottom: 14 },
  input:    { flex: 1, background: '#0a0a0a', border: '1px solid #333', borderRadius: 5, padding: '7px 10px', color: '#e0e0e0', fontSize: 12 },
  btnStart: { background: '#e53e3e', border: 'none', color: '#fff', borderRadius: 6, padding: '10px 28px', fontSize: 13, fontWeight: 700, cursor: 'pointer' },
  error:    { color: '#fc8181', fontSize: 12, marginTop: 8 },
}

export default function NewRunForm() {
  const [brief,     setBrief]     = useState('')
  const [inScope,   setInScope]   = useState('')
  const [threshold, setThreshold] = useState('0.85')
  const [loading,   setLoading]   = useState(false)
  const [error,     setError]     = useState('')
  const setThreadId = useRunStore((s) => s.setThreadId)
  const navigate    = useNavigate()

  async function handleStart() {
    if (!brief.trim()) { setError('Target brief is required'); return }
    setLoading(true)
    setError('')
    try {
      const scope_rules = inScope.trim()
        ? { in_scope: inScope.split('\n').map(s => s.trim()).filter(Boolean), out_of_scope: [] }
        : {}
      const { thread_id } = await startRun({
        target_brief: brief.trim(),
        scope_rules,
        run_config: { confidence_threshold: parseFloat(threshold) || 0.85 },
      })
      setThreadId(thread_id)
      navigate(`/runs/${thread_id}`)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={s.wrap}>
      <div style={s.examples}>
        <span style={{ ...s.label, marginBottom: 4 }}>Examples</span>
        {EXAMPLES.map((ex, i) => (
          <button key={i} style={s.exBtn} onClick={() => setBrief(ex)}>{ex}</button>
        ))}
      </div>

      <label style={s.label}>Target Brief *</label>
      <textarea style={s.textarea} value={brief}
        onChange={(e) => setBrief(e.target.value)}
        placeholder="Describe the target: URL, tech stack, auth mechanism, scope..." />

      <label style={s.label}>In-Scope URLs (one per line, optional)</label>
      <textarea style={{ ...s.textarea, minHeight: 60 }} value={inScope}
        onChange={(e) => setInScope(e.target.value)}
        placeholder="https://app.example.com&#10;https://api.example.com" />

      <div style={s.row}>
        <div style={{ flex: 1 }}>
          <label style={s.label}>Confidence Threshold</label>
          <input style={s.input} type="number" min="0" max="1" step="0.05"
            value={threshold} onChange={(e) => setThreshold(e.target.value)} />
        </div>
      </div>

      <button style={s.btnStart} onClick={handleStart} disabled={loading}>
        {loading ? 'Launching...' : '🔴 Launch BountyMind'}
      </button>
      {error && <div style={s.error}>{error}</div>}
    </div>
  )
}
