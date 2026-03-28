import { useState } from 'react'
import { useHITL } from '../hooks/useHITL'

const s: Record<string, React.CSSProperties> = {
  wrap:    { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16 },
  title:   { fontSize: 11, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 },
  label:   { fontSize: 11, color: '#666', marginBottom: 4 },
  editor:  { width: '100%', background: '#0a0a0a', border: '1px solid #333', borderRadius: 6, padding: 10, color: '#e0e0e0', fontFamily: 'monospace', fontSize: 11, resize: 'vertical', minHeight: 120, boxSizing: 'border-box' as const },
  actions: { display: 'flex', gap: 8, marginTop: 10 },
  btn:     { background: '#1a1a2d', border: '1px solid #2a2a4d', color: '#63b3ed', borderRadius: 5, padding: '6px 16px', fontSize: 11, cursor: 'pointer' },
  error:   { color: '#fc8181', fontSize: 11, marginTop: 6 },
  success: { color: '#68d391', fontSize: 11, marginTop: 6 },
}

const TEMPLATES: Record<string, object> = {
  scope:       { scope_rules: { in_scope: ["https://target.com"], out_of_scope: [] } },
  credentials: { operator_context: { credentials: { username: "test@test.com", password: "password" } } },
  threshold:   { confidence_threshold: 0.75 },
}

export default function StateEditor() {
  const { injectState } = useHITL()
  const [json,    setJson]    = useState(JSON.stringify(TEMPLATES.scope, null, 2))
  const [error,   setError]   = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleInject() {
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const parsed = JSON.parse(json)
      await injectState(parsed)
      setSuccess(`✓ State updated: ${Object.keys(parsed).join(', ')}`)
    } catch (e) {
      setError(e instanceof SyntaxError ? 'Invalid JSON' : String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={s.wrap}>
      <div style={s.title}>State Injection</div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        {Object.keys(TEMPLATES).map((tpl) => (
          <button key={tpl} style={{ ...s.btn, fontSize: 10, padding: '3px 10px' }}
            onClick={() => setJson(JSON.stringify(TEMPLATES[tpl], null, 2))}>
            {tpl}
          </button>
        ))}
      </div>

      <div style={s.label}>JSON fields to inject into BountyMindState:</div>
      <textarea
        style={s.editor}
        value={json}
        onChange={(e) => setJson(e.target.value)}
        spellCheck={false}
      />

      <div style={s.actions}>
        <button style={s.btn} onClick={handleInject} disabled={loading}>
          {loading ? '...' : '↑ Inject State'}
        </button>
      </div>

      {error   && <div style={s.error}>{error}</div>}
      {success && <div style={s.success}>{success}</div>}
    </div>
  )
}
