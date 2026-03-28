import { useState } from 'react'
import { useRunStore } from '../stores/runStore'

type SurfaceTab = 'endpoints' | 'forms' | 'technologies' | 'behaviors' | 'js'

const s: Record<string, React.CSSProperties> = {
  wrap:     { },
  tabs:     { display: 'flex', gap: 0, borderBottom: '1px solid #222', marginBottom: 14 },
  tab:      { padding: '6px 14px', fontSize: 11, cursor: 'pointer', border: 'none', background: 'transparent', textTransform: 'uppercase' as const, letterSpacing: 1 },
  table:    { width: '100%', borderCollapse: 'collapse' as const, fontSize: 11 },
  th:       { textAlign: 'left' as const, padding: '6px 8px', color: '#555', fontSize: 10, textTransform: 'uppercase' as const, borderBottom: '1px solid #1a1a1a' },
  td:       { padding: '5px 8px', color: '#ccc', borderBottom: '1px solid #111', fontFamily: 'monospace', fontSize: 11 },
  badge:    (color: string): React.CSSProperties => ({
              display: 'inline-block', background: color + '22', color,
              border: `1px solid ${color}44`, borderRadius: 3, padding: '1px 7px', fontSize: 10,
            }),
  empty:    { color: '#333', fontSize: 12, textAlign: 'center' as const, padding: 24 },
  method:   (m: string): React.CSSProperties => ({
              display: 'inline-block', padding: '0 6px', borderRadius: 3, fontSize: 10, fontWeight: 700,
              background: m === 'POST' ? '#2d1a1a' : m === 'GET' ? '#1a2d1a' : '#1a1a2d',
              color:      m === 'POST' ? '#fc8181' : m === 'GET' ? '#68d391' : '#63b3ed',
            }),
}

export default function SurfaceMapViewer() {
  const [tab, setTab] = useState<SurfaceTab>('endpoints')
  const run  = useRunStore((s) => s.run) as Record<string, unknown> | null
  const inv  = ((run?.state as Record<string,unknown> || {}).surface_inventory || {}) as Record<string, unknown>

  const endpoints   = (inv.endpoints   || []) as Record<string,unknown>[]
  const forms       = (inv.forms       || []) as Record<string,unknown>[]
  const technologies = (inv.technologies || []) as Record<string,unknown>[]
  const behaviors   = (inv.behaviors   || []) as Record<string,unknown>[]
  const jsFindings  = (inv.js_findings || []) as Record<string,unknown>[]

  const tabs: { id: SurfaceTab; label: string; count: number }[] = [
    { id: 'endpoints',    label: 'Endpoints',    count: endpoints.length },
    { id: 'forms',        label: 'Forms',        count: forms.length },
    { id: 'technologies', label: 'Technologies', count: technologies.length },
    { id: 'behaviors',    label: 'Behaviors',    count: behaviors.length },
    { id: 'js',           label: 'JS Findings',  count: jsFindings.length },
  ]

  return (
    <div style={s.wrap}>
      <div style={s.tabs}>
        {tabs.map(({ id, label, count }) => (
          <button key={id} style={{
            ...s.tab,
            color:        tab === id ? '#e53e3e' : '#555',
            borderBottom: tab === id ? '2px solid #e53e3e' : '2px solid transparent',
          }} onClick={() => setTab(id)}>
            {label} {count > 0 && <span style={{ color: '#444', fontSize: 10 }}>({count})</span>}
          </button>
        ))}
      </div>

      {tab === 'endpoints' && (
        endpoints.length === 0 ? <div style={s.empty}>No endpoints yet</div> :
        <table style={s.table}>
          <thead><tr>
            <th style={s.th}>Method</th>
            <th style={s.th}>URL</th>
            <th style={s.th}>Status</th>
            <th style={s.th}>Content-Type</th>
          </tr></thead>
          <tbody>
            {endpoints.slice(0, 100).map((ep, i) => (
              <tr key={i}>
                <td style={s.td}><span style={s.method(ep.method as string || 'GET')}>{ep.method as string || 'GET'}</span></td>
                <td style={{ ...s.td, color: '#63b3ed' }}>{ep.url as string}</td>
                <td style={s.td}>{ep.status_code as number || '—'}</td>
                <td style={{ ...s.td, color: '#555' }}>{(ep.content_type as string || '').split(';')[0]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'forms' && (
        forms.length === 0 ? <div style={s.empty}>No forms yet</div> :
        <table style={s.table}>
          <thead><tr>
            <th style={s.th}>Action</th>
            <th style={s.th}>Method</th>
            <th style={s.th}>Fields</th>
          </tr></thead>
          <tbody>
            {forms.map((f, i) => (
              <tr key={i}>
                <td style={{ ...s.td, color: '#63b3ed' }}>{f.action as string}</td>
                <td style={s.td}><span style={s.method(f.method as string || 'POST')}>{f.method as string || 'POST'}</span></td>
                <td style={{ ...s.td, color: '#b794f4' }}>
                  {(f.fields as Record<string,unknown>[] || []).map(fi => fi.name as string).join(', ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'technologies' && (
        technologies.length === 0 ? <div style={s.empty}>No technologies detected</div> :
        <table style={s.table}>
          <thead><tr>
            <th style={s.th}>Technology</th>
            <th style={s.th}>Version</th>
            <th style={s.th}>Confidence</th>
            <th style={s.th}>Category</th>
          </tr></thead>
          <tbody>
            {technologies.map((t, i) => (
              <tr key={i}>
                <td style={{ ...s.td, color: '#68d391', fontWeight: 600 }}>{t.name as string}</td>
                <td style={s.td}>{t.version as string || '—'}</td>
                <td style={s.td}>
                  <span style={s.badge('#68d391')}>{((t.confidence as number || 0) * 100).toFixed(0)}%</span>
                </td>
                <td style={{ ...s.td, color: '#555' }}>{t.category as string || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'behaviors' && (
        behaviors.length === 0 ? <div style={s.empty}>No behaviors detected</div> :
        <table style={s.table}>
          <thead><tr>
            <th style={s.th}>Pattern</th>
            <th style={s.th}>URL</th>
            <th style={s.th}>Significance</th>
          </tr></thead>
          <tbody>
            {behaviors.map((b, i) => (
              <tr key={i}>
                <td style={s.td}><span style={s.badge('#f6ad55')}>{b.pattern as string}</span></td>
                <td style={{ ...s.td, color: '#63b3ed' }}>{b.url as string}</td>
                <td style={{ ...s.td, color: '#888' }}>{b.significance as string}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'js' && (
        jsFindings.length === 0 ? <div style={s.empty}>No JS findings</div> :
        <table style={s.table}>
          <thead><tr>
            <th style={s.th}>Type</th>
            <th style={s.th}>Value</th>
            <th style={s.th}>Source</th>
          </tr></thead>
          <tbody>
            {jsFindings.map((f, i) => (
              <tr key={i}>
                <td style={s.td}><span style={s.badge('#fc8181')}>{f.type as string}</span></td>
                <td style={{ ...s.td, color: '#b794f4', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.value as string}</td>
                <td style={{ ...s.td, color: '#555' }}>{f.url as string}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
