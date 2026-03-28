import { useState } from 'react'
import { useRunStore } from '../stores/runStore'

const AGENT_COLORS: Record<string, string> = {
  WebTester:        '#63b3ed',
  AuthProber:       '#f6ad55',
  LogicAnalyst:     '#b794f4',
  CodeInspector:    '#68d391',
  IntegrationScout: '#fc8181',
  InfraProber:      '#76e4f7',
}

const s: Record<string, React.CSSProperties> = {
  wrap:    { },
  grid:    { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 },
  card:    { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 14, cursor: 'pointer' },
  cardH:   { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  name:    { fontSize: 13, fontWeight: 700 },
  badge:   { display: 'inline-block', padding: '1px 8px', borderRadius: 3, fontSize: 10, fontWeight: 700 },
  mission: { fontSize: 11, color: '#888', lineHeight: 1.5, marginBottom: 8 },
  meta:    { display: 'flex', gap: 8, fontSize: 10, color: '#555' },
  detail:  { background: '#0a0a0a', border: '1px solid #222', borderRadius: 8, padding: 20 },
  dTitle:  { fontSize: 11, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8, marginTop: 14 },
  tcRow:   { background: '#111', border: '1px solid #1a1a1a', borderRadius: 5, padding: 8, marginBottom: 6, fontSize: 11 },
  tcUrl:   { color: '#63b3ed', fontFamily: 'monospace', fontSize: 11, marginBottom: 3 },
  tcTech:  { color: '#b794f4', marginBottom: 3 },
  tcExp:   { color: '#888' },
  hypo:    { color: '#f6ad55', fontSize: 11, padding: '3px 0', borderBottom: '1px solid #111' },
  step:    { color: '#ccc', fontSize: 11, padding: '3px 0', borderBottom: '1px solid #111' },
  toolChip:{ display: 'inline-block', background: '#1a1a2d', color: '#63b3ed', border: '1px solid #2a2a4d', borderRadius: 3, padding: '2px 8px', fontSize: 10, marginRight: 6, marginBottom: 4 },
  inact:   { opacity: 0.35 },
}

export default function LoadOutViewer() {
  const [selected, setSelected] = useState<string | null>(null)
  const run = useRunStore((s) => s.run)
  const loadouts = (run as Record<string, unknown>)?.state
    ? ((run as Record<string, unknown>).state as Record<string, unknown>)?.agent_loadouts as Record<string, Record<string, unknown>>
    : null

  if (!loadouts || Object.keys(loadouts).length === 0) {
    return <div style={{ color: '#333', fontSize: 12, textAlign: 'center', padding: 32 }}>LoadOuts not generated yet</div>
  }

  const sel = selected ? loadouts[selected] : null

  return (
    <div style={s.wrap}>
      <div style={s.grid}>
        {Object.entries(loadouts).map(([agentId, lo]) => {
          const active = lo.active as boolean
          const color  = AGENT_COLORS[agentId] || '#ccc'
          return (
            <div
              key={agentId}
              style={{ ...s.card, ...(active ? {} : s.inact), borderColor: selected === agentId ? color + '88' : '#1a1a1a' }}
              onClick={() => setSelected(selected === agentId ? null : agentId)}
            >
              <div style={s.cardH}>
                <span style={{ ...s.name, color }}>{agentId}</span>
                {active
                  ? <span style={{ ...s.badge, background: color + '22', color }}>ACTIVE</span>
                  : <span style={{ ...s.badge, background: '#1a1a1a', color: '#444' }}>INACTIVE</span>}
              </div>
              {active && <div style={s.mission}>{(lo.mission as string || '').slice(0, 100)}{(lo.mission as string || '').length > 100 ? '...' : ''}</div>}
              {!active && <div style={{ ...s.mission, color: '#333' }}>{lo.rationale as string}</div>}
              <div style={s.meta}>
                <span>{(lo.test_cases as unknown[] || []).length} tests</span>
                <span>{(lo.tools as string[] || []).length} tools</span>
                <span>p{lo.priority as number}</span>
              </div>
            </div>
          )
        })}
      </div>

      {sel && selected && (
        <div style={{ ...s.detail, marginTop: 16, borderColor: (AGENT_COLORS[selected] || '#ccc') + '44' }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: AGENT_COLORS[selected] || '#ccc' }}>{selected}</div>

          <div style={s.dTitle}>Mission</div>
          <div style={{ fontSize: 12, color: '#ccc', lineHeight: 1.6 }}>{sel.mission as string}</div>

          {(sel.hypotheses as string[] || []).length > 0 && (
            <>
              <div style={s.dTitle}>Hypotheses ({(sel.hypotheses as string[]).length})</div>
              {(sel.hypotheses as string[]).map((h, i) => (
                <div key={i} style={s.hypo}>▸ {h}</div>
              ))}
            </>
          )}

          {(sel.test_cases as Record<string, unknown>[] || []).length > 0 && (
            <>
              <div style={s.dTitle}>Test Cases ({(sel.test_cases as unknown[]).length})</div>
              {(sel.test_cases as Record<string, unknown>[]).map((tc, i) => (
                <div key={i} style={s.tcRow}>
                  <div style={s.tcUrl}>⬡ {tc.surface as string}</div>
                  <div style={s.tcTech}>technique: {tc.technique as string}</div>
                  <div style={s.tcExp}>{tc.expected as string}</div>
                </div>
              ))}
            </>
          )}

          {(sel.methodology as string[] || []).length > 0 && (
            <>
              <div style={s.dTitle}>Methodology</div>
              {(sel.methodology as string[]).map((step, i) => (
                <div key={i} style={s.step}>{i + 1}. {step}</div>
              ))}
            </>
          )}

          {(sel.tools as string[] || []).length > 0 && (
            <>
              <div style={s.dTitle}>Tools</div>
              {(sel.tools as string[]).map((t, i) => (
                <span key={i} style={s.toolChip}>{t}</span>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}
