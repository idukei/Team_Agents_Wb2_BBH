import { useState } from 'react'
import { useRunStore } from '../stores/runStore'

const SEV_COLOR: Record<string, string> = {
  CRITICAL:        '#fc8181',
  HIGH:            '#f6ad55',
  MEDIUM:          '#f6e05e',
  LOW:             '#68d391',
  INFORMATIONAL:   '#63b3ed',
}

const AGENT_COLOR: Record<string, string> = {
  WebTester:        '#63b3ed',
  AuthProber:       '#f6ad55',
  LogicAnalyst:     '#b794f4',
  CodeInspector:    '#68d391',
  IntegrationScout: '#fc8181',
  InfraProber:      '#76e4f7',
}

const s: Record<string, React.CSSProperties> = {
  wrap:     { display: 'flex', flexDirection: 'column', gap: 6 },
  filters:  { display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' as const },
  filterBtn:(active: boolean, color: string): React.CSSProperties => ({
              background: active ? color + '22' : 'transparent',
              border: `1px solid ${active ? color + '66' : '#222'}`,
              color:   active ? color : '#444',
              borderRadius: 4, padding: '3px 12px', fontSize: 10, cursor: 'pointer',
            }),
  card:     { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 14, cursor: 'pointer' },
  cardHead: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 },
  title:    { fontSize: 12, fontWeight: 600, color: '#e0e0e0', flex: 1, marginRight: 8 },
  sevBadge: (sev: string): React.CSSProperties => ({
              padding: '2px 10px', borderRadius: 3, fontSize: 10, fontWeight: 700,
              background: (SEV_COLOR[sev] || '#ccc') + '22',
              color: SEV_COLOR[sev] || '#ccc',
              border: `1px solid ${(SEV_COLOR[sev] || '#ccc') + '44'}`,
            }),
  meta:     { display: 'flex', gap: 10, fontSize: 10, color: '#555' },
  agentTag: (agent: string): React.CSSProperties => ({
              color: AGENT_COLOR[agent] || '#ccc', fontSize: 10,
            }),
  detail:   { marginTop: 10, borderTop: '1px solid #1a1a1a', paddingTop: 10 },
  url:      { fontSize: 11, color: '#63b3ed', fontFamily: 'monospace', marginBottom: 4 },
  desc:     { fontSize: 11, color: '#999', lineHeight: 1.6, marginBottom: 8 },
  repro:    { fontSize: 10, color: '#666', fontFamily: 'monospace', lineHeight: 1.8 },
  cvss:     { fontSize: 11, fontWeight: 700, fontFamily: 'monospace' },
  evidence: { background: '#0a0a0a', border: '1px solid #111', borderRadius: 4, padding: 8, fontSize: 10, fontFamily: 'monospace', color: '#555', maxHeight: 150, overflow: 'auto', marginTop: 6 },
  noFind:   { color: '#333', fontSize: 12, textAlign: 'center', padding: 24 },
  confBadge:{ fontSize: 10, color: '#68d391', fontFamily: 'monospace' },
  chain:    { display: 'inline-block', background: '#2d1a3a', border: '1px solid #b794f444', color: '#b794f4', borderRadius: 3, padding: '1px 8px', fontSize: 10, marginLeft: 6 },
}

type Finding = Record<string, unknown>

export default function FindingsPanel() {
  const run        = useRunStore((s) => s.run) as Record<string, unknown> | null
  const state      = (run?.state  || {}) as Record<string, unknown>
  const validated  = (state.validated_findings as Finding[] || [])
  const chains     = (state.attack_chains      as Finding[] || [])
  const fps        = (state.false_positives    as Finding[] || [])

  const [filterSev,   setFilterSev]   = useState<string>('ALL')
  const [filterAgent, setFilterAgent] = useState<string>('ALL')
  const [showFPs,     setShowFPs]     = useState(false)
  const [expanded,    setExpanded]    = useState<string | null>(null)

  const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
  const agents     = ['ALL', 'WebTester', 'AuthProber', 'LogicAnalyst', 'CodeInspector', 'IntegrationScout', 'InfraProber']

  const chainIds = new Set(chains.flatMap((c) => (c.finding_ids as string[] || [])))

  const filtered = validated.filter((f) => {
    if (filterSev   !== 'ALL' && f.severity   !== filterSev)   return false
    if (filterAgent !== 'ALL' && f.agent_id   !== filterAgent) return false
    return true
  })

  const sorted = [...filtered].sort((a, b) =>
    (b.cvss_estimate as number || 0) - (a.cvss_estimate as number || 0)
  )

  return (
    <div style={s.wrap}>
      <div style={s.filters}>
        {severities.map((sev) => (
          <button key={sev} style={s.filterBtn(filterSev === sev, SEV_COLOR[sev] || '#ccc')}
            onClick={() => setFilterSev(sev)}>{sev}</button>
        ))}
        <span style={{ color: '#222', alignSelf: 'center' }}>|</span>
        {agents.map((ag) => (
          <button key={ag} style={s.filterBtn(filterAgent === ag, AGENT_COLOR[ag] || '#ccc')}
            onClick={() => setFilterAgent(ag)}>{ag}</button>
        ))}
        <span style={{ color: '#222', alignSelf: 'center' }}>|</span>
        <button style={s.filterBtn(showFPs, '#fc8181')}
          onClick={() => setShowFPs(!showFPs)}>
          FP ({fps.length})
        </button>
      </div>

      {chains.length > 0 && (
        <div style={{ background: '#140f1f', border: '1px solid #b794f422', borderRadius: 8, padding: 12, marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: '#b794f4', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
            ⛓ Attack Chains ({chains.length})
          </div>
          {chains.map((chain, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <span style={{ fontSize: 12, color: '#e0e0e0', fontWeight: 600 }}>{chain.title as string}</span>
              <span style={{ fontSize: 10, color: '#b794f4', marginLeft: 8 }}>CVSS {chain.cvss_composed as number}</span>
              <span style={{ fontSize: 10, color: '#555', marginLeft: 8 }}>{chain.narrative as string}</span>
            </div>
          ))}
        </div>
      )}

      {(showFPs ? fps : sorted).length === 0 && (
        <div style={s.noFind}>
          {showFPs ? 'No false positives' : 'No validated findings yet'}
        </div>
      )}

      {(showFPs ? fps : sorted).map((f, i) => {
        const id       = f.id as string || `${i}`
        const isOpen   = expanded === id
        const isChained = chainIds.has(id)
        const sev      = f.severity   as string || 'INFORMATIONAL'
        const agentId  = f.agent_id   as string || ''
        const cvss     = f.cvss_estimate as number || 0

        return (
          <div key={id} style={{ ...s.card, borderColor: showFPs ? '#3a1a1a' : (SEV_COLOR[sev] + '33') }}
               onClick={() => setExpanded(isOpen ? null : id)}>
            <div style={s.cardHead}>
              <span style={s.title}>{f.title as string}</span>
              {isChained && <span style={s.chain}>⛓ chain</span>}
              <span style={s.sevBadge(sev)}>{sev}</span>
            </div>
            <div style={s.meta}>
              <span style={s.agentTag(agentId)}>{agentId}</span>
              <span style={s.cvss}>{cvss.toFixed(1)}</span>
              {!showFPs && <span style={s.confBadge}>conf: {((f.confidence_score as number || 0) * 100).toFixed(0)}%</span>}
              {showFPs  && <span style={{ color: '#fc8181', fontSize: 10 }}>{f.rejection_reason as string}</span>}
            </div>

            {isOpen && (
              <div style={s.detail}>
                <div style={s.url}>{f.url as string}</div>
                <div style={s.desc}>{f.description as string}</div>
                {(f.reproduction_steps as string[] || []).length > 0 && (
                  <div style={s.repro}>
                    {(f.reproduction_steps as string[]).map((step, j) => (
                      <div key={j}>{step}</div>
                    ))}
                  </div>
                )}
                {f.payload && (
                  <div style={s.evidence}>payload: {f.payload as string}</div>
                )}
                {f.response_diff && (
                  <div style={s.evidence}>{JSON.stringify(f.response_diff, null, 2)}</div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
