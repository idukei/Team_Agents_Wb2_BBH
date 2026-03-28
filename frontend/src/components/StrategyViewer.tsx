import { useRunStore } from '../stores/runStore'

const PRIORITY_COLOR = (p: number) =>
  p === 1 ? '#fc8181' : p === 2 ? '#f6ad55' : '#68d391'

const s: Record<string, React.CSSProperties> = {
  wrap:      { display: 'flex', flexDirection: 'column', gap: 14 },
  section:   { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 6, padding: 14 },
  title:     { fontSize: 10, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 },
  narrative: { fontSize: 12, color: '#ccc', lineHeight: 1.7 },
  areaRow:   { display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid #111', alignItems: 'flex-start' },
  areaPrio:  (p: number): React.CSSProperties => ({
    minWidth: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center',
    justifyContent: 'center', fontSize: 10, fontWeight: 700, flexShrink: 0,
    background: PRIORITY_COLOR(p) + '22', color: PRIORITY_COLOR(p), border: `1px solid ${PRIORITY_COLOR(p)}44`,
  }),
  areaName:  { fontSize: 12, color: '#ccc', fontWeight: 600 },
  areaRat:   { fontSize: 11, color: '#888', marginTop: 2 },
  seqRow:    { display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid #111', alignItems: 'center' },
  seqNum:    { minWidth: 24, height: 24, background: '#1a1a2d', border: '1px solid #2a2a4d', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: '#63b3ed', flexShrink: 0 },
  seqAgents: { display: 'flex', gap: 4, flexWrap: 'wrap' as const },
  agChip:    { background: '#1a2d1a', color: '#68d391', border: '1px solid #2a4d2a', borderRadius: 3, padding: '1px 8px', fontSize: 10 },
  hypoRow:   { padding: '5px 0', borderBottom: '1px solid #111', fontSize: 11, color: '#888' },
  hypoText:  { color: '#ccc' },
  hypoAgent: { color: '#b794f4', fontSize: 10, marginLeft: 6 },
  empty:     { color: '#333', fontSize: 12, textAlign: 'center', padding: 24 },
}

export default function StrategyViewer() {
  const run = useRunStore((s) => s.run)
  const strategy = (run as Record<string, unknown>)?.state
    ? ((run as Record<string, unknown>).state as Record<string, unknown>)?.attack_strategy as Record<string, unknown>
    : null

  if (!strategy || !strategy.narrative) {
    return <div style={s.empty}>Strategy not generated yet</div>
  }

  const threatAreas   = (strategy.threat_areas       as Record<string, unknown>[] || [])
  const sequence      = (strategy.testing_sequence   as Record<string, unknown>[] || [])
  const hypotheses    = (strategy.global_hypotheses  as Record<string, unknown>[] || [])
  const collaboration = strategy.collaboration_plan  as Record<string, unknown> | undefined

  return (
    <div style={s.wrap}>
      <div style={s.section}>
        <div style={s.title}>Narrative</div>
        <div style={s.narrative}>{strategy.narrative as string}</div>
      </div>

      {threatAreas.length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Threat Areas ({threatAreas.length})</div>
          {threatAreas.sort((a, b) => (a.priority as number) - (b.priority as number)).map((area, i) => (
            <div key={i} style={s.areaRow}>
              <div style={s.areaPrio(area.priority as number)}>{area.priority as number}</div>
              <div>
                <div style={s.areaName}>{area.area as string}</div>
                <div style={s.areaRat}>{area.rationale as string}</div>
                {(area.surfaces_involved as string[] || []).length > 0 && (
                  <div style={{ fontSize: 10, color: '#444', marginTop: 4 }}>
                    {(area.surfaces_involved as string[]).join(' · ')}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {sequence.length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Testing Sequence</div>
          {sequence.map((step, i) => (
            <div key={i} style={s.seqRow}>
              <div style={s.seqNum}>{step.step as number}</div>
              <div>
                <div style={s.seqAgents}>
                  {(step.agents as string[] || []).map((a, j) => (
                    <span key={j} style={s.agChip}>{a}</span>
                  ))}
                </div>
                <div style={{ fontSize: 11, color: '#888', marginTop: 3 }}>{step.rationale as string}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {hypotheses.length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Global Hypotheses ({hypotheses.length})</div>
          {hypotheses.sort((a, b) => (a.priority as number) - (b.priority as number)).map((h, i) => (
            <div key={i} style={s.hypoRow}>
              <span style={s.hypoText}>{h.hypothesis as string}</span>
              <span style={s.hypoAgent}>→ {h.assigned_agent as string}</span>
            </div>
          ))}
        </div>
      )}

      {collaboration && (collaboration.channels as string[] || []).length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Collaboration Channels</div>
          <div>
            {(collaboration.channels as string[]).map((c, i) => (
              <span key={i} style={{ display: 'inline-block', background: '#1a1a1a', border: '1px solid #222', borderRadius: 3, padding: '2px 8px', fontSize: 10, color: '#63b3ed', marginRight: 6 }}>
                {c}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
