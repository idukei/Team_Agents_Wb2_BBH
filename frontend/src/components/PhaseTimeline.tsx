import { useRunStore } from '../stores/runStore'

const PHASES = [
  { id: 'BRIEF',        label: 'Brief'       },
  { id: 'RECON',        label: 'Recon'       },
  { id: 'INTELLIGENCE', label: 'Intel'       },
  { id: 'STRATEGY',     label: 'Strategy'    },
  { id: 'ATTACK',       label: 'Attack'      },
  { id: 'SYNTHESIS',    label: 'Synthesis'   },
  { id: 'VALIDATION',   label: 'Validation'  },
  { id: 'REVIEW',       label: 'HITL Review' },
  { id: 'REPORT',       label: 'Report'      },
]

const PHASE_ORDER = PHASES.map(p => p.id)

const s: Record<string, React.CSSProperties> = {
  wrap:   { display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto' as const, paddingBottom: 4 },
  phase:  (active: boolean, done: boolean): React.CSSProperties => ({
            display: 'flex', alignItems: 'center', gap: 0,
          }),
  dot:    (active: boolean, done: boolean): React.CSSProperties => ({
            width: 28, height: 28, borderRadius: '50%', display: 'flex',
            alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700,
            flexShrink: 0,
            background: active ? '#e53e3e'
                       : done  ? '#2d4a2d'
                       :         '#1a1a1a',
            color:      active ? '#fff'
                       : done  ? '#68d391'
                       :         '#333',
            border:     `2px solid ${active ? '#e53e3e' : done ? '#68d39144' : '#222'}`,
            transition: 'all 0.3s',
          }),
  line:   (done: boolean): React.CSSProperties => ({
            width: 32, height: 2, flexShrink: 0,
            background: done ? '#2d4a2d' : '#1a1a1a',
            transition: 'background 0.3s',
          }),
  label:  (active: boolean, done: boolean): React.CSSProperties => ({
            fontSize: 9, textTransform: 'uppercase' as const, letterSpacing: 0.5,
            color:   active ? '#e53e3e' : done ? '#68d391' : '#333',
            marginTop: 4, textAlign: 'center' as const,
          }),
  col:    { display: 'flex', flexDirection: 'column' as const, alignItems: 'center' as const },
}

export default function PhaseTimeline() {
  const phase = useRunStore((s) => s.phase) || 'BRIEF'
  const idx   = PHASE_ORDER.indexOf(phase)

  return (
    <div style={s.wrap}>
      {PHASES.map((p, i) => {
        const active = p.id === phase
        const done   = i < idx
        return (
          <div key={p.id} style={s.phase(active, done)}>
            <div style={s.col}>
              <div style={s.dot(active, done)}>{done ? '✓' : i + 1}</div>
              <div style={s.label(active, done)}>{p.label}</div>
            </div>
            {i < PHASES.length - 1 && <div style={s.line(done)} />}
          </div>
        )
      })}
    </div>
  )
}
