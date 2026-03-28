import { useRunStore } from '../stores/runStore'

const AGENT_COLORS: Record<string, string> = {
  WebTester:        '#63b3ed',
  AuthProber:       '#f6ad55',
  LogicAnalyst:     '#b794f4',
  CodeInspector:    '#68d391',
  IntegrationScout: '#fc8181',
  InfraProber:      '#76e4f7',
}

const AGENT_ROLES: Record<string, string> = {
  WebTester:        'Forms · Endpoints · XSS · CSRF',
  AuthProber:       'Auth · Reset · JWT · OAuth',
  LogicAnalyst:     'IDOR · Mass Assignment · Logic',
  CodeInspector:    'JS Bundles · Secrets · Source Maps',
  IntegrationScout: 'SSRF · CORS · Webhooks · Redirects',
  InfraProber:      'Ports · Files · Cloud · Services',
}

const s: Record<string, React.CSSProperties> = {
  wrap:      { display: 'flex', flexDirection: 'column', gap: 8 },
  agent:     { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 14 },
  header:    { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  name:      { fontSize: 13, fontWeight: 700 },
  role:      { fontSize: 10, color: '#444', marginBottom: 8 },
  statusRow: { display: 'flex', gap: 12, alignItems: 'center' },
  badge:     (active: boolean, color: string): React.CSSProperties => ({
               display: 'inline-block', padding: '2px 10px', borderRadius: 3, fontSize: 10,
               fontWeight: 700, background: active ? color + '22' : '#1a1a1a',
               color: active ? color : '#444', border: `1px solid ${active ? color + '44' : '#222'}`,
             }),
  progWrap:  { flex: 1, background: '#111', borderRadius: 4, height: 4, overflow: 'hidden' },
  progBar:   (pct: number, color: string): React.CSSProperties => ({
               height: '100%', background: color, width: `${pct}%`,
               transition: 'width 0.5s ease', borderRadius: 4,
             }),
  findings:  { fontSize: 10, color: '#555', fontFamily: 'monospace' },
  phase:     { fontSize: 10, color: '#444', fontFamily: 'monospace' },
  empty:     { color: '#333', fontSize: 12, textAlign: 'center', padding: 24 },
}

export default function SwarmMonitor() {
  const agentStatus = useRunStore((s) => s.agentStatus)
  const loadouts    = useRunStore((s) => s.agentLoadouts)
  const phase       = useRunStore((s) => s.phase)

  const allAgents = ['WebTester', 'AuthProber', 'LogicAnalyst', 'CodeInspector', 'IntegrationScout', 'InfraProber']
  const inAttackPhase = phase === 'ATTACK'

  if (!inAttackPhase && Object.keys(agentStatus).length === 0) {
    return <div style={s.empty}>Swarm not active — waiting for ATTACK phase</div>
  }

  return (
    <div style={s.wrap}>
      {allAgents.map((agentId) => {
        const color   = AGENT_COLORS[agentId] || '#ccc'
        const role    = AGENT_ROLES[agentId]  || ''
        const status  = agentStatus[agentId]  || {}
        const loadout = (loadouts as Record<string, Record<string, unknown>>)[agentId] || {}

        const active      = status.active ?? loadout.active ?? false
        const iteration   = (status.iteration as number)    || 0
        const maxIter     = (loadout.max_iterations as number) || 25
        const findingsN   = (status.findings_count as number) || 0
        const curPhase    = (status.phase as string)          || (active ? 'waiting' : 'inactive')
        const pct         = maxIter > 0 ? Math.min((iteration / maxIter) * 100, 100) : 0

        return (
          <div key={agentId} style={{ ...s.agent, borderColor: active ? color + '33' : '#1a1a1a' }}>
            <div style={s.header}>
              <span style={{ ...s.name, color }}>{agentId}</span>
              <span style={s.badge(active, color)}>
                {active ? (curPhase === 'waiting' ? 'WAITING' : 'ACTIVE') : 'INACTIVE'}
              </span>
            </div>
            <div style={s.role}>{role}</div>
            <div style={s.statusRow}>
              <span style={s.findings}>{findingsN} findings</span>
              <div style={s.progWrap}>
                <div style={s.progBar(pct, color)} />
              </div>
              <span style={{ ...s.findings, minWidth: 60 }}>{iteration}/{maxIter} iter</span>
              <span style={s.phase}>{curPhase}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
