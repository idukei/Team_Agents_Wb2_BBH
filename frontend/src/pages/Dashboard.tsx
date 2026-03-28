import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useRunStore } from '../stores/runStore'
import { useSSEStream } from '../hooks/useSSEStream'
import { getRun } from '../api/client'
import NewRunForm from '../components/NewRunForm'
import PhaseTimeline from '../components/PhaseTimeline'
import EventLog from '../components/EventLog'
import SurfaceMapViewer from '../components/SurfaceMapViewer'
import TargetContextViewer from '../components/TargetContextViewer'
import LoadOutViewer from '../components/LoadOutViewer'
import StrategyViewer from '../components/StrategyViewer'
import SwarmMonitor from '../components/SwarmMonitor'
import FindingsPanel from '../components/FindingsPanel'
import InterruptQueue from '../components/InterruptQueue'
import CheckpointBrowser from '../components/CheckpointBrowser'
import StateEditor from '../components/StateEditor'

type Tab =
  | 'surface' | 'intelligence' | 'strategy'
  | 'loadouts' | 'swarm' | 'findings'
  | 'events' | 'timetravel'

const TABS: { id: Tab; label: string; badge?: (run: Record<string,unknown>) => string }[] = [
  { id: 'surface',      label: 'Surface Map'  },
  { id: 'intelligence', label: 'Intelligence' },
  { id: 'strategy',     label: 'Strategy'     },
  { id: 'loadouts',     label: 'LoadOuts'     },
  { id: 'swarm',        label: 'Swarm'        },
  {
    id: 'findings',
    label: 'Findings',
    badge: (run) => {
      const n = ((run?.state as Record<string,unknown>)?.validated_findings as unknown[] || []).length
      return n > 0 ? String(n) : ''
    },
  },
  { id: 'events',     label: 'Events'      },
  { id: 'timetravel', label: 'Time Travel' },
]

const s: Record<string, React.CSSProperties> = {
  root:    { minHeight: '100vh', background: '#0a0a0a', color: '#e0e0e0', fontFamily: 'system-ui, sans-serif' },
  hdr:     { background: '#111', borderBottom: '1px solid #222', padding: '12px 24px', display: 'flex', alignItems: 'center', gap: 12 },
  logo:    { fontSize: 20, fontWeight: 800, color: '#e53e3e', letterSpacing: 1 },
  tag:     { fontSize: 10, color: '#555', background: '#1a1a1a', padding: '2px 8px', borderRadius: 3, fontFamily: 'monospace' },
  main:    { padding: 24, maxWidth: 1400, margin: '0 auto' },
  card:    { background: '#111', border: '1px solid #222', borderRadius: 8, padding: 20, marginBottom: 18 },
  tabs:    { display: 'flex', gap: 0, borderBottom: '1px solid #222', marginBottom: 18 },
  tab:     { padding: '8px 16px', fontSize: 11, cursor: 'pointer', border: 'none', background: 'transparent', textTransform: 'uppercase' as const, letterSpacing: 1, position: 'relative' as const },
  tabBadge:{ position: 'absolute' as const, top: 4, right: 4, background: '#e53e3e', color: '#fff', borderRadius: 8, fontSize: 9, padding: '0 4px', fontWeight: 700 },
  badge:   { display: 'inline-block', background: '#1a1a1a', border: '1px solid #333', borderRadius: 4, padding: '2px 10px', fontSize: 11, fontFamily: 'monospace', color: '#48bb78' },
  dot:     { display: 'inline-block', width: 8, height: 8, borderRadius: '50%', marginRight: 6 },
  statsRow:{ display: 'flex', gap: 12, marginBottom: 16 },
  stat:    { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 6, padding: '10px 16px', flex: 1 },
  statVal: { fontSize: 22, fontWeight: 800, fontFamily: 'monospace' },
  statLbl: { fontSize: 10, color: '#555', textTransform: 'uppercase' as const, letterSpacing: 1, marginTop: 2 },
  btnSm:   { background: 'transparent', border: '1px solid #333', color: '#555', borderRadius: 5, padding: '5px 12px', fontSize: 11, cursor: 'pointer', marginTop: 12 },
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#fc8181', HIGH: '#f6ad55', MEDIUM: '#f6e05e', LOW: '#68d391',
}

export default function Dashboard() {
  const { threadId: paramThreadId } = useParams()
  const store     = useRunStore()
  const [tab, setTab] = useState<Tab>('events')

  useEffect(() => {
    if (paramThreadId && !store.threadId) store.setThreadId(paramThreadId)
  }, [paramThreadId])

  useEffect(() => {
    if (store.threadId) {
      getRun(store.threadId).then((run) => {
        store.setRun(run as Record<string, unknown>)
        if (run.phase) store.setPhase(run.phase)
      }).catch(() => {})
    }
  }, [store.threadId])

  useSSEStream(store.threadId)

  const phase    = store.phase || 'BRIEF'
  const hasHITL  = store.pendingInterrupts.length > 0
  const run      = store.run   as Record<string,unknown> | null
  const stateObj = (run?.state || {}) as Record<string,unknown>

  const validated = (stateObj.validated_findings as unknown[] || []).length
  const chains    = (stateObj.attack_chains      as unknown[] || []).length
  const fps       = (stateObj.false_positives    as unknown[] || []).length
  const endpoints = ((stateObj.surface_inventory as Record<string,unknown> || {}).endpoints as unknown[] || []).length

  const criticals = ((stateObj.validated_findings as Record<string,unknown>[] || [])
    .filter(f => f.severity === 'CRITICAL')).length

  return (
    <div style={s.root}>
      <header style={s.hdr}>
        <span style={s.logo}>🔴 BOUNTYMIND</span>
        <span style={s.tag}>Fixed Team · Dynamic LoadOut · v4.0</span>
        {store.threadId && (
          <span style={{ ...s.tag, color: '#444' }}>{store.threadId.slice(0, 16)}…</span>
        )}
        <span style={{ ...s.badge, marginLeft: 'auto' }}>{phase}</span>
        {store.isStreaming && (
          <span style={{ ...s.tag, color: '#48bb78', borderColor: '#48bb7844' }}>
            <span style={{ ...s.dot, background: '#48bb78' }} />LIVE
          </span>
        )}
        {hasHITL && (
          <span style={{ ...s.tag, color: '#f6ad55', borderColor: '#f6ad5544' }}>
            ⚠ {store.pendingInterrupts.length} HITL
          </span>
        )}
      </header>

      <main style={s.main}>
        {!store.threadId ? (
          <div style={s.card}>
            <div style={{ fontSize: 11, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 14 }}>
              New Run
            </div>
            <NewRunForm />
          </div>
        ) : (
          <>
            <div style={s.card}>
              <PhaseTimeline />
            </div>

            <div style={s.statsRow}>
              {[
                { val: endpoints,  lbl: 'Endpoints',  color: '#63b3ed' },
                { val: validated,  lbl: 'Findings',   color: '#68d391' },
                { val: criticals,  lbl: 'Criticals',  color: '#fc8181' },
                { val: chains,     lbl: 'Chains',     color: '#b794f4' },
                { val: fps,        lbl: 'False Pos',  color: '#555'    },
              ].map(({ val, lbl, color }) => (
                <div key={lbl} style={s.stat}>
                  <div style={{ ...s.statVal, color }}>{val}</div>
                  <div style={s.statLbl}>{lbl}</div>
                </div>
              ))}
            </div>

            {hasHITL && (
              <div style={{ ...s.card, borderColor: '#f6ad5544' }}>
                <InterruptQueue />
              </div>
            )}

            <div style={s.tabs}>
              {TABS.map(({ id, label, badge }) => {
                const badgeVal = badge && run ? badge(run) : ''
                return (
                  <button key={id} style={{
                    ...s.tab,
                    color:        tab === id ? '#e53e3e' : '#555',
                    borderBottom: tab === id ? '2px solid #e53e3e' : '2px solid transparent',
                  }} onClick={() => setTab(id)}>
                    {label}
                    {badgeVal && <span style={s.tabBadge}>{badgeVal}</span>}
                  </button>
                )
              })}
            </div>

            <div style={s.card}>
              {tab === 'surface'      && <SurfaceMapViewer />}
              {tab === 'intelligence' && <TargetContextViewer />}
              {tab === 'strategy'     && <StrategyViewer />}
              {tab === 'loadouts'     && <LoadOutViewer />}
              {tab === 'swarm'        && <SwarmMonitor />}
              {tab === 'findings'     && <FindingsPanel />}
              {tab === 'events'       && <EventLog />}
              {tab === 'timetravel'   && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <CheckpointBrowser />
                  <StateEditor />
                </div>
              )}
            </div>

            <button style={s.btnSm} onClick={() => store.reset()}>← New Run</button>
          </>
        )}
      </main>
    </div>
  )
}
