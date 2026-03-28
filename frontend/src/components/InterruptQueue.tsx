import { useRunStore } from '../stores/runStore'
import InterruptCard from './InterruptCard'
import { useHITL } from '../hooks/useHITL'

const s: Record<string, React.CSSProperties> = {
  wrap:   { },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 },
  title:  { fontSize: 11, color: '#f6ad55', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700 },
  count:  { background: '#f6ad5522', border: '1px solid #f6ad5544', color: '#f6ad55', borderRadius: 12, padding: '1px 8px', fontSize: 11, fontWeight: 700 },
  btnAll: { background: 'transparent', border: '1px solid #333', color: '#555', borderRadius: 5, padding: '4px 12px', fontSize: 11, cursor: 'pointer' },
  empty:  { color: '#333', fontSize: 12, textAlign: 'center', padding: 24 },
}

export default function InterruptQueue() {
  const interrupts      = useRunStore((s) => s.pendingInterrupts)
  const clearInterrupts = useRunStore((s) => s.clearInterrupts)
  const { respondToInterrupt } = useHITL()

  if (!interrupts || interrupts.length === 0) {
    return <div style={s.empty}>No pending interrupts</div>
  }

  async function approveAll() {
    for (const interrupt of interrupts) {
      try {
        await respondToInterrupt(interrupt.interrupt_type, { action: 'approve' })
      } catch { }
    }
    clearInterrupts()
  }

  return (
    <div style={s.wrap}>
      <div style={s.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={s.title}>⚠ HITL Queue</span>
          <span style={s.count}>{interrupts.length}</span>
        </div>
        {interrupts.length > 1 && (
          <button style={s.btnAll} onClick={approveAll}>Approve All</button>
        )}
      </div>
      {interrupts.map((interrupt, i) => (
        <InterruptCard
          key={`${interrupt.interrupt_type}-${i}`}
          interrupt={interrupt as Parameters<typeof InterruptCard>[0]['interrupt']}
          onResolved={clearInterrupts}
        />
      ))}
    </div>
  )
}
