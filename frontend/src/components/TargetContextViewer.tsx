import { useRunStore } from '../stores/runStore'

const s: Record<string, React.CSSProperties> = {
  wrap:    { display: 'flex', flexDirection: 'column' as const, gap: 12 },
  section: { background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 6, padding: 14 },
  title:   { fontSize: 10, color: '#555', textTransform: 'uppercase' as const, letterSpacing: 1, marginBottom: 10 },
  chip:    (color: string): React.CSSProperties => ({
             display: 'inline-block', background: color + '22', color,
             border: `1px solid ${color}44`, borderRadius: 4, padding: '3px 10px',
             fontSize: 11, marginRight: 6, marginBottom: 4,
           }),
  item:    { padding: '5px 0', borderBottom: '1px solid #111', fontSize: 11 },
  empty:   { color: '#333', fontSize: 12, textAlign: 'center' as const, padding: 24 },
  cvss:    (score: number): React.CSSProperties => ({
             color: score >= 9 ? '#fc8181' : score >= 7 ? '#f6ad55' : score >= 4 ? '#f6e05e' : '#68d391',
             fontWeight: 700, fontFamily: 'monospace',
           }),
}

export default function TargetContextViewer() {
  const run = useRunStore((s) => s.run) as Record<string, unknown> | null
  const ctx = ((run?.state as Record<string,unknown> || {}).target_context || {}) as Record<string, unknown>

  if (!ctx.tech_fingerprint) {
    return <div style={s.empty}>Intelligence not gathered yet</div>
  }

  return (
    <div style={s.wrap}>
      <div style={s.section}>
        <div style={s.title}>Stack & Sector</div>
        <span style={s.chip('#63b3ed')}>{ctx.tech_fingerprint as string}</span>
        <span style={s.chip('#b794f4')}>{ctx.sector as string}</span>
      </div>

      {(ctx.cve_list as Record<string,unknown>[] || []).length > 0 && (
        <div style={s.section}>
          <div style={s.title}>CVEs ({(ctx.cve_list as unknown[]).length})</div>
          {(ctx.cve_list as Record<string,unknown>[]).slice(0, 5).map((cve, i) => (
            <div key={i} style={s.item}>
              <span style={{ color: '#fc8181', fontFamily: 'monospace', marginRight: 8 }}>{cve.id as string}</span>
              <span style={s.cvss(cve.cvss_score as number || 0)}>{(cve.cvss_score as number || 0).toFixed(1)}</span>
              <span style={{ color: '#888', marginLeft: 8 }}>{(cve.description as string || '').slice(0, 120)}</span>
            </div>
          ))}
        </div>
      )}

      {(ctx.proven_techniques as Record<string,unknown>[] || []).length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Proven Techniques ({(ctx.proven_techniques as unknown[]).length})</div>
          {(ctx.proven_techniques as Record<string,unknown>[]).map((t, i) => (
            <div key={i} style={s.item}>
              <span style={{ color: '#68d391', fontFamily: 'monospace', marginRight: 8 }}>{t.technique as string}</span>
              <span style={{ color: '#888' }}>{t.description as string}</span>
            </div>
          ))}
        </div>
      )}

      {(ctx.sector_patterns as string[] || []).length > 0 && (
        <div style={s.section}>
          <div style={s.title}>Sector Patterns</div>
          {(ctx.sector_patterns as string[]).map((p, i) => (
            <div key={i} style={{ ...s.item, color: '#f6ad55' }}>▸ {p}</div>
          ))}
        </div>
      )}

      {(ctx.interesting_observations as string[] || []).length > 0 && (
        <div style={s.section}>
          <div style={s.title}>OSINT Observations</div>
          {(ctx.interesting_observations as string[]).map((obs, i) => (
            <div key={i} style={{ ...s.item, color: '#63b3ed' }}>⬡ {obs}</div>
          ))}
        </div>
      )}
    </div>
  )
}
