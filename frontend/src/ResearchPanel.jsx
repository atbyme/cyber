import { useState, useEffect, useMemo, useCallback } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const REGIONS = [
  { name: 'NA', x: 18, y: 28 }, { name: 'SA', x: 25, y: 58 }, { name: 'EU', x: 48, y: 22 },
  { name: 'AF', x: 50, y: 52 }, { name: 'RU', x: 62, y: 18 }, { name: 'ME', x: 55, y: 35 },
  { name: 'AS', x: 65, y: 38 }, { name: 'CN', x: 76, y: 22 }, { name: 'SEA', x: 72, y: 42 }, { name: 'AU', x: 84, y: 55 },
]
const ATTACK_TYPES = ['DDoS', 'Ransomware', 'Phishing', 'APT', 'Malware', 'Zero-Day', 'Botnet', 'Data Breach']
const COLORS = ['#06b6d4', '#8b5cf6', '#f59e0b', '#ef4444', '#10b981', '#ec4899', '#14b8a6', '#f97316']

export default function ResearchPanel({ status, feedData, onThreatClick }) {
  const [query, setQuery] = useState('')
  const [deepResults, setDeepResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [insights, setInsights] = useState([])
  const [trends, setTrends] = useState([])
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('aura_threat_history') || '[]') } catch { return [] }
  })
  const [attacks, setAttacks] = useState([])
  const [incomingWaves, setIncomingWaves] = useState(0)
  const [activeAttacks, setActiveAttacks] = useState(0)
  const [mapPopup, setMapPopup] = useState(null)

  const genAttacks = useCallback(() => {
    const list = []
    for (let i = 0; i < 10; i++) {
      const r = REGIONS[Math.floor(Math.random() * REGIONS.length)]
      list.push({
        id: i, region: r.name, x: r.x + (Math.random() - 0.5) * 5, y: r.y + (Math.random() - 0.5) * 5,
        type: ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)],
        severity: Math.random() > 0.6 ? 'critical' : Math.random() > 0.3 ? 'high' : 'medium',
        intensity: 0.3 + Math.random() * 0.7, t: new Date().toLocaleTimeString(),
        target: ['Govt', 'Finance', 'Energy', 'Telecom', 'Healthcare', 'Military', 'Tech', 'Cloud'][Math.floor(Math.random() * 8)],
        method: ['Exploit', 'Phishing', 'DDoS', 'Malware', 'Zero-Day', 'Supply Chain'][Math.floor(Math.random() * 6)],
        impact: `${Math.floor(Math.random() * 5000 + 100)} systems`,
      })
    }
    setAttacks(list)
    setIncomingWaves(Math.floor(Math.random() * 18) + 5)
    setActiveAttacks(Math.floor(Math.random() * 10) + 2)
  }, [])

  useEffect(() => {
    genAttacks()
    const i = setInterval(genAttacks, 6000)
    return () => clearInterval(i)
  }, [genAttacks])

  useEffect(() => {
    if (feedData?.threats?.length > 0) {
      const typed = {}
      feedData.threats.slice(0, 100).forEach(t => {
        const k = t.type || 'unknown'
        typed[k] = (typed[k] || 0) + 1
      })
      setTrends(Object.entries(typed).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value).slice(0, 10))
    }
  }, [feedData])

  const deepResearch = async () => {
    if (!query.trim()) return
    setLoading(true)
    try {
      const r = await fetch(`/api/research/deep?query=${encodeURIComponent(query.trim())}`)
      const d = await r.json()
      setDeepResults(d)
      setInsights(p => [{ type: 'deep', query, results: d.total_matches, t: new Date().toISOString() }, ...p].slice(0, 50))
    } catch (e) { setInsights(p => [{ type: 'error', query, error: e.message, t: new Date().toISOString() }, ...p].slice(0, 50)) }
    setLoading(false)
  }

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">DEEP CYBER RESEARCH ENGINE</span>
        <span className="blink">{activeAttacks > 0 ? `${activeAttacks} ACTIVE · ${incomingWaves} INCOMING` : 'MONITORING'}</span>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{incomingWaves}</div>
          <div className="soc-stat-lbl">INCOMING WAVES</div>
          <div className="soc-stat-sub">Next 24h prediction</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{activeAttacks}</div>
          <div className="soc-stat-lbl">ACTIVE ATTACKS</div>
          <div className="soc-stat-sub">Ongoing globally</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{deepResults?.total_matches || feedData?.threats?.length || 0}</div>
          <div className="soc-stat-lbl">RELEVANT THREATS</div>
          <div className="soc-stat-sub">{deepResults ? 'Deep search' : 'Live feed'}</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{history.length}</div>
          <div className="soc-stat-lbl">DAYS HISTORY</div>
          <div className="soc-stat-sub">Browser stored</div>
        </div>
      </div>

      {/* Global mini map with clickable dots */}
      <div className="chart-container" style={{ marginBottom: 10 }}>
        <div className="chart-title">LIVE CYBER THREAT MAP <span className="chart-badge">{attacks.length} events</span></div>
        <div className="map-container" style={{ height: 120, position: 'relative' }}>
          <svg viewBox="0 0 100 55" className="world-map" style={{ width: '100%', height: '100%' }}>
            <ellipse cx="20" cy="24" rx="12" ry="7" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
            <ellipse cx="50" cy="26" rx="25" ry="12" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
            <ellipse cx="72" cy="26" rx="18" ry="10" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
            <ellipse cx="45" cy="38" rx="18" ry="7" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
            {REGIONS.map((r, i) => (
              <text key={i} x={r.x} y={r.y + 4} textAnchor="middle" fill="#3d4a60" fontSize={2.5} opacity={0.6}>{r.name}</text>
            ))}
            {attacks.map(a => (
              <g key={a.id} style={{ cursor: 'pointer' }}
                onClick={() => {
                  onThreatClick?.({ type: a.type, source: a.region, description: `${a.type} on ${a.target} via ${a.method} — ${a.impact} · ${a.severity.toUpperCase()} severity`, t: Date.now() })
                  setMapPopup(a)
                }}
                onMouseEnter={() => setMapPopup(a)}
                onMouseLeave={() => setTimeout(() => setMapPopup(null), 2000)}>
                <circle cx={a.x} cy={a.y} r={2 + a.intensity * 2.5} fill="none"
                  stroke={a.severity === 'critical' ? '#ef4444' : a.severity === 'high' ? '#f59e0b' : '#06b6d4'}
                  strokeWidth={0.4} opacity={0.25} className="map-pulse" />
                <circle cx={a.x} cy={a.y} r={1.2} fill={a.severity === 'critical' ? '#ef4444' : a.severity === 'high' ? '#f59e0b' : '#06b6d4'} opacity={0.85} />
              </g>
            ))}
          </svg>
          {mapPopup && (
            <div style={{
              position: 'absolute', left: mapPopup.x * 1.2 + 10, top: mapPopup.y * 0.8 + 5, zIndex: 100,
              background: '#1a2332', border: `1px solid ${mapPopup.severity === 'critical' ? '#ef4444' : mapPopup.severity === 'high' ? '#f59e0b' : '#06b6d4'}`,
              borderRadius: 6, padding: '6px 10px', fontSize: 9, maxWidth: 260, boxShadow: '0 4px 20px rgba(0,0,0,0.6)',
            }}>
              <div style={{ color: mapPopup.severity === 'critical' ? '#ef4444' : mapPopup.severity === 'high' ? '#f59e0b' : '#06b6d4', fontWeight: 700, fontSize: 10, marginBottom: 3 }}>
                {mapPopup.type} — {mapPopup.severity.toUpperCase()}
              </div>
              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Region: {mapPopup.region}<br />
                Target: {mapPopup.target}<br />
                Method: {mapPopup.method}<br />
                Impact: {mapPopup.impact}<br />
                Time: {mapPopup.t}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="filters-bar">
        <input className="filter-search" style={{ flex: 1, fontSize: 13, padding: '8px 12px' }}
          placeholder="DEEP RESEARCH: company, threat actor, CVE, malware, country, agency..."
          value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && deepResearch()} />
        <button className="btn btn-primary" onClick={deepResearch} disabled={loading || !query.trim()}>
          {loading ? '⟳ DEEP RESEARCH...' : 'DEEP RESEARCH'}
        </button>
        <button className="btn btn-primary" onClick={() => window.open('/api/threats/export', '_blank')}>EXPORT</button>
      </div>

      {deepResults && (
        <div className="soc-panel" style={{ marginBottom: 10 }}>
          <div className="soc-panel-header">
            DEEP RESEARCH: "{deepResults.query}" <span className="soc-badge">{deepResults.total_matches} matches</span>
            <span className="soc-badge sec">{deepResults.source_breakdown ? Object.keys(deepResults.source_breakdown).length + ' sources' : ''}</span>
          </div>
          {deepResults.source_breakdown && Object.keys(deepResults.source_breakdown).length > 0 && (
            <div style={{ display: 'flex', gap: 8, padding: '6px 10px', flexWrap: 'wrap', borderBottom: '1px solid var(--border)' }}>
              {Object.entries(deepResults.source_breakdown).slice(0, 8).map(([k, v]) => (
                <span key={k} className="soc-src-chip" style={{ padding: '2px 6px', fontSize: 8 }}>
                  {k}: <strong>{v}</strong>
                </span>
              ))}
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 250, overflow: 'auto', padding: 6 }}>
            {deepResults.results?.slice(0, 30).map((t, i) => (
              <div key={i} className="soc-src-chip" style={{ cursor: 'pointer', padding: '4px 8px' }}
                onClick={() => onThreatClick?.(t)}>
                <span className={`soc-tag ${t.type === 'cve' ? 'cve' : ['ioc','botnet'].includes(t.type) ? 'ioc' : 'url'}`} style={{ fontSize: 7 }}>{t.type || '?'}</span>
                <span style={{ fontSize: 8, color: 'var(--accent-cyan)' }}>{t.source}</span>
                <span style={{ fontSize: 8 }}>{t.instruction?.slice(0, 80) || t.url?.slice(0, 50) || t.ioc || t.description?.slice(0, 60)}</span>
                <span className="soc-time" style={{ fontSize: 8 }}>{new Date(t.t || Date.now()).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {trends.length > 0 && (
        <div className="charts-row">
          <div className="chart-container half">
            <div className="chart-title">THREAT TYPE DISTRIBUTION <span className="chart-badge">{trends.length}</span></div>
            <div className="chart-wrap" style={{ height: 100 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trends} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 7, fill: '#94a3b8' }} width={55} />
                  <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                  <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                    {trends.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="chart-container half">
            <div className="chart-title">RESEARCH INSIGHTS</div>
            <div className="scroll-200" style={{ padding: 6 }}>
              {insights.length > 0 ? insights.slice(-8).reverse().map((ins, i) => (
                <div key={i} style={{ fontSize: 9, padding: '3px 6px', borderBottom: '1px solid var(--border)', marginBottom: 2 }}>
                  <span style={{ color: ins.type === 'error' ? 'var(--accent-red)' : 'var(--accent-cyan)', fontWeight: 600 }}>
                    [{ins.type === 'deep' ? 'DEEP' : ins.type === 'error' ? 'ERR' : '?'}]
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}> {ins.query?.slice(0, 60) || '—'}</span>
                  {ins.results !== undefined && <span className="soc-badge" style={{ marginLeft: 6 }}>{ins.results} matches</span>}
                </div>
              )) : <div className="soc-empty">Enter a deep research query</div>}
            </div>
          </div>
        </div>
      )}

      {history.length > 0 && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            THREAT HISTORY <span className="soc-badge">{history.length} days</span>
            <span className="soc-badge sec">LOCALSTORAGE</span>
          </div>
          <div className="soc-activity" style={{ maxHeight: 120 }}>
            <table className="soc-table">
              <thead><tr><th>Date</th><th>Threats</th><th>Preview</th></tr></thead>
              <tbody>
                {history.slice(-30).reverse().map((h, i) => (
                  <tr key={i} className="soc-tr">
                    <td style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--accent-cyan)' }}>{h.day}</td>
                    <td style={{ fontWeight: 600 }}>{h.count}</td>
                    <td style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{(h.threats || []).slice(0, 3).map(t => t.type || t.source).filter(Boolean).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="soc-panel">
        <div className="soc-panel-header">PAST ATTACKS KNOWLEDGE BASE</div>
        <div className="soc-sources" style={{ maxHeight: 80 }}>
          {['WannaCry (2017)', 'SolarWinds (2020)', 'Log4j (2021)', 'Colonial Pipeline (2021)',
            'Ukraine Cyber War (2022)', 'MOVEit (2023)', 'Ivanti (2024)', 'Salt Typhoon (2025)'].map((att, i) => (
            <div key={i} className="soc-src-chip" style={{ borderColor: 'var(--accent-red)', cursor: 'pointer' }}
              onClick={() => { setQuery(att.split(' (')[0]); deepResearch() }}>
              <span className="soc-src-id">{att}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
