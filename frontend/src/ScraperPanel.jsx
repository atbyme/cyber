import { useState, useEffect, useRef, useMemo } from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const SRC_COLORS = ['#06b6d4','#f59e0b','#8b5cf6','#ef4444','#10b981','#ec4899','#14b8a6','#f97316']

export default function ScraperPanel({ status, feedData, onThreatClick }) {
  const [liveScrapes, setLiveScrapes] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('aura_live_scrapes') || '[]') } catch { return [] }
  })
  const [allThreats, setAllThreats] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('aura_threats') || '[]') } catch { return [] }
  })
  const [sources, setSources] = useState({})
  const [scraping, setScraping] = useState(false)
  const wsRef = useRef(null)

  useEffect(() => {
    try { sessionStorage.setItem('aura_live_scrapes', JSON.stringify(liveScrapes.slice(0, 100))) } catch {}
  }, [liveScrapes])

  useEffect(() => {
    try { sessionStorage.setItem('aura_threats', JSON.stringify(allThreats.slice(0, 200))) } catch {}
  }, [allThreats])

  useEffect(() => {
    if (feedData?.threats) setAllThreats(feedData.threats)
    if (feedData?.sources) setSources(feedData.sources)
  }, [feedData])

  useEffect(() => {
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host.includes('5173') ? 'localhost:8000' : location.host}/ws`)
    wsRef.current = ws
    ws.onmessage = e => {
      try {
        const m = JSON.parse(e.data)
        if (m.event === 'source_result') {
          setLiveScrapes(p => [{ source: m.data.source, count: m.data.count, scan_type: m.data.scan_type, cycle: m.data.cycle, t: m.t, fresh: true }, ...p].slice(0, 100))
          setTimeout(() => setLiveScrapes(p => p.map(x => x.source === m.data.source ? { ...x, fresh: false } : x)), 2000)
        }
        if (['research', 'deep_research', 'crawl', 'passive_scan'].includes(m.event)) {
          fetch('/api/threats?limit=100').then(r => r.json()).then(setAllThreats).catch(() => {})
        }
      } catch {}
    }
    ws.onclose = () => setTimeout(() => {
      const h = location.host.includes('5173') ? 'localhost:8000' : location.host
      const p = location.protocol === 'https:' ? 'wss:' : 'ws:'
      if (wsRef.current === ws) wsRef.current = new WebSocket(`${p}//${h}/ws`)
    }, 2000)
    return () => ws.close()
  }, [])

  const trigger = async () => {
    setScraping(true)
    try { const r = await fetch('/api/scrape'); await r.json() } catch {}
    try {
      const r = await fetch('/api/threats?limit=100')
      setAllThreats(await r.json())
    } catch {}
    setScraping(false)
  }

  const sourceDist = useMemo(() => {
    const map = {}
    allThreats.forEach(t => { if (t.source) map[t.source] = (map[t.source] || 0) + 1 })
    return Object.entries(map).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value).slice(0, 10)
  }, [allThreats])

  const s = status || {}

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">REAL-TIME SCRAPER ENGINE — JOURNAL OF THE INTERNET</span>
        <span className="blink">{liveScrapes.length > 0 ? 'ACTIVE' : 'IDLE'}</span>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{(s.total_scraped || allThreats.length).toLocaleString()}</div>
          <div className="soc-stat-lbl">TOTAL SCRAPED</div>
          <div className="soc-stat-sub">{s.last_scrape ? new Date(s.last_scrape).toLocaleTimeString() : ''}</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{typeof sources === 'object' ? Object.keys(sources).length : 0}</div>
          <div className="soc-stat-lbl">ACTIVE SOURCES</div>
          <div className="soc-stat-sub">100+ sources · 30s RT cycle</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{liveScrapes.length}</div>
          <div className="soc-stat-lbl">LIVE EVENTS</div>
          <div className="soc-stat-sub">WebSocket feed</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{allThreats.length}</div>
          <div className="soc-stat-lbl">RECENT THREATS</div>
          <div className="soc-stat-sub">Session cached</div>
        </div>
      </div>

      <div className="filters-bar">
        <button className="btn btn-primary" onClick={trigger} disabled={scraping}>
          {scraping ? '⟳ SCANNING 100+ SOURCES...' : '⟳ TRIGGER DEEP SCAN'}
        </button>
        <span className="filter-label" style={{ marginLeft: 8 }}>Auto-scraping 100+ sources every 30s · Polling every 3s</span>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">SOURCE SCRAPE HISTORY <span className="chart-badge">{sourceDist.length} sources</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sourceDist.length > 0 ? sourceDist : [{ name: 'waiting', value: 1 }]} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 7, fill: '#94a3b8' }} width={60} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                  {sourceDist.map((e, i) => <Cell key={i} fill={SRC_COLORS[i % SRC_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">SOURCE DISTRIBUTION <span className="chart-badge">{sourceDist.length} sources</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={sourceDist.slice(0, 6)} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} innerRadius={30}>
                  {sourceDist.slice(0, 6).map((e, i) => <Cell key={i} fill={SRC_COLORS[i % SRC_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Legend wrapperStyle={{ fontSize: 8, color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="soc-panel" style={{ marginBottom: 14 }}>
        <div className="soc-panel-header">
          LIVE SCRAPE FEED <span className="soc-badge">{liveScrapes.length} events</span><span className="soc-badge sec">WS REAL-TIME</span>
        </div>
        <div className="soc-activity">
          {liveScrapes.length > 0 ? (
            <table className="soc-table">
              <thead><tr><th style={{ width: 50 }}>SOURCE</th><th style={{ width: 35 }}>ITEMS</th><th style={{ width: 45 }}>SCAN</th><th style={{ width: 35 }}>CYCLE</th><th style={{ width: 60 }}>TIME</th></tr></thead>
              <tbody>
                {liveScrapes.slice(0, 30).map((ls, i) => (
                  <tr key={i} className="soc-tr" style={ls.fresh ? { background: 'rgba(16,185,129,0.05)' } : {}}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontSize: 10 }}>{ls.source}</td>
                    <td style={{ fontWeight: 600, fontSize: 11 }}>+{ls.count}</td>
                    <td><span className={`soc-tag ${ls.scan_type === 'deep' ? 'cve' : 'info'}`}>{ls.scan_type}</span></td>
                    <td style={{ fontSize: 10, color: 'var(--text-secondary)' }}>#{ls.cycle}</td>
                    <td className="soc-time">{new Date(ls.t || Date.now()).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <div className="soc-empty">Connecting to scrape engine — waiting for WebSocket data...</div>}
        </div>
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">
          RECENT THREATS SCRAPED <span className="soc-badge">{allThreats.length} items</span><span className="soc-badge sec">CACHED</span>
        </div>
        <div className="soc-feed">
          {allThreats.length > 0 ? (
            <table className="soc-table">
              <thead><tr><th style={{ width: 25 }}>#</th><th style={{ width: 50 }}>TYPE</th><th style={{ width: 40 }}>SOURCE</th><th>CONTENT / URL / IOC</th><th style={{ width: 55 }}>TIME</th></tr></thead>
              <tbody>
                {allThreats.slice(0, 40).map((t, i) => (
                  <tr key={`${t.t}-${i}`} className="soc-tr tr-clickable" onClick={() => onThreatClick?.(t)}>
                    <td className="soc-idx">{i + 1}</td>
                    <td><span className={`soc-tag ${t.type === 'cve' ? 'cve' : ['ioc','botnet'].includes(t.type) ? 'ioc' : ['malicious_url','phishing_url'].includes(t.type) ? 'url' : 'info'}`}>{t.type?.slice(0, 10)}</span></td>
                    <td className="soc-src">{t.source?.slice(0, 8)}</td>
                    <td className="soc-desc" title={t.instruction || t.response || t.url || t.ioc || t.description}>
                      {t.instruction?.slice(0, 100) || t.response?.slice(0, 100) || t.url?.slice(0, 70) || t.ioc?.slice(0, 50) || t.description?.slice(0, 60) || '-'}
                    </td>
                    <td className="soc-time">{new Date(t.t || Date.now()).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <div className="soc-empty">No data yet — scanning in progress...</div>}
        </div>
      </div>
    </div>
  )
}
