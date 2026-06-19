import { useState, useEffect, useMemo } from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'

export default function FootprintPanel({ status, feedData }) {
  const [monitored, setMonitored] = useState([])
  const [liveFootprints, setLiveFootprints] = useState([])
  const [target, setTarget] = useState('')
  const [manualResult, setManualResult] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)

  useEffect(() => {
    if (feedData?.footprints) setLiveFootprints(feedData.footprints)
  }, [feedData])

  useEffect(() => {
    const f = () => {
      fetch('/api/monitor?limit=50').then(r => r.json()).then(setMonitored).catch(() => {})
    }
    f()
    const i = setInterval(f, 4000)
    return () => clearInterval(i)
  }, [])

  useEffect(() => {
    const host = location.host.includes('5173') ? 'localhost:8000' : location.host
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${host}/ws`)
    ws.onmessage = e => {
      try {
        const m = JSON.parse(e.data)
        if (m.event === 'footprint') {
          setLiveFootprints(p => [{ count: m.data.count, malicious: m.data.malicious, t: m.t }, ...p].slice(0, 100))
        }
      } catch {}
    }
    return () => ws.close()
  }, [])

  const stats = useMemo(() => {
    const total = monitored.length
    let malicious = 0, clean = 0, ips = 0, domains = 0, urls = 0
    monitored.forEach(e => {
      const r = e.result || {}
      const analysis = r.analysis || {}
      if (r.threat?.malicious || analysis.ioc?.malicious) malicious++
      else clean++
      if (analysis.ip) ips++
      if (analysis.domain) domains++
      if (analysis.url) urls++
    })
    return { total, malicious, clean, ips, domains, urls }
  }, [monitored])

  const maliciousTimeline = useMemo(() => {
    return liveFootprints.slice(0, 30).reverse().map((f, i) => ({
      time: new Date(f.t || Date.now()).toLocaleTimeString(),
      total: f.count || 0,
      malicious: f.malicious || 0
    }))
  }, [liveFootprints])

  const manualAnalyze = async () => {
    if (!target.trim()) return
    setAnalyzing(true)
    try {
      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), scan_ports: true }),
      })
      setManualResult(await r.json())
    } catch {}
    setAnalyzing(false)
  }

  function EntityCard({ entity }) {
    const r = entity.result || {}
    const analysis = r.analysis || {}
    const isMalicious = r.threat?.malicious || analysis.ioc?.malicious
    const isIP = analysis.ip
    const isDomain = analysis.domain
    const isURL = analysis.url
    const type = isIP ? 'IP' : isDomain ? 'Domain' : isURL ? 'URL' : 'IOC'
    const risk = isMalicious ? 'critical' : 'low'

    return (
      <div className={`threat-card ${risk}`}>
        <div className="threat-card-header">
          <span className={`threat-card-type ${risk}`}>{type}</span>
          <span className={`threat-card-risk ${risk}`}>{isMalicious ? 'MALICIOUS' : 'CLEAN'}</span>
        </div>
        <div className="threat-card-desc" style={{ whiteSpace: 'normal' }}>{entity.target}</div>
        <div className="threat-card-meta" style={{ flexWrap: 'wrap', marginTop: 4 }}>
          {analysis.ip?.hostname && <span>Hostname: {analysis.ip.hostname}</span>}
          {isDomain && analysis.domain?.dns?.ips && <span>IPs: {analysis.domain.dns.ips.slice(0, 3).join(', ')}</span>}
          {r.whois?.country && <span>Country: {r.whois.country}</span>}
          {r.whois?.registrar && <span>Reg: {r.whois.registrar}</span>}
          {r.port_scan?.length > 0 && <span>Ports: {r.port_scan.map(p => p.port).join(', ')}</span>}
        </div>
        <div className="threat-card-time" style={{ marginTop: 4 }}>{new Date(entity.timestamp || entity.t || Date.now()).toLocaleString()}</div>
      </div>
    )
  }

  const pieData = [
    { name: 'Malicious', value: stats.malicious, color: '#ef4444' },
    { name: 'Clean', value: stats.clean, color: '#10b981' },
  ].filter(d => d.value > 0)

  const entityTypes = [
    { name: 'IPs', value: stats.ips, color: '#06b6d4' },
    { name: 'Domains', value: stats.domains, color: '#8b5cf6' },
    { name: 'URLs', value: stats.urls, color: '#f59e0b' },
  ].filter(d => d.value > 0)

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">REAL-TIME FOOTPRINT MONITOR</span>
        <span className="blink">{liveFootprints.length > 0 || monitored.length > 0 ? 'TRACKING' : 'IDLE'}</span>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{stats.total}</div>
          <div className="soc-stat-lbl">MONITORED ENTITIES</div>
          <div className="soc-stat-sub">Auto-tracked from scan data</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{stats.malicious}</div>
          <div className="soc-stat-lbl">MALICIOUS DETECTED</div>
          <div className="soc-stat-sub">{stats.total > 0 ? ((stats.malicious / stats.total) * 100).toFixed(1) + '%' : '0%'}</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{stats.clean}</div>
          <div className="soc-stat-lbl">CLEAN ENTITIES</div>
          <div className="soc-stat-sub">No threats detected</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{liveFootprints.length}</div>
          <div className="soc-stat-lbl">LIVE EVENTS</div>
          <div className="soc-stat-sub">Real-time WebSocket feed</div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">MALICIOUS VS CLEAN <span className="chart-badge">{stats.total} total</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData.length > 0 ? pieData : [{ name: 'No data', value: 1, color: '#2d3a50' }]} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} innerRadius={30}>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 9, color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">ENTITY TYPE BREAKDOWN <span className="chart-badge">{entityTypes.reduce((s, e) => s + e.value, 0)}</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={entityTypes.length > 0 ? entityTypes : [{ name: 'No data', value: 1, color: '#2d3a50' }]}>
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 9, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 11 }} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {entityTypes.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {maliciousTimeline.length > 0 && (
        <div className="chart-container" style={{ marginBottom: 14 }}>
          <div className="chart-title">FOOTPRINT TIMELINE <span className="chart-badge">{maliciousTimeline.length} events</span></div>
          <div className="chart-wrap" style={{ height: 100 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={maliciousTimeline}>
                <XAxis dataKey="time" tick={{ fontSize: 7, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 11 }} />
                <Bar dataKey="total" fill="#06b6d4" stackId="a" radius={[2, 2, 0, 0]} />
                <Bar dataKey="malicious" fill="#ef4444" stackId="a" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="soc-panel" style={{ marginBottom: 14 }}>
        <div className="soc-panel-header">MANUAL ANALYSIS</div>
        <div className="form-row">
          <input className="filter-search" style={{ flex: 1, fontSize: 13, padding: '8px 12px' }}
            placeholder="Enter IP, domain, URL, or IOC to analyze..." value={target}
            onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === 'Enter' && manualAnalyze()} />
          <button className="btn btn-primary" onClick={manualAnalyze} disabled={analyzing || !target.trim()}>
            {analyzing ? '⟳ ANALYZING...' : 'ANALYZE'}
          </button>
        </div>
        {manualResult && (
          <div className="soc-activity">
            <pre style={{ fontSize: 10, maxHeight: 200, overflow: 'auto', color: 'var(--text-secondary)' }}>{JSON.stringify(manualResult, null, 2)}</pre>
          </div>
        )}
      </div>

      <div className="soc-panel" style={{ marginBottom: 14 }}>
        <div className="soc-panel-header">
          AUTO-MONITORED LIVE FEED <span className="soc-badge">{monitored.length} entities</span><span className="soc-badge sec">4S POLL</span>
        </div>
        {monitored.length > 0 ? (
          <div className="threat-grid">
            {monitored.map((e, i) => <EntityCard key={i} entity={e} />)}
          </div>
        ) : <div className="soc-empty">Auto-monitoring started — waiting for footprint data from scans...</div>}
      </div>

      {liveFootprints.length > 0 && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            REAL-TIME FOOTPRINT EVENTS <span className="soc-badge sec">WS LIVE</span>
          </div>
          <div className="soc-activity">
            <table className="soc-table">
              <thead><tr><th>Total</th><th>Malicious</th><th>Clean %</th><th>Time</th></tr></thead>
              <tbody>
                {liveFootprints.slice(0, 20).map((f, i) => (
                  <tr key={i} className="soc-tr">
                    <td style={{ fontWeight: 600 }}>{f.count}</td>
                    <td style={{ color: 'var(--accent-red)', fontWeight: 600 }}>{f.malicious}</td>
                    <td style={{ color: 'var(--accent-green)' }}>{f.count > 0 ? (((f.count - f.malicious) / f.count) * 100).toFixed(0) + '%' : '-'}</td>
                    <td className="soc-time">{new Date(f.t || Date.now()).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
