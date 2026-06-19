import { useState, useEffect } from 'react'

function EntityCard({ entity }) {
  const r = entity.result || {}
  const analysis = r.analysis || {}
  const isMalicious = r.threat?.malicious || analysis.ioc?.malicious
  const isIP = analysis.ip
  const isDomain = analysis.domain
  const isURL = analysis.url
  const type = isIP ? 'IP' : isDomain ? 'Domain' : isURL ? 'URL' : 'IOC'

  return (
    <div style={{ background: 'var(--bg-hover)', borderRadius: 8, padding: 12, border: `1px solid ${isMalicious ? 'var(--accent-red)' : 'var(--border)'}`, marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <strong style={{ fontSize: 13, fontFamily: 'monospace' }}>{entity.target}</strong>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span className={`tag ${isMalicious ? 'tag-malicious' : 'tag-clean'}`}>{isMalicious ? '⚠ Threat' : 'Clean'}</span>
          <span className="tag tag-cve">{type}</span>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: 11, color: 'var(--text-secondary)' }}>
        {analysis.ip?.hostname && <div>Hostname: {analysis.ip.hostname}</div>}
        {isDomain && analysis.domain?.dns?.ips && <div>IPs: {analysis.domain.dns.ips.join(', ')}</div>}
        {r.whois?.registrar && <div>Registrar: {r.whois.registrar}</div>}
        {r.whois?.country && <div>Country: {r.whois.country}</div>}
        {r.port_scan && r.port_scan.length > 0 && <div>Open Ports: {r.port_scan.map(p => p.port).join(', ')}</div>}
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4, opacity: 0.5 }}>
        {new Date(entity.timestamp).toLocaleString()}
      </div>
    </div>
  )
}

export default function FootprintPanel() {
  const [monitored, setMonitored] = useState([])
  const [stats, setStats] = useState({ total: 0, malicious: 0, clean: 0, iocs: 0, ips: 0 })
  const [target, setTarget] = useState('')
  const [manualResult, setManualResult] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)

  useEffect(() => {
    const f = () => {
      fetch('/api/monitor?limit=50').then(r => r.json()).then(setMonitored).catch(() => {})
      fetch('/api/monitor/stats').then(r => r.json()).then(setStats).catch(() => {})
    }
    f()
    const i = setInterval(f, 4000)
    return () => clearInterval(i)
  }, [])

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

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Real-Time Footprint Monitor</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Auto-monitoring all discovered IOCs · Live updates every 4s · {stats.total} entities tracked
      </p>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card"><div className="label">Monitored Entities</div><div className="value" style={{ color: 'var(--accent-cyan)', fontSize: 22 }}>{stats.total}</div><div className="sub">Auto-tracked</div></div>
        <div className="stat-card"><div className="label">Threats Detected</div><div className="value" style={{ color: 'var(--accent-red)', fontSize: 22 }}>{stats.malicious}</div><div className="sub">Malicious</div></div>
        <div className="stat-card"><div className="label">Clean Entities</div><div className="value" style={{ color: 'var(--accent-green)', fontSize: 22 }}>{stats.clean}</div><div className="sub">No threats</div></div>
        <div className="stat-card"><div className="label">IOCs Analyzed</div><div className="value" style={{ color: 'var(--accent-yellow)', fontSize: 22 }}>{stats.iocs}</div><div className="sub">Indicators</div></div>
        <div className="stat-card"><div className="label">IPs Tracked</div><div className="value" style={{ color: 'var(--accent-purple)', fontSize: 22 }}>{stats.ips}</div><div className="sub">Addresses</div></div>
      </div>

      <div className="panel">
        <h2>Manual Analysis</h2>
        <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
          <input type="text" placeholder="IP, domain, URL, or IOC to analyze..." value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === 'Enter' && manualAnalyze()} style={{ flex: 1, padding: '10px 16px', background: 'var(--bg-hover)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)', fontSize: 14 }} />
          <button className="btn btn-primary" onClick={manualAnalyze} disabled={analyzing || !target.trim()}>{analyzing ? 'Analyzing...' : 'Analyze'}</button>
        </div>
        {manualResult && <pre style={{ fontSize: 11, maxHeight: 200, overflow: 'auto' }}>{JSON.stringify(manualResult, null, 2)}</pre>}
      </div>

      <div className="panel">
        <h2>Auto-Monitored Live Feed <span className="badge">{monitored.length} entities · updates every 4s</span></h2>
        {monitored.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {monitored.map((e, i) => <EntityCard key={i} entity={e} />)}
          </div>
        ) : <div className="loading"><div className="spinner" /> Auto-monitoring started — waiting for data...</div>}
      </div>
    </div>
  )
}
