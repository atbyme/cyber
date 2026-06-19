import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'

export default function ResearchPanel() {
  const [activity, setActivity] = useState([])
  const [knowledge, setKnowledge] = useState({ history: [] })
  const [sources, setSources] = useState({})
  const [threats, setThreats] = useState([])

  useEffect(() => {
    const f = () => {
      fetch('/api/research/activity').then(r => r.json()).then(setActivity).catch(() => {})
      fetch('/api/knowledge').then(r => r.json()).then(setKnowledge).catch(() => {})
      fetch('/api/sources').then(r => r.json()).then(setSources).catch(() => {})
      fetch('/api/threats?limit=50').then(r => r.json()).then(setThreats).catch(() => {})
    }
    f()
    const i = setInterval(f, 3000)
    return () => clearInterval(i)
  }, [])

  const k = knowledge
  const total = (k.unique_cves || 0) + (k.unique_iocs || 0) + (k.unique_malware || 0) + (k.unique_urls || 0)
  const history = knowledge.history || []
  const lastActivity = activity[0] || {}

  const typeData = {}
  threats.forEach(t => { const s = t.source || '?'; typeData[s] = (typeData[s] || 0) + 1 })
  const barData = Object.entries(typeData).slice(0, 18).map(([n, v]) => ({ name: n.slice(0, 10), value: v }))

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Real-Time Research Engine</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Live internet research · Refresh every 3s · {Object.keys(sources).length} sources · Last cycle: {lastActivity.count || 0} threats
      </p>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card"><div className="label">Total Knowledge</div><div className="value" style={{ color: 'var(--accent-purple)', fontSize: 22 }}>{total.toLocaleString()}</div><div className="sub">Unique artifacts</div></div>
        <div className="stat-card"><div className="label">CVEs</div><div className="value" style={{ color: 'var(--accent-red)', fontSize: 22 }}>{(k.unique_cves || 0).toLocaleString()}</div><div className="sub">Vulnerabilities</div></div>
        <div className="stat-card"><div className="label">IOCs</div><div className="value" style={{ color: 'var(--accent-yellow)', fontSize: 22 }}>{(k.unique_iocs || 0).toLocaleString()}</div><div className="sub">Indicators</div></div>
        <div className="stat-card"><div className="label">Malware</div><div className="value" style={{ color: 'var(--accent-cyan)', fontSize: 22 }}>{(k.unique_malware || 0).toLocaleString()}</div><div className="sub">Families</div></div>
        <div className="stat-card"><div className="label">Malicious URLs</div><div className="value" style={{ color: 'var(--accent-green)', fontSize: 22 }}>{(k.unique_urls || 0).toLocaleString()}</div><div className="sub">URLs cataloged</div></div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Knowledge Growth (Live)</h2>
          {history.length > 1 ? <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={history}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="cycle" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Area type="monotone" dataKey="unique_iocs" stackId="1" stroke="var(--accent-yellow)" fill="var(--accent-yellow)" fillOpacity={0.2} /><Area type="monotone" dataKey="unique_cves" stackId="1" stroke="var(--accent-red)" fill="var(--accent-red)" fillOpacity={0.2} /><Area type="monotone" dataKey="unique_malware" stackId="1" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.2} /></AreaChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Accumulating live knowledge...</div>}
        </div>
        <div className="panel">
          <h2>Live Source Distribution</h2>
          {barData.length > 0 ? <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Bar dataKey="value" fill="var(--accent-cyan)" radius={[4, 4, 0, 0]} /></BarChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Live data incoming...</div>}
        </div>
      </div>

      <div className="panel">
        <h2>Live Research Activity Feed <span className="badge">refreshes every 3s</span></h2>
        {activity.length > 0 ? <div className="threat-table"><table>
          <thead><tr><th>#</th><th>Type</th><th>Count</th><th>Source Breakdown</th><th>Type Breakdown</th><th>Time</th></tr></thead>
          <tbody>{activity.slice(0, 30).map((a, i) => (
            <tr key={i}>
              <td style={{ color: 'var(--accent-cyan)' }}>#{a.cycle}</td>
              <td><span className={`tag ${a.type === 'realtime' ? 'tag-ioc' : 'tag-cve'}`}>{a.type}</span></td>
              <td style={{ fontWeight: 600 }}>{a.count}</td>
              <td style={{ fontSize: 10 }}>{Object.entries(a.sources || {}).map(([k, v]) => <span key={k} className="tag tag-cve" style={{ margin: '0 2px' }}>{k}:{v}</span>)}</td>
              <td style={{ fontSize: 10 }}>{Object.entries(a.types || {}).map(([k, v]) => <span key={k} className="tag tag-ioc" style={{ margin: '0 2px' }}>{k}:{v}</span>)}</td>
              <td style={{ color: 'var(--text-secondary)', fontSize: 10 }}>{new Date(a.time).toLocaleTimeString()}</td>
            </tr>
          ))}</tbody>
        </table></div> : <div className="loading"><div className="spinner" /> Research engine initializing...</div>}
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Live Knowledge Composition</h2>
          {total > 0 ? <table><tbody>
            <tr><td style={{ color: 'var(--text-secondary)' }}>CVEs</td><td style={{ color: 'var(--accent-red)', fontWeight: 600, fontSize: 18 }}>{(k.unique_cves || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_cves || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>IOCs</td><td style={{ color: 'var(--accent-yellow)', fontWeight: 600, fontSize: 18 }}>{(k.unique_iocs || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_iocs || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malware Families</td><td style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: 18 }}>{(k.unique_malware || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_malware || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malicious URLs</td><td style={{ color: 'var(--accent-purple)', fontWeight: 600, fontSize: 18 }}>{(k.unique_urls || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_urls || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Total Samples</td><td style={{ fontWeight: 600, fontSize: 18 }}>{(k.total_samples || 0).toLocaleString()}</td><td>100%</td></tr>
          </tbody></table> : <div className="loading"><div className="spinner" /> Building live knowledge...</div>}
        </div>
        <div className="panel">
          <h2>All Research Sources</h2>
          <table><thead><tr><th>Source ID</th><th>Full Name</th></tr></thead><tbody>{Object.entries(sources).map(([id, name], i) => (
            <tr key={i}><td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-cyan)' }}>{id}</td><td style={{ fontSize: 12 }}>{name}</td></tr>
          ))}</tbody></table>
        </div>
      </div>

      <div className="panel">
        <h2>Live Discoveries Feed <span className="badge">{threats.length} recent</span></h2>
        {threats.length > 0 ? <div className="threat-table"><table>
          <thead><tr><th>Type</th><th>Source</th><th>Detail</th></tr></thead>
          <tbody>{threats.slice(0, 25).map((t, i) => (
            <tr key={i}><td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || '?'}</span></td><td style={{ fontSize: 11 }}>{t.source}</td><td style={{ fontSize: 11, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.instruction?.slice(0, 100) || t.description?.slice(0, 100) || t.ioc?.slice(0, 50) || t.url?.slice(0, 50) || '-'}</td></tr>
          ))}</tbody>
        </table></div> : <div className="loading"><div className="spinner" /> Live feed starting...</div>}
      </div>
    </div>
  )
}
