import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, AreaChart, Area } from 'recharts'

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
      fetch('/api/threats?limit=30').then(r => r.json()).then(setThreats).catch(() => {})
    }
    f()
    const i = setInterval(f, 5000)
    return () => clearInterval(i)
  }, [])

  const k = knowledge
  const total = (k.unique_cves || 0) + (k.unique_iocs || 0) + (k.unique_malware || 0) + (k.unique_urls || 0)
  const history = knowledge.history || []

  const srcData = Object.entries(sources).slice(0, 18).map(([id, name]) => ({ name: id.slice(0, 10), full: name }))

  const typeCounts = {}
  threats.forEach(t => { const s = t.source || '?'; typeCounts[s] = (typeCounts[s] || 0) + 1 })
  const typeData = Object.entries(typeCounts).slice(0, 15).map(([n, v]) => ({ name: n.slice(0, 10), value: v }))

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Internet Research Engine</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Passive real-time research every 3min · Deep research every 2hr · {Object.keys(sources).length} sources monitored
      </p>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="stat-card"><div className="label">Total Knowledge</div><div className="value" style={{ color: 'var(--accent-purple)' }}>{total.toLocaleString()}</div><div className="sub">Unique intelligence artifacts</div></div>
        <div className="stat-card"><div className="label">CVEs Discovered</div><div className="value" style={{ color: 'var(--accent-red)' }}>{k.unique_cves || 0}</div><div className="sub">Vulnerabilities</div></div>
        <div className="stat-card"><div className="label">IOCs Tracked</div><div className="value" style={{ color: 'var(--accent-yellow)' }}>{k.unique_iocs || 0}</div><div className="sub">Malicious indicators</div></div>
        <div className="stat-card"><div className="label">Malware Families</div><div className="value" style={{ color: 'var(--accent-cyan)' }}>{k.unique_malware || 0}</div><div className="sub">Unique malware</div></div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Knowledge Growth</h2>
          {history.length > 1 ? <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={history}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="cycle" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Area type="monotone" dataKey="unique_iocs" stackId="1" stroke="var(--accent-yellow)" fill="var(--accent-yellow)" fillOpacity={0.2} /><Area type="monotone" dataKey="unique_cves" stackId="1" stroke="var(--accent-red)" fill="var(--accent-red)" fillOpacity={0.2} /><Area type="monotone" dataKey="unique_malware" stackId="1" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.2} /></AreaChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Accumulating knowledge...</div>}
        </div>
        <div className="panel">
          <h2>Research Sources</h2>
          {srcData.length > 0 ? <table><thead><tr><th>Source</th><th>Name</th></tr></thead><tbody>{srcData.map((s, i) => <tr key={i}><td style={{ fontFamily: 'monospace', fontSize: 11 }}>{s.name}</td><td style={{ fontSize: 12 }}>{s.full}</td></tr>)}</tbody></table> : <div className="loading"><div className="spinner" /> Loading sources...</div>}
        </div>
      </div>

      <div className="panel">
        <h2>Live Research Activity <span className="badge">{activity.length} cycles · refreshes every 5s</span></h2>
        {activity.length > 0 ? <div className="threat-table"><table>
          <thead><tr><th>Cycle</th><th>Type</th><th>Count</th><th>Sources</th><th>Types</th><th>Time</th></tr></thead>
          <tbody>{activity.slice(0, 20).map((a, i) => (
            <tr key={i}>
              <td style={{ color: 'var(--accent-cyan)' }}>#{a.cycle}</td>
              <td><span className={`tag ${a.type === 'realtime' ? 'tag-ioc' : 'tag-cve'}`}>{a.type}</span></td>
              <td style={{ fontWeight: 600 }}>{a.count}</td>
              <td style={{ fontSize: 11 }}>{Object.entries(a.sources || {}).map(([k, v]) => `${k}:${v}`).join(' ')}</td>
              <td style={{ fontSize: 11 }}>{Object.entries(a.types || {}).map(([k, v]) => `${k}:${v}`).join(' ')}</td>
              <td style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{new Date(a.time).toLocaleTimeString()}</td>
            </tr>
          ))}</tbody>
        </table></div> : <div className="loading"><div className="spinner" /> Research engine starting...</div>}
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Knowledge Composition</h2>
          {total > 0 ? <table><tbody>
            <tr><td style={{ color: 'var(--text-secondary)' }}>CVEs</td><td style={{ color: 'var(--accent-red)', fontWeight: 600 }}>{(k.unique_cves || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_cves || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>IOCs</td><td style={{ color: 'var(--accent-yellow)', fontWeight: 600 }}>{(k.unique_iocs || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_iocs || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malware Families</td><td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{(k.unique_malware || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_malware || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malicious URLs</td><td style={{ color: 'var(--accent-purple)', fontWeight: 600 }}>{(k.unique_urls || 0).toLocaleString()}</td><td>{total > 0 ? `${((k.unique_urls || 0) / total * 100).toFixed(1)}%` : ''}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Total Samples</td><td style={{ fontWeight: 600 }}>{(k.total_samples || 0).toLocaleString()}</td><td>100%</td></tr>
          </tbody></table> : <div className="loading"><div className="spinner" /> Building knowledge...</div>}
        </div>
        <div className="panel">
          <h2>Recent Discoveries</h2>
          {threats.length > 0 ? <table><thead><tr><th>Type</th><th>Source</th><th>Detail</th></tr></thead><tbody>{threats.slice(0, 12).map((t, i) => (
            <tr key={i}><td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || '?'}</span></td><td style={{ fontSize: 11 }}>{t.source}</td><td style={{ fontSize: 11, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.instruction?.slice(0, 80) || t.description?.slice(0, 80) || t.ioc?.slice(0, 40) || t.url?.slice(0, 40) || '-'}</td></tr>
          ))}</tbody></table> : <div className="loading"><div className="spinner" /> Researching...</div>}
        </div>
      </div>
    </div>
  )
}
