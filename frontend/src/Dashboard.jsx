import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'

export default function Dashboard({ status }) {
  const [threats, setThreats] = useState([])
  const [models, setModels] = useState([])
  const [knowledge, setKnowledge] = useState({})
  const [threatHistory, setThreatHistory] = useState([])

  useEffect(() => {
    const f = () => {
      fetch('/api/threats?limit=15').then(r => r.json()).then(setThreats).catch(() => {})
      fetch('/api/models').then(r => r.json()).then(d => setModels(d.versions || [])).catch(() => {})
      fetch('/api/knowledge').then(r => r.json()).then(setKnowledge).catch(() => {})
      fetch('/api/threats/history').then(r => r.json()).then(setThreatHistory).catch(() => {})
    }
    f()
    const i = setInterval(f, 8000)
    return () => clearInterval(i)
  }, [])

  const s = status.scraper || {}
  const t = status.training || {}
  const r = status.research || {}
  const cycle = status.cycle || 0
  const rcycle = status.research_cycle || 0
  const total = s.total_scraped || 0
  const k = knowledge

  const srcChart = {}
  threats.forEach(x => { const src = x.source || '?'; srcChart[src] = (srcChart[src] || 0) + 1 })
  const barData = Object.entries(srcChart).map(([n, v]) => ({ name: n.slice(0, 10), value: v }))

  const totalKnowledge = (k.unique_cves || 0) + (k.unique_iocs || 0) + (k.unique_malware || 0) + (k.unique_urls || 0)

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0 }}>AURA Live Dashboard</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
            Passive research: #{rcycle} · Deep research: #{cycle} · {total.toLocaleString()} total threats collected · {totalKnowledge.toLocaleString()} knowledge items
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="status-dot online" /><span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Research: 3min · Deep: 2hr</span>
        </div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card"><div className="label">Total Threats</div><div className="value" style={{ color: 'var(--accent-cyan)', fontSize: 22 }}>{total.toLocaleString()}</div><div className="sub">All time</div></div>
        <div className="stat-card"><div className="label">Knowledge Items</div><div className="value" style={{ color: 'var(--accent-purple)', fontSize: 22 }}>{totalKnowledge.toLocaleString()}</div><div className="sub">Unique learnings</div></div>
        <div className="stat-card"><div className="label">CVEs</div><div className="value" style={{ color: 'var(--accent-red)', fontSize: 22 }}>{(k.unique_cves || 0).toLocaleString()}</div><div className="sub">Vulnerabilities</div></div>
        <div className="stat-card"><div className="label">IOCs</div><div className="value" style={{ color: 'var(--accent-yellow)', fontSize: 22 }}>{(k.unique_iocs || 0).toLocaleString()}</div><div className="sub">Indicators</div></div>
        <div className="stat-card"><div className="label">Model Versions</div><div className="value" style={{ color: 'var(--accent-green)', fontSize: 22 }}>{t.versions || 0}</div><div className="sub">On ModelScope Hub</div></div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Research Sources Breakdown</h2>
          {barData.length > 0 ? <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Bar dataKey="value" fill="var(--accent-cyan)" radius={[4, 4, 0, 0]} /></BarChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Researching internet...</div>}
        </div>
        <div className="panel">
          <h2>Knowledge Accumulation</h2>
          {totalKnowledge > 0 ? <table><tbody>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Unique CVEs</td><td style={{ color: 'var(--accent-red)', fontWeight: 600 }}>{(k.unique_cves || 0).toLocaleString()}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Unique IOCs</td><td style={{ color: 'var(--accent-yellow)', fontWeight: 600 }}>{(k.unique_iocs || 0).toLocaleString()}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malware Families</td><td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{(k.unique_malware || 0).toLocaleString()}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Malicious URLs</td><td style={{ color: 'var(--accent-purple)', fontWeight: 600 }}>{(k.unique_urls || 0).toLocaleString()}</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Total Samples Processed</td><td style={{ fontWeight: 600 }}>{(k.total_samples || 0).toLocaleString()}</td></tr>
          </tbody></table> : <div className="loading"><div className="spinner" /> Building knowledge base...</div>}
        </div>
      </div>

      <div className="panel">
        <h2>Live Threat Feed <span className="badge">{threats.length} entries · real-time</span></h2>
        {threats.length > 0 ? <div className="threat-table"><table>
          <thead><tr><th>#</th><th>Type</th><th>Source</th><th>Detail</th><th>Score</th></tr></thead>
          <tbody>{threats.map((t, i) => (
            <tr key={i}>
              <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{i + 1}</td>
              <td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || '?'}</span></td>
              <td style={{ fontSize: 11 }}>{t.source}</td>
              <td style={{ maxWidth: 400, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.instruction?.slice(0, 100) || t.description?.slice(0, 100) || '-'}</td>
              <td>{t.cvss_score || '-'}</td>
            </tr>
          ))}</tbody>
        </table></div> : <div className="loading"><div className="spinner" /> Scanning internet...</div>}
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Model Versions <span className="badge">{models.length}</span></h2>
          {models.length > 0 ? <table><thead><tr><th>Cycle</th><th>Version</th><th>Samples</th><th>Time</th></tr></thead>
          <tbody>{models.slice(-8).reverse().map((m, i) => (
            <tr key={i}><td>#{m.cycle}</td><td style={{ color: 'var(--accent-cyan)' }}>{m.version}</td><td>{m.samples}</td><td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{new Date(m.timestamp).toLocaleTimeString()}</td></tr>
          ))}</tbody></table> : <div className="loading"><div className="spinner" /> No models yet</div>}
        </div>
        <div className="panel">
          <h2>System Status</h2>
          <table><tbody>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Research Cycle</td><td>Every 3 minutes (passive)</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Deep Research</td><td>Every 2 hours (full internet)</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Data Sources</td><td>18 simultaneous feeds</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Training</td><td>ModelScope cloud (zero local GPU)</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Training Data</td><td>All CVEs + IOCs + Malware + URLs + Linux cmds</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Dataset Format</td><td>Instruction-Response JSONL → ModelScope Hub</td></tr>
          </tbody></table>
        </div>
      </div>
    </div>
  )
}
