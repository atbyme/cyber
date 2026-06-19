import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, AreaChart, Area } from 'recharts'

export default function Dashboard({ status }) {
  const [threats, setThreats] = useState([])
  const [models, setModels] = useState([])
  const [history, setHistory] = useState([])
  const [sources, setSources] = useState({})
  const [threatHistory, setThreatHistory] = useState([])

  useEffect(() => {
    const fetchAll = () => {
      fetch('/api/threats?limit=20').then(r => r.json()).then(setThreats).catch(() => {})
      fetch('/api/models').then(r => r.json()).then(d => setModels(d.versions || [])).catch(() => {})
      fetch('/api/sources').then(r => r.json()).then(setSources).catch(() => {})
      fetch('/api/threats/history').then(r => r.json()).then(setThreatHistory).catch(() => {})
    }
    fetchAll()
    const i = setInterval(fetchAll, 10000)
    return () => clearInterval(i)
  }, [])

  useEffect(() => {
    fetch('/api/status').then(r => r.json()).then(s => {
      setHistory(p => [...p, { time: new Date().toLocaleTimeString(), threats: s.scraper?.total_scraped || 0, cycle: s.cycle || 0 }].slice(-30))
    }).catch(() => {})
  }, [status])

  const s = status.scraper || {}
  const t = status.training || {}
  const cycle = status.cycle || 0
  const total = s.total_scraped || 0

  const srcChart = {}
  threats.forEach(x => { const k = x.source || 'other'; srcChart[k] = (srcChart[k] || 0) + 1 })
  const barData = Object.entries(srcChart).map(([n, v]) => ({ name: n.slice(0, 12), value: v }))

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0 }}>AURA Live Dashboard</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>Continuous internet monitoring · {cycle} cycles completed · {total} total threats</p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className={`status-dot ${cycle > 0 ? 'online' : 'offline'}`} />
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Cycle #{cycle} · Next in ~60s</span>
        </div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="stat-card"><div className="label">Threats Collected</div><div className="value" style={{ color: 'var(--accent-cyan)' }}>{total}</div><div className="sub">{threats.length} recent</div></div>
        <div className="stat-card"><div className="label">Learning Cycle</div><div className="value" style={{ color: 'var(--accent-purple)' }}>#{cycle}</div><div className="sub">{t.running ? 'Training...' : 'Active'}</div></div>
        <div className="stat-card"><div className="label">Model Versions</div><div className="value" style={{ color: 'var(--accent-green)' }}>{t.versions || 0}</div><div className="sub">On ModelScope Hub</div></div>
        <div className="stat-card"><div className="label">Data Sources</div><div className="value" style={{ color: 'var(--accent-yellow)', fontSize: 20 }}>{Object.keys(sources).length || 10}</div><div className="sub">Simultaneous feeds</div></div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Threat Sources <span className="badge">{barData.length} sources</span></h2>
          {barData.length > 0 ? <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Bar dataKey="value" fill="var(--accent-cyan)" radius={[4, 4, 0, 0]} /></BarChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Gathering data...</div>}
        </div>
        <div className="panel">
          <h2>Threats Over Time</h2>
          {threatHistory.length > 1 ? <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={threatHistory}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="cycle" stroke="var(--text-secondary)" fontSize={10} /><YAxis stroke="var(--text-secondary)" fontSize={11} /><Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} /><Area type="monotone" dataKey="count" stroke="var(--accent-purple)" fill="var(--accent-purple)" fillOpacity={0.2} /></AreaChart>
          </ResponsiveContainer> : <div className="loading"><div className="spinner" /> Collecting...</div>}
        </div>
      </div>

      <div className="panel">
        <h2>Live Threat Feed <span className="badge">{threats.length} entries · updates every 10s</span></h2>
        {threats.length > 0 ? <div className="threat-table"><table>
          <thead><tr><th>#</th><th>Type</th><th>Source</th><th>Description</th><th>Score</th></tr></thead>
          <tbody>{threats.slice(0, 25).map((t, i) => (
            <tr key={i}>
              <td style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{i + 1}</td>
              <td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || 'threat'}</span></td>
              <td style={{ fontSize: 11 }}>{t.source}</td>
              <td style={{ maxWidth: 400, fontSize: 12 }}>{t.instruction?.slice(0, 120) || t.description?.slice(0, 120) || '-'}</td>
              <td>{t.cvss_score || '-'}</td>
            </tr>
          ))}</tbody>
        </table></div> : <div className="loading"><div className="spinner" /> Waiting for real-time data...</div>}
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Latest Model Versions <span className="badge">{models.length}</span></h2>
          {models.length > 0 ? <table><thead><tr><th>Cycle</th><th>Version</th><th>Samples</th><th>Time</th></tr></thead>
          <tbody>{models.slice(-10).reverse().map((m, i) => (
            <tr key={i}><td>#{m.cycle}</td><td style={{ color: 'var(--accent-cyan)' }}>{m.version}</td><td>{m.samples}</td><td style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{new Date(m.timestamp).toLocaleTimeString()}</td></tr>
          ))}</tbody></table> : <div className="loading"><div className="spinner" /> No models yet</div>}
        </div>
        <div className="panel">
          <h2>System Info</h2>
          <table><tbody>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Cycle Interval</td><td>Every 60 seconds</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Data Sources</td><td>10 simultaneous threat feeds</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Training Cloud</td><td>ModelScope (zero local GPU)</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Auto-Train</td><td>After each cycle with new data</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Dataset Format</td><td>Instruction-Response JSONL</td></tr>
            <tr><td style={{ color: 'var(--text-secondary)' }}>Hosting</td><td>Render.com (24/7 always-on)</td></tr>
          </tbody></table>
        </div>
      </div>
    </div>
  )
}
