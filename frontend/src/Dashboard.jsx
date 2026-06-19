import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts'

export default function Dashboard({ status }) {
  const [threats, setThreats] = useState([])
  const [models, setModels] = useState([])
  const [history, setHistory] = useState([])

  useEffect(() => {
    fetch('/api/threats?limit=20').then(r => r.json()).then(setThreats).catch(() => {})
    fetch('/api/models').then(r => r.json()).then(d => setModels(d.versions || [])).catch(() => {})
    const interval = setInterval(() => {
      fetch('/api/threats?limit=20').then(r => r.json()).then(setThreats).catch(() => {})
      fetch('/api/models').then(r => r.json()).then(d => setModels(d.versions || [])).catch(() => {})
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    fetch('/api/status').then(r => r.json()).then(s => {
      setHistory(prev => {
        const next = [...prev, {
          time: new Date().toLocaleTimeString(),
          threats: s.scraper?.total_scraped || 0,
          cycle: s.cycle || 0,
        }]
        return next.slice(-30)
      })
    }).catch(() => {})
  }, [status])

  const scrapeStats = status.scraper || {}
  const trainStats = status.training || {}
  const cycle = status.cycle || 0
  const totalScraped = scrapeStats.total_scraped || 0

  const typeCounts = {}
  threats.forEach(t => { const s = t.source || 'other'; typeCounts[s] = (typeCounts[s] || 0) + 1 })
  const chartData = Object.entries(typeCounts).map(([name, value]) => ({ name, value }))

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>AURA Dashboard</h1>
      <p style={{ color: 'var(--text-secondary)', marginBottom: 24, fontSize: 14 }}>
        Continuous cyber threat learning · Auto-train cycle every hour · ModelScope cloud GPU
      </p>

      <div className="dashboard-grid">
        <div className="stat-card">
          <div className="label">Learning Cycle</div>
          <div className="value" style={{ color: 'var(--accent-cyan)' }}>#{cycle}</div>
          <div className="sub">{cycle > 0 ? 'Active' : 'Starting...'} · Next in ~1h</div>
        </div>
        <div className="stat-card">
          <div className="label">Threats Collected</div>
          <div className="value" style={{ color: 'var(--accent-purple)' }}>{totalScraped}</div>
          <div className="sub">{threats.length} recent samples in memory</div>
        </div>
        <div className="stat-card">
          <div className="label">Model Versions</div>
          <div className="value" style={{ color: 'var(--accent-green)' }}>{trainStats.versions || 0}</div>
          <div className="sub">Pushed to ModelScope Hub</div>
        </div>
        <div className="stat-card">
          <div className="label">Training Status</div>
          <div className="value" style={{ color: trainStats.running ? 'var(--accent-yellow)' : 'var(--accent-green)', fontSize: 20 }}>
            {trainStats.running ? 'Training...' : 'Idle'}
          </div>
          <div className="sub">
            {trainStats.last_trained
              ? `Last: ${new Date(trainStats.last_trained).toLocaleString()}`
              : 'Waiting for first cycle'}
          </div>
        </div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Threat Sources Distribution</h2>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={11} />
                <YAxis stroke="var(--text-secondary)" fontSize={11} />
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} />
                <Bar dataKey="value" fill="var(--accent-cyan)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="loading"><div className="spinner" /> Waiting for data...</div>}
        </div>
        <div className="panel">
          <h2>Activity Over Time</h2>
          {history.length > 1 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={history}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="time" stroke="var(--text-secondary)" fontSize={10} />
                <YAxis stroke="var(--text-secondary)" fontSize={11} />
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }} />
                <Line type="monotone" dataKey="threats" stroke="var(--accent-cyan)" dot={false} strokeWidth={2} name="Threats" />
                <Line type="stepAfter" dataKey="cycle" stroke="var(--accent-purple)" dot={false} strokeWidth={2} name="Cycle" />
              </LineChart>
            </ResponsiveContainer>
          ) : <div className="loading"><div className="spinner" /> Collecting metrics...</div>}
        </div>
      </div>

      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <h2>Model Version History <span className="badge">{models.length} versions</span></h2>
          {models.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Cycle</th>
                  <th>Version</th>
                  <th>Samples</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {models.slice(-10).reverse().map((m, i) => (
                  <tr key={i}>
                    <td>#{m.cycle}</td>
                    <td style={{ color: 'var(--accent-cyan)' }}>{m.version}</td>
                    <td>{m.samples}</td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{new Date(m.timestamp).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="loading"><div className="spinner" /> No models yet</div>
          )}
        </div>
        <div className="panel">
          <h2>System Info</h2>
          <table>
            <tbody>
              <tr><td style={{ color: 'var(--text-secondary)' }}>Cloud Platform</td><td>ModelScope AI (MS-SWIFT)</td></tr>
              <tr><td style={{ color: 'var(--text-secondary)' }}>GPU Usage</td><td><span className="tag tag-clean">Zero (cloud only)</span></td></tr>
              <tr><td style={{ color: 'var(--text-secondary)' }}>Auto-Train Cycle</td><td>Every 1 hour</td></tr>
              <tr><td style={{ color: 'var(--text-secondary)' }}>Data Sources</td><td>NVD, ThreatFox, OTX, URLhaus</td></tr>
              <tr><td style={{ color: 'var(--text-secondary)' }}>Linux Commands</td><td>{'30+ cybersecurity commands'}</td></tr>
              <tr><td style={{ color: 'var(--text-secondary)' }}>Dataset Format</td><td>Instruction-Response (JSONL)</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <h2>Recent Threats <span className="badge">{threats.length} entries</span></h2>
        {threats.length > 0 ? (
          <div className="threat-table">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Description / Instruction</th>
                  <th>Source</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {threats.slice(0, 15).map((t, i) => (
                  <tr key={i}>
                    <td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || 'threat'}</span></td>
                    <td style={{ maxWidth: 400 }}>{t.instruction?.slice(0, 100) || t.description?.slice(0, 100) || '-'}</td>
                    <td>{t.source || '-'}</td>
                    <td>{t.cvss_score || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="loading"><div className="spinner" /> Waiting for first scrape cycle...</div>
        )}
      </div>
    </div>
  )
}
