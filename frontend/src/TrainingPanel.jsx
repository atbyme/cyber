import { useState, useEffect, useMemo, useCallback } from 'react'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const COLORS = ['#06b6d4','#8b5cf6','#f59e0b','#ef4444']

export default function TrainingPanel() {
  const [data, setData] = useState({ versions: [], datasets: [] })
  const [training, setTraining] = useState({})
  const [knowledge, setKnowledge] = useState({ cves: 0, iocs: 0, malware: 0, urls: 0, history: [] })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [sampleHistory, setSampleHistory] = useState([])

  const fetchAll = useCallback(() => {
    fetch('/api/train/status').then(r => r.json()).then(setTraining).catch(() => { setError('Failed to load training status') })
    fetch('/api/train/versions').then(r => r.json()).then(d => {
      setData(d)
      const versions = d.versions || []
      setSampleHistory(prev => {
        const pts = versions.filter(v => !prev.find(p => p.cycle === v.cycle)).map(v => ({ cycle: `#${v.cycle}`, samples: v.samples || 0, version: v.version }))
        return [...prev, ...pts].slice(-40)
      })
    }).catch(() => {})
    fetch('/api/knowledge').then(r => r.json()).then(setKnowledge).catch(() => {})
  }, [])

  useEffect(() => {
    fetchAll()
    const i = setInterval(fetchAll, 3000)
    return () => clearInterval(i)
  }, [fetchAll])

  const startTraining = async () => {
    setBusy(true)
    await fetch('/api/train/start', { method: 'POST' })
    setTimeout(() => { setBusy(false); fetchAll() }, 3000)
  }

  const versions = data.versions || []
  const t = training
  const k = knowledge
  const totalK = (k.cves || 0) + (k.iocs || 0) + (k.malware || 0) + (k.urls || 0)
  const totalSamples = t.samples || 0

  const knowledgeTypes = useMemo(() => [
    { name: 'CVEs', value: k.cves || 0 }, { name: 'IOCs', value: k.iocs || 0 },
    { name: 'Malware', value: k.malware || 0 }, { name: 'URLs', value: k.urls || 0 },
  ], [k])

  const latestVersion = versions.length > 0 ? versions[versions.length - 1] : null

  return (
    <div>
      {error && <div className="explain-bar" style={{borderColor:'var(--accent-yellow)'}}><span className="explain-icon">⚠</span><div style={{color:'var(--accent-yellow)'}}>{error}</div></div>}
      <div className="terminal-bar">
        <span className="glitch">AI TRAINING & MODEL MANAGEMENT — MODELScope CLOUD</span>
        <span className="blink">{t.running ? 'TRAINING ON GPU' : 'READY'}</span>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{totalSamples.toLocaleString()}</div>
          <div className="soc-stat-lbl">TOTAL SAMPLES</div>
          <div className="soc-stat-sub">{t.running ? 'Training...' : 'Trained'}</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{t.versions || versions.length || 0}</div>
          <div className="soc-stat-lbl">MODEL VERSIONS</div>
          <div className="soc-stat-sub">{t.last_trained ? new Date(t.last_trained).toLocaleDateString() : 'No versions'}</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{totalK.toLocaleString()}</div>
          <div className="soc-stat-lbl">KNOWLEDGE INPUT</div>
          <div className="soc-stat-sub">Training data</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{t.datasets || data.datasets?.length || 0}</div>
          <div className="soc-stat-lbl">DATASETS</div>
          <div className="soc-stat-sub">ModelScope Hub</div>
        </div>
      </div>

      <div className="filters-bar">
        <button className="btn btn-primary" onClick={startTraining} disabled={busy || t.running} style={{ fontSize: 11, padding: '6px 14px' }}>
          {t.running ? '⟳ TRAINING ON MODELScope CLOUD...' : busy ? 'BUSY' : 'TRAIN NOW'}
        </button>
        <span className="modelscope-badge">ModelScope Cloud GPU · Qwen2.5-7B-Instruct</span>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-secondary)' }}>
          {t.running ? '● Training active' : '○ Idle'} · Auto-train daily at 03:00 UTC
        </span>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">SAMPLE GROWTH <span className="chart-badge">{sampleHistory.length} versions</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sampleHistory.length > 0 ? sampleHistory : [{ cycle: '#0', samples: 0 }]}>
                <defs><linearGradient id="trainGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3}/><stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/></linearGradient></defs>
                <XAxis dataKey="cycle" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Area type="monotone" dataKey="samples" stroke="#8b5cf6" fill="url(#trainGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">KNOWLEDGE DISTRIBUTION <span className="chart-badge">{totalK.toLocaleString()} total</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={knowledgeTypes}>
                <XAxis dataKey="name" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {knowledgeTypes.map((e, i) => <Cell key={i} fill={COLORS[i]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="split-row">
        <div className="soc-panel half">
          <div className="soc-panel-header">MODEL VERSIONS <span className="soc-badge">{versions.length}</span></div>
          <div className="scroll-200">
            {versions.length > 0 ? (
              <table className="soc-table">
                <thead><tr><th>Cycle</th><th>Version</th><th>Samples</th><th>Hub</th><th>Time</th></tr></thead>
                <tbody>
                  {[...versions].reverse().slice(0, 20).map((v, i) => (
                    <tr key={i} className="soc-tr">
                      <td className="soc-idx">#{v.cycle}</td>
                      <td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{v.version}</td>
                      <td style={{ fontWeight: 600 }}>{(v.samples || 0).toLocaleString()}</td>
                      <td style={{ fontSize: 9, color: 'var(--accent-green)' }}>{v.hub_status || 'pushed'}</td>
                      <td className="soc-time">{new Date(v.t).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <div className="soc-empty">No versions yet — auto-training daily at 03:00 UTC</div>}
          </div>
        </div>
        <div className="soc-panel half">
          <div className="soc-panel-header">TRAINING RESOURCES</div>
          <table className="soc-table">
            <thead><tr><th>Resource</th><th>Details</th></tr></thead>
            <tbody>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Base Model</td><td style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>Qwen2.5-7B-Instruct</td></tr>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Platform</td><td style={{ fontWeight: 600, color: 'var(--accent-purple)' }}>ModelScope Cloud GPU</td></tr>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Framework</td><td style={{ fontWeight: 600, color: 'var(--accent-yellow)' }}>MS-SWIFT</td></tr>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Schedule</td><td style={{ fontWeight: 600 }}>Daily at 03:00 UTC</td></tr>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Pipeline</td><td style={{ fontWeight: 600 }}>Scrape → Clean → Format → Merge → Push → Train</td></tr>
              <tr className="soc-tr"><td style={{ color: 'var(--text-secondary)' }}>Data Sources</td><td style={{ fontWeight: 600 }}>19 threat sources + 99 Linux commands</td></tr>
            </tbody>
          </table>
          <div style={{ marginTop: 10 }}>
            <div className="soc-panel-header" style={{ fontSize: 10, borderBottom: 'none', paddingBottom: 0 }}>PIPELINE</div>
            <div className="soc-sources" style={{ marginTop: 4 }}>
              {[
                { label: 'SCRAPE', done: true, sub: '19 sources' },
                { label: 'CLEAN', done: true, sub: 'Filter' },
                { label: 'FORMAT', done: true, sub: 'Instruct' },
                { label: 'MERGE', done: true, sub: '+ Linux' },
                { label: 'PUSH', done: !!latestVersion, sub: 'Hub' },
                { label: 'TRAIN', done: !t.running, sub: t.running ? 'Running' : 'Ready' },
              ].map((p, i) => (
                <div key={i} className="soc-src-chip" style={p.done ? { borderColor: 'var(--accent-green)', background: 'rgba(16,185,129,0.08)' } : {}}>
                  <span style={{ fontSize: 9, fontWeight: 600 }}>{p.done ? '✓' : '⟳'}</span>
                  <span style={{ fontSize: 9, fontWeight: 600 }}>{p.label}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{p.sub}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {t.running && (
        <div className="soc-panel" style={{ marginTop: 14, borderColor: 'var(--accent-yellow)' }}>
          <div className="soc-panel-header" style={{ color: 'var(--accent-yellow)' }}>⟳ TRAINING ON MODELScope CLOUD GPU</div>
          <div className="progress-track" style={{ height: 6, marginBottom: 6 }}>
            <div className="progress-fill" style={{ width: '65%', background: 'linear-gradient(90deg, var(--accent-yellow), var(--accent-red))' }} />
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
            {totalSamples.toLocaleString()} samples → Qwen2.5-7B-Instruct via MS-SWIFT on ModelScope cloud GPU
          </div>
        </div>
      )}

      {versions.length > 0 && (
        <div className="soc-panel" style={{ marginTop: 14 }}>
          <div className="soc-panel-header">MODELScope HUB DATASETS <span className="soc-badge">{versions.length}</span></div>
          <div className="soc-sources">
            {[...versions].reverse().slice(0, 15).map((v, i) => (
              <div key={i} className="soc-src-chip" style={{ borderColor: 'rgba(139,92,246,0.3)' }}>
                <span className="soc-src-id">{v.version}</span>
                <span style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{(v.samples || 0).toLocaleString()} samples</span>
                <span style={{ fontSize: 8, color: 'var(--accent-green)' }}>{v.hub_status || 'pushed'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
