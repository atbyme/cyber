import { useState, useEffect } from 'react'

export default function TrainingPanel({ status }) {
  const [trainStatus, setTrainStatus] = useState({})
  const [modelHistory, setModelHistory] = useState([])
  const [knowledge, setKnowledge] = useState({})
  const [starting, setStarting] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    const f = () => {
      fetch('/api/train/status').then(r => r.json()).then(setTrainStatus).catch(() => {})
      fetch('/api/train/history').then(r => r.json()).then(d => setModelHistory(d.model_versions || [])).catch(() => {})
      fetch('/api/knowledge').then(r => r.json()).then(setKnowledge).catch(() => {})
    }
    f()
    const i = setInterval(f, 8000)
    return () => clearInterval(i)
  }, [])

  const startTraining = async () => {
    setStarting(true); setMessage('')
    try { const r = await fetch('/api/train/start', { method: 'POST' }); const d = await r.json(); setMessage(d.message) }
    catch { setMessage('Failed') }
    finally { setStarting(false) }
  }

  const ts = trainStatus
  const models = modelHistory
  const k = knowledge
  const totalSamples = k.total_samples || 0
  const isRunning = ts.running || status.training?.running
  const verCount = ts.versions || models.length

  const resourceTotal = (k.unique_cves || 0) + (k.unique_iocs || 0) + (k.unique_malware || 0) + (k.unique_urls || 0)

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>AI Training Pipeline</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Training on ALL internet resources · {verCount} model versions · ModelScope cloud GPU (zero local)
      </p>

      <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="stat-card"><div className="label">Model Versions</div><div className="value" style={{ color: 'var(--accent-cyan)' }}>{verCount}</div><div className="sub">Pushed to ModelScope Hub</div></div>
        <div className="stat-card"><div className="label">Training Samples</div><div className="value" style={{ color: 'var(--accent-purple)' }}>{(ts.total_samples || totalSamples).toLocaleString()}</div><div className="sub">Merged threat + Linux data</div></div>
        <div className="stat-card"><div className="label">Status</div><div className="value" style={{ color: isRunning ? 'var(--accent-yellow)' : 'var(--accent-green)', fontSize: 20 }}>{isRunning ? 'Training Cloud' : 'Ready'}</div><div className="sub">{ts.last_trained ? new Date(ts.last_trained).toLocaleString() : 'Awaiting data'}</div></div>
        <div className="stat-card"><div className="label">Cloud Platform</div><div className="value" style={{ color: 'var(--accent-cyan)', fontSize: 18 }}>ModelScope</div><div className="sub">MS-SWIFT · Zero local GPU</div></div>
      </div>

      <div className="panel">
        <h2>All Training Resources</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 12, fontSize: 13 }}>The AI trains on ALL collected internet intelligence — not limited to 1-2 sources:</p>
        <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 0 }}>
          <div style={{ textAlign: 'center', padding: 12, background: 'var(--bg-hover)', borderRadius: 8 }}><div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-red)' }}>{k.unique_cves || 0}</div><div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>CVEs</div></div>
          <div style={{ textAlign: 'center', padding: 12, background: 'var(--bg-hover)', borderRadius: 8 }}><div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-yellow)' }}>{k.unique_iocs || 0}</div><div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>IOCs</div></div>
          <div style={{ textAlign: 'center', padding: 12, background: 'var(--bg-hover)', borderRadius: 8 }}><div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-cyan)' }}>{k.unique_malware || 0}</div><div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Malware</div></div>
          <div style={{ textAlign: 'center', padding: 12, background: 'var(--bg-hover)', borderRadius: 8 }}><div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-purple)' }}>{k.unique_urls || 0}</div><div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>URLs</div></div>
          <div style={{ textAlign: 'center', padding: 12, background: 'var(--bg-hover)', borderRadius: 8 }}><div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-green)' }}>31</div><div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Linux Commands</div></div>
        </div>
      </div>

      <div className="panel">
        <h2>Automated Training Pipeline</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 16, fontSize: 13 }}>
          Every research cycle automatically creates a dataset and dispatches to ModelScope cloud for training.
        </p>
        {isRunning && <div style={{ marginBottom: 16 }}><div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 13, color: 'var(--text-secondary)' }}><span>Dispatching to ModelScope cloud...</span></div><div className="progress-bar"><div className="fill" style={{ width: '60%' }} /></div></div>}
        <div style={{ display: 'flex', gap: 12 }}>
          <button className="btn btn-primary" onClick={startTraining} disabled={isRunning || starting}>
            {isRunning ? 'Training on Cloud...' : starting ? 'Starting...' : 'Manual Train Now'}
          </button>
        </div>
        {message && <p style={{ color: 'var(--accent-green)', marginTop: 12, fontSize: 14 }}>{message}</p>}
      </div>

      {models.length > 0 && <div className="panel">
        <h2>Model Version History <span className="badge">{models.length} versions</span></h2>
        <div className="threat-table"><table>
          <thead><tr><th>Cycle</th><th>Hub Model ID</th><th>Version</th><th>Samples</th><th>Time</th></tr></thead>
          <tbody>{models.slice().reverse().map((m, i) => (
            <tr key={i}>
              <td style={{ color: 'var(--accent-cyan)' }}>#{m.cycle}</td>
              <td style={{ fontSize: 11 }}>{m.hub_id}</td>
              <td><span className="tag tag-cve">{m.version}</span></td>
              <td>{m.samples}</td>
              <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{new Date(m.timestamp).toLocaleString()}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </div>}

      <div className="panel">
        <h2>Full Training Pipeline</h2>
        <ol style={{ color: 'var(--text-secondary)', lineHeight: 2.4, fontSize: 14, paddingLeft: 20 }}>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[PASSIVE] Real-time Research</strong> — Lightweight scan every 3min (ThreatFox, URLhaus, PhishTank, Feodo, SSLBL)</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[DEEP] Full Internet Scan</strong> — Every 2 hours, all 18 sources including NVD, AlienVault, CISA KEV, crt.sh, MalwareBazaar</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[FILTER] Clean & Dedup</strong> — Remove noise, format as instruction-response pairs</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[MERGE] All Resources</strong> — CVEs + IOCs + Malware + URLs + Linux commands (31) + threat pulses</li>
          <li><strong style={{ color: 'var(--accent-green)' }}>[CLOUD] Train on ModelScope</strong> — <strong>Zero local GPU</strong>, runs entirely on ModelScope cloud infrastructure</li>
          <li><strong style={{ color: 'var(--accent-green)' }}>[HUB] Push to ModelScope</strong> — Dataset + model saved as <code>aura-cyber/&lt;model&gt;-finetuned:v{models.length + 1}</code></li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[LOOP] Continuous</strong> — Never-ending: research → learn → train → improve → repeat</li>
        </ol>
      </div>

      <div className="panel">
        <h2>Cloud Training Command (ModelScope)</h2>
        <pre>{`# Run on ModelScope free cloud GPU:
pip install ms-swift -U

# Train with latest dataset:
swift train --config /path/to/swift_config.yaml

# Push to Hub:
swift export --ckpt_dir output \\
  --push_to_hub true \\
  --hub_model_id aura-cyber/<model>-finetuned

# Each cycle auto-creates: aura-cyber/<model>-finetuned:v1, v2, v3...`}</pre>
      </div>
    </div>
  )
}
