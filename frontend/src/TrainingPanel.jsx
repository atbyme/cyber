import { useState, useEffect } from 'react'

export default function TrainingPanel({ status }) {
  const [trainStatus, setTrainStatus] = useState({ running: false, total_samples: 0, last_trained: null, versions: 0, datasets: 0 })
  const [modelHistory, setModelHistory] = useState([])
  const [starting, setStarting] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    fetch('/api/train/status').then(r => r.json()).then(setTrainStatus).catch(() => {})
    fetch('/api/train/history').then(r => r.json()).then(d => setModelHistory(d.model_versions || [])).catch(() => {})
    const interval = setInterval(() => {
      fetch('/api/train/status').then(r => r.json()).then(setTrainStatus).catch(() => {})
      fetch('/api/train/history').then(r => r.json()).then(d => setModelHistory(d.model_versions || [])).catch(() => {})
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const startTraining = async () => {
    setStarting(true)
    setMessage('')
    try {
      const r = await fetch('/api/train/start', { method: 'POST' })
      const d = await r.json()
      setMessage(d.message)
    } catch { setMessage('Failed to start training') }
    finally { setStarting(false) }
  }

  const total = trainStatus.total_samples || 0
  const isRunning = trainStatus.running || status.training?.running
  const lastTrain = trainStatus.last_trained
  const versions = trainStatus.versions || 0
  const datasets = trainStatus.datasets || 0

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>AI Model Training</h1>

      <div className="dashboard-grid">
        <div className="stat-card">
          <div className="label">Latest Samples</div>
          <div className="value" style={{ color: 'var(--accent-purple)' }}>{total}</div>
          <div className="sub">Threat + Linux command merged</div>
        </div>
        <div className="stat-card">
          <div className="label">Status</div>
          <div className="value" style={{
            color: isRunning ? 'var(--accent-yellow)' : 'var(--accent-green)',
            fontSize: 20,
          }}>
            {isRunning ? 'Training Now' : 'Idle'}
          </div>
          <div className="sub">
            {lastTrain ? `Last: ${new Date(lastTrain).toLocaleString()}` : 'No training yet'}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Model Versions</div>
          <div className="value" style={{ color: 'var(--accent-cyan)' }}>{versions}</div>
          <div className="sub">Pushed to ModelScope Hub</div>
        </div>
        <div className="stat-card">
          <div className="label">Datasets Created</div>
          <div className="value" style={{ color: 'var(--accent-green)' }}>{datasets}</div>
          <div className="sub">Saved locally + cloud-ready</div>
        </div>
      </div>

      <div className="panel">
        <h2>Continuous Learning Pipeline</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 16, fontSize: 14 }}>
          AURA runs an automatic scrape → train → push cycle <strong>every hour</strong>.
          All training uses <strong>ModelScope cloud GPU</strong> — zero load on your laptop.
          Each cycle creates a new dataset version and pushes a fine-tuned model to the ModelScope Hub.
        </p>

        {isRunning && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 13, color: 'var(--text-secondary)' }}>
              <span>Preparing dataset & dispatching to ModelScope cloud...</span>
            </div>
            <div className="progress-bar">
              <div className="fill" style={{ width: '60%', animation: 'pulse 1.5s ease-in-out infinite' }} />
            </div>
            <style>{`@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }`}</style>
          </div>
        )}

        <div style={{ display: 'flex', gap: 12 }}>
          <button className="btn btn-primary" onClick={startTraining} disabled={isRunning || starting}>
            {isRunning ? 'Training in progress...' : starting ? 'Starting...' : 'Trigger Training Now'}
          </button>
        </div>
        {message && <p style={{ color: 'var(--accent-green)', marginTop: 12, fontSize: 14 }}>{message}</p>}
      </div>

      {modelHistory.length > 0 && (
        <div className="panel">
          <h2>Model Version History <span className="badge">{modelHistory.length} versions</span></h2>
          <div className="threat-table">
            <table>
              <thead>
                <tr>
                  <th>Cycle</th>
                  <th>Hub Model ID</th>
                  <th>Version Tag</th>
                  <th>Samples</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {modelHistory.slice().reverse().map((m, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--accent-cyan)' }}>#{m.cycle}</td>
                    <td style={{ fontSize: 12 }}>{m.hub_id}</td>
                    <td><span className="tag tag-cve">{m.version}</span></td>
                    <td>{m.samples}</td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{new Date(m.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <h2>Training Pipeline (Full Cycle)</h2>
        <ol style={{ color: 'var(--text-secondary)', lineHeight: 2.2, fontSize: 14, paddingLeft: 20 }}>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[Auto] Scrape</strong> — Collect threats from NVD, ThreatFox, OTX, URLhaus</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[Auto] Clean & Filter</strong> — Remove noise, dedup, format as instruction-response</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[Auto] Merge</strong> — Combine with {30}+ Linux cybersecurity commands knowledge base</li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[Auto] Prepare Dataset</strong> — Generate train.jsonl + valid.jsonl + MS-SWIFT config</li>
          <li><strong style={{ color: 'var(--accent-green)' }}>[Cloud] Train on ModelScope</strong> — <strong>Zero local GPU usage</strong>, runs on ModelScope cloud</li>
          <li><strong style={{ color: 'var(--accent-green)' }}>[Cloud] Push to Hub</strong> — Model saved as <code>aura-cyber/&lt;model&gt;-finetuned:v{Math.max(0, ...modelHistory.map(m => m.cycle)) + 1}</code></li>
          <li><strong style={{ color: 'var(--accent-cyan)' }}>[Loop] Repeat</strong> — Next cycle in 1 hour with fresh threat data</li>
        </ol>
      </div>

      <div className="panel">
        <h2>ModelScope Cloud Training Command</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 8, fontSize: 13 }}>
          Copy this command to run on ModelScope's free cloud GPU:
        </p>
        <pre>{`pip install ms-swift -U

# Run training (upload the dataset folder from ./datasets/)
swift train --config /path/to/swift_config.yaml

# Push to ModelScope Hub
swift export --ckpt_dir output \\
  --push_to_hub true \\
  --hub_model_id aura-cyber/<model>-finetuned

# Each cycle creates: aura-cyber/<model>-finetuned:v1, v2, v3...`}</pre>
      </div>
    </div>
  )
}
