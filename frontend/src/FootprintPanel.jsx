import { useState } from 'react'

export default function FootprintPanel() {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])

  const analyze = async () => {
    if (!target.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), scan_ports: true }),
      })
      const d = await r.json()
      setResult(d)
      setHistory(prev => [{ target: target.trim(), timestamp: new Date().toLocaleString(), result: d }, ...prev].slice(0, 20))
    } catch { setError('Analysis failed') }
    finally { setLoading(false) }
  }

  const handleKeyDown = (e) => { if (e.key === 'Enter') analyze() }

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Digital Footprint Analysis</h1>
      <div className="panel">
        <h2>Analyze Target</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 12, fontSize: 14 }}>
          Enter an IP address, domain, URL, or IOC to analyze its digital footprint, DNS records, WHOIS data, and threat intelligence.
        </p>
        <div className="analysis-form">
          <input
            type="text"
            placeholder="e.g., example.com, 8.8.8.8, or a suspicious URL"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <button className="btn btn-primary" onClick={analyze} disabled={loading || !target.trim()}>
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
        {error && <p style={{ color: 'var(--accent-red)', marginTop: 8 }}>{error}</p>}
      </div>

      {result && (
        <div className="panel">
          <h2>Results: {result.target}</h2>
          <pre>{JSON.stringify(result, null, 2)}</pre>
          {result.port_scan && result.port_scan.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h3 style={{ color: 'var(--accent-red)', marginBottom: 8, fontSize: 14 }}>Open Ports</h3>
              <table>
                <thead>
                  <tr><th>Port</th><th>State</th></tr>
                </thead>
                <tbody>
                  {result.port_scan.map((p, i) => (
                    <tr key={i}><td>{p.port}</td><td><span className="tag tag-malicious">{p.state}</span></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {history.length > 0 && (
        <div className="panel">
          <h2>Analysis History <span className="badge">{history.length} entries</span></h2>
          <div className="threat-table">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Threat</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => {
                  const r = h.result
                  const hasThreat = r?.threat?.malicious || r?.analysis?.ioc?.malicious
                  const analysis = r?.analysis || {}
                  const type = analysis.ip ? 'IP' : analysis.domain ? 'Domain' : analysis.url ? 'URL' : 'IOC'
                  return (
                    <tr key={i} onClick={() => { setTarget(h.target); setResult(r) }} style={{ cursor: 'pointer' }}>
                      <td style={{ color: 'var(--text-secondary)' }}>{h.timestamp}</td>
                      <td>{h.target}</td>
                      <td><span className="tag tag-cve">{type}</span></td>
                      <td>
                        {hasThreat
                          ? <span className="tag tag-malicious">Malicious</span>
                          : <span className="tag tag-clean">Clean</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
