import { useState, useEffect, useMemo } from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const REGIONS = [
  { name: 'North America', x: 18, y: 28 }, { name: 'South America', x: 25, y: 58 },
  { name: 'Europe', x: 48, y: 22 }, { name: 'Africa', x: 50, y: 52 },
  { name: 'Russia/CIS', x: 58, y: 18 }, { name: 'Middle East', x: 55, y: 35 },
  { name: 'South Asia', x: 62, y: 38 }, { name: 'China/EA', x: 72, y: 25 },
  { name: 'SE Asia', x: 70, y: 48 }, { name: 'Australia', x: 82, y: 60 },
]

export default function CompanyIntelPanel({ onThreatClick }) {
  const [company, setCompany] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [savedDatasets, setSavedDatasets] = useState([])
  const [activeTab, setActiveTab] = useState('recon')
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('aura_company_history') || '[]') } catch { return [] }
  })
  const [error, setError] = useState(null)
  const [topCompanies, setTopCompanies] = useState([])
  const [topLoading, setTopLoading] = useState(false)
  const [selectedTop, setSelectedTop] = useState(null)

  useEffect(() => {
    try {
      const saved = localStorage.getItem('aura_company_datasets')
      if (saved) setSavedDatasets(JSON.parse(saved))
    } catch {}
  }, [])

  useEffect(() => {
    try { localStorage.setItem('aura_company_history', JSON.stringify(history.slice(0, 100))) } catch {}
  }, [history])

  useEffect(() => {
    try { localStorage.setItem('aura_company_datasets', JSON.stringify(savedDatasets.slice(0, 50))) } catch {}
  }, [savedDatasets])

  useEffect(() => {
    const fetchTop = async () => {
      try { const r = await fetch('/api/companies/top'); const d = await r.json(); setTopCompanies(d.companies || []) } catch {}
    }
    fetchTop()
    const i = setInterval(fetchTop, 4000)
    return () => clearInterval(i)
  }, [])

  const analyze = async () => {
    if (!company.trim()) return
    setLoading(true)
    setError(null)
    try {
      const r = await fetch('/api/company-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ company: company.trim() }),
      })
      if (!r.ok) { setError(`Server error: ${r.status}`); setLoading(false); return }
      const data = await r.json()
      if (!data || Object.keys(data).length === 0) { setError('Empty response from server'); setLoading(false); return }
      setResult(data)
      const entry = { company: company.trim(), timestamp: new Date().toISOString(), ...data }
      setHistory(p => [entry, ...p.filter(h => h.company !== company.trim())].slice(0, 100))
    } catch (e) { setError(`Network error: ${e.message}`) }
    setLoading(false)
  }

  const saveDataset = () => {
    if (!result) return
    const ds = {
      id: Date.now(), company: result.company, date: new Date().toISOString(),
      data: JSON.stringify(result),
      samples: (result.total_domains || 0) + (result.total_ports || 0) + (result.total_threats || 0) + (result.total_breaches || 0),
    }
    setSavedDatasets(p => [ds, ...p.filter(d => d.company !== result.company)].slice(0, 50))
  }

  const replayHistory = (entry) => {
    setCompany(entry.company)
    setResult(entry)
    setActiveTab('recon')
  }

  const COLORS = ['#06b6d4', '#8b5cf6', '#f59e0b', '#ef4444']

  const domainChart = useMemo(() => {
    if (!result?.domains) return []
    return result.domains.slice(0, 10).map(d => ({
      name: (d.domain || '?').slice(0, 18),
      ips: d.ips?.length || 0,
      malicious: d.malicious ? 1 : 0,
    }))
  }, [result])

  const portPie = useMemo(() => {
    if (!result?.open_ports) return []
    const counts = {}
    result.open_ports.forEach(p => { const key = `Port ${p.port}`; counts[key] = (counts[key] || 0) + 1 })
    return Object.entries(counts).slice(0, 8).map(([n, v]) => ({ name: n, value: v }))
  }, [result])

  const mapDots = useMemo(() => {
    if (!result?.open_ports) return []
    const seen = new Set()
    return result.open_ports.filter(p => {
      if (seen.has(p.ip)) return false
      seen.add(p.ip)
      return true
    }).slice(0, 12).map((p, i) => ({
      x: 15 + Math.random() * 70, y: 15 + Math.random() * 45,
      ip: p.ip, port: p.port, region: REGIONS[i % REGIONS.length].name,
    }))
  }, [result])

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">COMPANY THREAT INTELLIGENCE BUREAU</span>
        <span className="blink">{loading ? '⟳ SCANNING INTERNET...' : `${history.length} HISTORIES · ${savedDatasets.length} DATASETS`}</span>
      </div>

      <div className="charts-row" style={{ marginBottom: 8 }}>
        <div className="chart-container" style={{ flex: 1.5 }}>
          <div className="chart-title">GLOBAL ASSET MAP <span className="chart-badge">{mapDots.length} locations</span></div>
          <div className="map-container" style={{ height: 100 }}>
            <svg viewBox="0 0 100 55" className="world-map">
              <ellipse cx="20" cy="24" rx="12" ry="8" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
              <ellipse cx="50" cy="28" rx="25" ry="14" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
              <ellipse cx="72" cy="28" rx="18" ry="12" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
              <ellipse cx="45" cy="38" rx="18" ry="8" fill="none" stroke="#2d3a50" strokeWidth="0.3" />
              {REGIONS.map((r, i) => (
                <text key={i} x={r.x} y={r.y + 6} textAnchor="middle" fill="#2d3a50" fontSize={2} opacity={0.5}>{r.name}</text>
              ))}
              {mapDots.map((d, i) => (
                <g key={i}>
                  <circle cx={d.x} cy={d.y} r={2} fill="#06b6d4" opacity={0.8} />
                  <text x={d.x} y={d.y + 5} textAnchor="middle" fill="#06b6d4" fontSize={2.5} opacity={0.6}>{d.ip}:{d.port}</text>
                </g>
              ))}
            </svg>
          </div>
        </div>
      </div>

      <div className="filters-bar">
        <button className={`filter-btn ${activeTab === 'recon' ? 'active' : ''}`} onClick={() => setActiveTab('recon')}>RECON</button>
        <button className={`filter-btn ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}>THREATS</button>
        <button className={`filter-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>HISTORY ({history.length})</button>
        <button className={`filter-btn ${activeTab === 'datasets' ? 'active' : ''}`} onClick={() => setActiveTab('datasets')}>DATASETS ({savedDatasets.length})</button>
        <button className={`filter-btn ${activeTab === 'top10' ? 'active' : ''}`} onClick={() => setActiveTab('top10')}>TOP 10</button>
        <input className="filter-search" style={{ flex: 1, fontSize: 13, padding: '8px 12px' }}
          placeholder="Company name (google, microsoft, tesla, amazon, oracle...)" value={company}
          onChange={e => setCompany(e.target.value)} onKeyDown={e => e.key === 'Enter' && analyze()} />
        <button className="btn btn-primary" onClick={analyze} disabled={loading || !company.trim()}>
          {loading ? '⟳ RECON...' : 'FULL RECON'}
        </button>
      </div>

      {error && (
        <div className="soc-panel" style={{ borderLeft: '3px solid var(--accent-red)' }}>
          <div className="soc-panel-header">ERROR</div>
          <div className="soc-empty" style={{ color: 'var(--accent-red)' }}>{error}</div>
        </div>
      )}

      {activeTab === 'recon' && (
        <>
          {result && (
            <>
              <div className="soc-stats">
                <div className="soc-stat critical">
                  <div className="soc-stat-val">{result.total_domains || 0}</div>
                  <div className="soc-stat-lbl">DOMAINS</div>
                  <div className="soc-stat-sub">WHOIS + crt.sh</div>
                </div>
                <div className="soc-stat high">
                  <div className="soc-stat-val">{result.total_ports || 0}</div>
                  <div className="soc-stat-lbl">OPEN PORTS</div>
                  <div className="soc-stat-sub">Shodan InternetDB</div>
                </div>
                <div className="soc-stat medium">
                  <div className="soc-stat-val">{result.total_threats || 0}</div>
                  <div className="soc-stat-lbl">THREATS</div>
                  <div className="soc-stat-sub">Vulns + Malicious</div>
                </div>
                <div className="soc-stat low">
                  <div className="soc-stat-val">{result.total_breaches || 0}</div>
                  <div className="soc-stat-lbl">BREACHES</div>
                  <div className="soc-stat-sub">Data leaks</div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
                <span className="modelscope-badge" style={{ cursor: 'pointer' }} onClick={saveDataset}>
                  {savedDatasets.some(d => d.company === result.company) ? '✓ SAVED' : '+ SAVE DATASET'}
                </span>
                <span className="modelscope-badge">{result.samples || 0} samples for AI training</span>
                <span className="modelscope-badge">{new Date(result.timestamp).toLocaleString()}</span>
              </div>

              <div className="charts-row">
                <div className="chart-container">
                  <div className="chart-title">DOMAINS & IPS</div>
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={domainChart.length > 0 ? domainChart : [{ name: 'none', ips: 0 }]} layout="vertical">
                        <XAxis type="number" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                        <YAxis type="category" dataKey="name" tick={{ fontSize: 7, fill: '#94a3b8' }} width={80} />
                        <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                        <Bar dataKey="ips" fill="#06b6d4" radius={[0, 3, 3, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="chart-container">
                  <div className="chart-title">OPEN PORTS</div>
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={portPie.length > 0 ? portPie : [{ name: 'No data', value: 1 }]} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} innerRadius={30}>
                          {portPie.map((_, i) => <Cell key={i} fill={COLORS[i % 4]} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              <div className="split-row">
                <div className="soc-panel half">
                  <div className="soc-panel-header">DISCOVERED ASSETS <span className="soc-badge">{(result.domains || []).length}</span></div>
                  <div className="scroll-200">
                    {(result.domains || []).length > 0 ? (
                      <table className="soc-table">
                        <thead><tr><th>Domain</th><th>IPs</th><th>Status</th><th>Info</th></tr></thead>
                        <tbody>
                          {(result.domains || []).map((d, i) => (
                            <tr key={i} className="soc-tr">
                              <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontSize: 10 }}>{d.domain || '?'}</td>
                              <td style={{ fontSize: 9 }}>{(d.ips || []).slice(0, 3).join(', ') || '—'}</td>
                              <td>{d.malicious ? <span className="soc-tag cve">MALICIOUS</span> : <span className="soc-tag info">CLEAN</span>}</td>
                              <td style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{d.whois?.registrar?.slice(0, 20) || d.subdomain ? 'sub' : '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : <div className="soc-empty">No domains resolved — company name may not match domain TLDs</div>}
                  </div>
                </div>
                <div className="soc-panel half">
                  <div className="soc-panel-header">EXPOSED PORTS & SERVICES</div>
                  <div className="soc-sources">
                    {(result.open_ports || []).length > 0 ? (
                      (result.open_ports || []).slice(0, 30).map((p, i) => (
                        <div key={i} className="soc-src-chip" style={{ borderColor: [21,22,23,25,80,443,445,1433,3306,3389,6379,27017].includes(p.port) ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>
                          <span className="soc-src-id">{p.ip}</span>
                          <span style={{ fontSize: 9, color: 'var(--accent-cyan)' }}>:{p.port}</span>
                        </div>
                      ))
                    ) : <div className="soc-empty">No open ports detected via Shodan InternetDB</div>}
                  </div>
                </div>
              </div>

              <div className="soc-panel" style={{ marginTop: 14 }}>
                <div className="soc-panel-header">RAW DATA <span className="soc-badge sec">JSON</span></div>
                <pre style={{ fontSize: 9, maxHeight: 120, overflow: 'auto', color: 'var(--text-secondary)', background: 'var(--bg-primary)', padding: 10, borderRadius: 4 }}>
                  {JSON.stringify(result, null, 2).slice(0, 3000)}
                </pre>
              </div>
            </>
          )}
          {!result && !loading && !error && (
            <div className="soc-panel">
              <div className="soc-panel-header">COMPANY THREAT INTELLIGENCE — WHOLE INTERNET RECON</div>
              <div className="soc-empty" style={{ textAlign: 'left', padding: '20px 16px', lineHeight: 1.8 }}>
                <strong style={{ color: 'var(--accent-cyan)' }}>GLOBAL COMPANY RECONNAISSANCE SYSTEM</strong><br />
                Enter any company name above to perform full passive internet-wide reconnaissance.<br /><br />
                <strong>Capabilities:</strong><br />
                • WHOIS — registrar, org, country, dates<br />
                • DNS — all A records, IPs<br />
                • Shodan InternetDB — open ports, CVEs, vulnerabilities<br />
                • Certificate Transparency — subdomain discovery<br />
                • Threat intelligence — ThreatFox + AbuseIPDB check<br />
                • Data breach detection via email patterns<br /><br />
                <strong>History:</strong> All recon results saved automatically in browser localStorage
              </div>
            </div>
          )}
        </>
      )}

      {activeTab === 'threats' && (
        <div className="soc-panel">
          <div className="soc-panel-header">COMPANY THREAT LANDSCAPE</div>
          {(result?.threats || []).length > 0 ? (
            <table className="soc-table">
              <thead><tr><th>Target</th><th>Source</th><th>Details</th></tr></thead>
              <tbody>
                {(result?.threats || []).map((t, i) => (
                  <tr key={i} className="soc-tr">
                    <td style={{ fontFamily: 'monospace', fontSize: 10 }}>{t.ip || t.domain || '—'}</td>
                    <td><span className="soc-tag cve">{t.source || 'threatfox'}</span></td>
                    <td style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{t.vulns ? t.vulns.slice(0, 5).join(', ') : t.sources?.join(', ') || 'malicious'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="soc-empty">Run a company recon first to see threats — or no threats found for this company</div>
          )}
        </div>
      )}

      {activeTab === 'history' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            COMPANY INTEL HISTORY <span className="soc-badge">{history.length} entries</span>
            <span className="soc-badge sec">BROWSER LOCALSTORAGE</span>
            <button className="btn btn-primary" style={{ marginLeft: 'auto', fontSize: 9, padding: '2px 8px' }}
              onClick={() => { setHistory([]); localStorage.removeItem('aura_company_history') }}>
              CLEAR ALL
            </button>
          </div>
          {history.length > 0 ? (
            <table className="soc-table">
              <thead><tr><th>Company</th><th>Domains</th><th>Ports</th><th>Threats</th><th>Breaches</th><th>Samples</th><th>Time</th></tr></thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i} className="soc-tr" style={{ cursor: 'pointer' }} onClick={() => replayHistory(h)}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontWeight: 600 }}>{h.company}</td>
                    <td>{h.total_domains || 0}</td>
                    <td>{h.total_ports || 0}</td>
                    <td><span className={`soc-tag ${(h.total_threats || 0) > 0 ? 'cve' : 'info'}`}>{h.total_threats || 0}</span></td>
                    <td><span className={`soc-tag ${(h.total_breaches || 0) > 0 ? 'url' : 'info'}`}>{h.total_breaches || 0}</span></td>
                    <td style={{ fontWeight: 600 }}>{h.samples || 0}</td>
                    <td className="soc-time">{new Date(h.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="soc-empty">No recon history yet. Run company recon — results auto-save to browser storage</div>
          )}
        </div>
      )}

      {activeTab === 'datasets' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            COMPANY INTELLIGENCE DATASETS <span className="soc-badge">{savedDatasets.length}</span>
            <span className="soc-badge sec">FOR AI TRAINING</span>
          </div>
          {savedDatasets.length > 0 ? (
            <table className="soc-table">
              <thead><tr><th>Company</th><th>Samples</th><th>Date</th><th>Train</th></tr></thead>
              <tbody>
                {savedDatasets.map((ds, i) => (
                  <tr key={ds.id} className="soc-tr">
                    <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontWeight: 600 }}>{ds.company}</td>
                    <td>{ds.samples || '—'}</td>
                    <td className="soc-time">{new Date(ds.date).toLocaleString()}</td>
                    <td>
                      <button className="btn btn-primary" style={{ fontSize: 9, padding: '2px 8px' }}
                        onClick={() => fetch('/api/train/start', { method: 'POST' }).then(() => alert('Training triggered on ModelScope Cloud GPU!'))}>
                        TRAIN AI
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="soc-empty">No datasets saved. Run company recon → click "Save Dataset"</div>
          )}
        </div>
      )}

      {activeTab === 'top10' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            WORLD TOP 10 COMPANIES — LIVE THREAT SIMULATION
            <span className="soc-badge">LIVE</span>
            <span className="soc-badge sec">UPDATES 4S</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {topCompanies.map(c => (
              <div key={c.rank} className="soc-src-chip" style={{ cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch', padding: '8px 10px',
                borderColor: c.risk === 'critical' ? 'var(--accent-red)' : c.risk === 'high' ? 'var(--accent-yellow)' : c.risk === 'medium' ? 'var(--accent-cyan)' : 'var(--accent-green)' }}
                onClick={() => {
                  setCompany(c.name.split(' (')[0]); setActiveTab('recon')
                  setTimeout(() => document.querySelector('.filter-search')?.focus(), 100)
                }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
                  <span className="soc-src-id" style={{ fontSize: 9, minWidth: 20 }}>#{c.rank}</span>
                  <span style={{ fontWeight: 600, fontSize: 10 }}>{c.name}</span>
                  <span className={`soc-tag ${c.risk === 'critical' ? 'cve' : c.risk === 'high' ? 'url' : 'info'}`} style={{ fontSize: 7 }}>{c.risk.toUpperCase()}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{c.sector}</span>
                  <span style={{ fontSize: 8, color: 'var(--accent-cyan)' }}>{c.market_cap}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{c.country}</span>
                  <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, fontSize: 8 }}>
                    <span style={{ color: 'var(--accent-red)' }}>⚠ {c.threats || 0}</span>
                    <span style={{ color: 'var(--accent-yellow)' }}>⚔ {c.attacks || 0}</span>
                    <span style={{ color: 'var(--accent-purple)' }}>🔓 {c.breaches || 0}</span>
                    <span style={{ color: 'var(--accent-cyan)' }}>🔌 {c.ports || 0}</span>
                  </div>
                </div>
                <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginTop: 4, display: 'flex', gap: 12 }}>
                  <span><strong>Ticker:</strong> {c.ticker}</span>
                  <span><strong>CEO:</strong> {c.ceo}</span>
                  <span><strong>Employees:</strong> {c.employees?.toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
