import { useState, useEffect, useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const AGENCIES = [
  { id: 'nsa', name: 'NSA', full: 'National Security Agency', country: 'USA', color: '#ef4444',
    focus: 'Mass surveillance, SIGINT, cyber warfare', status: 'ACTIVE', threat: 'extreme',
    knownOps: ['PRISM', 'EternalBlue', 'Stuxnet (co-op)', 'CNE global ops'],
    tactics: ['Zero-day stockpile', 'Crypto backdoors', 'Fiber tapping', 'Mass metadata collection'],
    targets: ['Global comms', 'Chinese govt', 'Russian military', 'Terror networks'],
    tools: ['EternalBlue', 'DoublePulsar', 'ANT catalog', 'QUANTUM'],
    lastSeen: '2025-06-19', footprint: 8942, agents: 'Unknown (classified)', srcPattern: ['us', 'nsa', 'usa'] },
  { id: 'mossad', name: 'Mossad', full: 'Institute for Intelligence and Special Operations', country: 'Israel', color: '#06b6d4',
    focus: 'Cyber espionage, assassination, covert ops', status: 'ACTIVE', threat: 'extreme',
    knownOps: ['Stuxnet (with NSA)', 'Flame malware', 'Duqu', 'Operation Olympic Games', 'Pegasus'],
    tactics: ['Zero-day exploits', 'Physical access', 'Agent infiltration', 'Psychological ops'],
    targets: ['Iran nuclear', 'Hezbollah', 'Syrian air defense', 'Hamas leadership'],
    tools: ['Pegasus', 'Flame', 'Duqu', 'Stuxnet'],
    lastSeen: '2025-06-19', footprint: 6712, agents: '~80 known field officers', srcPattern: ['il', 'israel', 'mossad'] },
  { id: 'gru', name: 'GRU', full: 'Main Intelligence Directorate', country: 'Russia', color: '#ec4899',
    focus: 'Destructive malware, disinformation, military intel', status: 'ACTIVE', threat: 'extreme',
    knownOps: ['NotPetya', 'DNC hack 2016', 'Olympic Destroyer', 'Buccaneer', 'SolarWinds (co-op)'],
    tactics: ['Destructive malware', 'Disinformation campaigns', 'SSR (Sandworm)', 'Cyber warfare'],
    targets: ['Ukraine infrastructure', 'Western elections', 'Olympics', 'Chemical weapons orgs'],
    tools: ['NotPetya', 'BlackEnergy', 'Industroyer', 'VPNFilter'],
    lastSeen: '2025-06-18', footprint: 7832, agents: '~300 GRU cyber units', srcPattern: ['ru', 'russia', 'gru'] },
  { id: 'msrc', name: 'MSS', full: 'Ministry of State Security', country: 'China', color: '#f97316',
    focus: 'Industrial espionage, IP theft, persistent access', status: 'ACTIVE', threat: 'high',
    knownOps: ['APT1', 'APT10', 'SolarWinds (alleged)', 'Hafnium Exchange', 'Salt Typhoon'],
    tactics: ['Supply chain attacks', 'Zero-day exploitation', 'Persistent espionage', 'IP theft'],
    targets: ['US defense contractors', 'Taiwan govt', 'Tech companies', 'Research institutions'],
    tools: ['PlugX', 'Gh0st RAT', 'ShadowPad', 'Titanium'],
    lastSeen: '2025-06-19', footprint: 12104, agents: '~400 cyber warfare officers', srcPattern: ['cn', 'china', 'msrc'] },
  { id: 'gchq', name: 'GCHQ', full: 'Government Communications Headquarters', country: 'UK', color: '#8b5cf6',
    focus: 'SIGINT, cyber defense, fiber tapping', status: 'ACTIVE', threat: 'high',
    knownOps: ['Tempora', 'PRISM partner', 'Cyber defense ops', 'Skynet AI'],
    tactics: ['Fiber optic tapping', 'SIGINT sharing (5-eyes)', 'AI analysis', 'Cyber defense'],
    targets: ['Terror networks', 'Russian intel', 'Chinese espionage', 'Organized crime'],
    tools: ['Skynet (AI)', 'Tempora probes', 'CNE tools'],
    lastSeen: '2025-06-17', footprint: 4532, agents: '~250 analysts', srcPattern: ['uk', 'gchq', 'british'] },
  { id: 'raw', name: 'RAW', full: 'Research & Analysis Wing', country: 'India', color: '#f59e0b',
    focus: 'Foreign intel, counter-terror, dark web ops', status: 'ACTIVE', threat: 'medium',
    knownOps: ['Operation Smiling Buddha', 'Covid cyber ops', 'Anti-terror networks', 'Naxal monitoring'],
    tactics: ['Hacktivist proxies', 'Dark web monitoring', 'Social engineering', 'Network infiltration'],
    targets: ['Pakistani military', 'Chinese PLA', 'Naxal networks', 'Terror financing'],
    tools: ['Custom RATs', 'Android spyware', 'Network sniffers'],
    lastSeen: '2025-06-15', footprint: 3210, agents: '~200 officers', srcPattern: ['in', 'india', 'raw'] },
  { id: 'isi', name: 'ISI', full: 'Inter-Services Intelligence', country: 'Pakistan', color: '#10b981',
    focus: 'Military intel, APT ops, regional influence', status: 'ACTIVE', threat: 'high',
    knownOps: ['Operation Panther', 'APT37 (ScarletCrow)', 'Transparent Tribe', 'Kashmir ops'],
    tactics: ['Spear phishing', 'Android malware', 'RAT deployment', 'Social media influence'],
    targets: ['Indian defense', 'Afghan govt', 'Diplomatic missions', 'Kashmir activists'],
    tools: ['Crimson RAT', 'Pegasus (alleged)', 'AndroRAT', 'DroidJack'],
    lastSeen: '2025-06-18', footprint: 2890, agents: '~150 cyber operators', srcPattern: ['pk', 'pakistan', 'isi'] },
]

const MAJOR_ATTACKS = [
  { year: '2010', name: 'Stuxnet', actor: 'NSA + Mossad', target: 'Iran nuclear centrifuges', impact: 'Destroyed 1,000+ centrifuges', method: 'Zero-day USB spread', severity: 'critical', agencyId: ['nsa','mossad'] },
  { year: '2012', name: 'Flame', actor: 'Mossad + NSA', target: 'Iranian oil ministry', impact: 'Mass data theft, 5+ years undetected', method: 'USB + network worm', severity: 'critical', agencyId: ['mossad','nsa'] },
  { year: '2015', name: 'Ukraine Power Grid', actor: 'GRU (Sandworm)', target: 'Ukrainian power companies', impact: '230,000 without power', method: 'BlackEnergy + ICS exploitation', severity: 'critical', agencyId: ['gru'] },
  { year: '2016', name: 'DNC Hack', actor: 'GRU (APT28)', target: 'Democratic National Committee', impact: 'Email leaks, US election interference', method: 'Spear phishing + X-Agent', severity: 'critical', agencyId: ['gru'] },
  { year: '2017', name: 'NotPetya', actor: 'GRU (Sandworm)', target: 'Ukraine, global spread', impact: '$10B+ damages, Maersk, Merck, FedEx', method: 'MEDoc supply chain + EternalBlue', severity: 'critical', agencyId: ['gru'] },
  { year: '2018', name: 'Olympic Destroyer', actor: 'GRU', target: 'PyeongChang Winter Olympics', impact: 'Network shutdown during opening', method: 'Destructive malware + false flags', severity: 'high', agencyId: ['gru'] },
  { year: '2020', name: 'SolarWinds', actor: 'Cooperative (Russian intel)', target: 'US govt, 18,000+ organizations', impact: 'Supply chain backdoor, months undetected', method: 'Trojanized Orion update', severity: 'critical', agencyId: ['gru'] },
  { year: '2021', name: 'Hafnium Exchange', actor: 'MSS (China)', target: '30,000+ US orgs', impact: 'Email server backdoors', method: 'ProxyLogon zero-day', severity: 'critical', agencyId: ['msrc'] },
  { year: '2022', name: 'Ukraine Cyber War', actor: 'GRU (multiple units)', target: 'Ukraine infrastructure', impact: 'Viasat modem wipe, power grid hacks', method: 'Wiper malware + DDoS', severity: 'critical', agencyId: ['gru'] },
  { year: '2025', name: 'Salt Typhoon', actor: 'MSS (China)', target: 'US telecom networks', impact: 'Comms intercept, 8+ months dwell', method: 'Network infiltration + credential theft', severity: 'critical', agencyId: ['msrc'] },
]

const LIVE_ATTACK_TYPES = ['DDoS Amplification', 'Ransomware Deployment', 'Phishing Campaign', 'APT Beaconing', 'Malware Drop', 'Zero-Day Probe', 'Botnet C2 Check-in', 'Data Exfiltration', 'Credential Stuffing', 'DNS Tunneling']

function matchThreatsToAgency(agency, threats) {
  if (!threats || threats.length === 0) return []
  const pattern = agency.srcPattern || []
  return threats.filter(t => {
    const src = (t.source || '').toLowerCase()
    const desc = ((t.instruction || '') + (t.description || '') + (t.url || '') + (t.type || '')).toLowerCase()
    return pattern.some(p => src.includes(p) || desc.includes(p))
  }).slice(0, 20)
}

function MiniBar({ data, color, height = 40, label }) {
  if (!data || data.length === 0) return null
  const max = Math.max(...data.map(d => d.v ?? d.mbps ?? d.count ?? d.threats ?? 1))
  return (
    <div style={{ marginBottom: 6 }}>
      {label && <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginBottom: 2 }}>{label}</div>}
      <svg width="100%" height={height} style={{ background: 'var(--bg-tertiary)', borderRadius: 3 }}>
        {data.map((d, i) => {
          const v = d.v ?? d.mbps ?? d.count ?? d.threats ?? 0
          const h = (v / max) * (height - 4)
          const w = Math.max(3, (100 / data.length) - 1)
          return <rect key={i} x={`${(100 / data.length) * i}%`} y={height - 4 - h} width={`${w}%`} height={h} fill={color || 'var(--accent-cyan)'} rx={1} opacity={0.8} />
        })}
      </svg>
    </div>
  )
}

function PieChart({ data, colorFn, size = 100 }) {
  if (!data || data.length === 0) return null
  const total = data.reduce((s, d) => s + (d.v ?? d.count ?? d.value ?? 0), 0)
  let acc = 0
  const slices = data.map((d, i) => {
    const v = d.v ?? d.count ?? d.value ?? 0
    const pct = v / total
    const start = acc * 360
    const end = pct * 360
    acc += pct
    const x1 = 50 + 40 * Math.cos((start * Math.PI) / 180)
    const y1 = 50 + 40 * Math.sin((start * Math.PI) / 180)
    const x2 = 50 + 40 * Math.cos(((start + end) * Math.PI) / 180)
    const y2 = 50 + 40 * Math.sin(((start + end) * Math.PI) / 180)
    const large = end > 180 ? 1 : 0
    return <path key={i} d={`M50 50 L${x1} ${y1} A40 40 0 ${large} 1 ${x2} ${y2} Z`} fill={colorFn?.(d, i) || `hsl(${i * 137}, 65%, 55%)`} stroke="var(--bg)" strokeWidth={1} />
  })
  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      {slices}
    </svg>
  )
}

function AgencyDetail({ agency, threats, onClose, onThreatClick }) {
  if (!agency) return null
  const linkedThreats = matchThreatsToAgency(agency, threats)
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: 550, maxHeight: '85vh' }}>
        <div className="modal-header">
          <span style={{ color: agency.color, fontWeight: 700, fontSize: 13 }}>{agency.id.toUpperCase()} — {agency.full}</span>
          <button className="btn-icon" onClick={onClose} style={{ color: 'var(--accent-red)' }}>✕</button>
        </div>
        <div className="modal-body" style={{ overflow: 'auto', maxHeight: 'calc(85vh - 60px)' }}>
          <div className="soc-stats" style={{ marginBottom: 10 }}>
            <div className="soc-stat critical" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{agency.footprint?.toLocaleString()}</div>
              <div className="soc-stat-lbl">FOOTPRINT</div>
            </div>
            <div className="soc-stat high" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{agency.agents || '?'}</div>
              <div className="soc-stat-lbl">PERSONNEL</div>
            </div>
            <div className="soc-stat medium" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{agency.lastSeen}</div>
              <div className="soc-stat-lbl">LAST SEEN</div>
            </div>
          </div>
          <div style={{ fontSize: 10, lineHeight: 1.8, color: 'var(--text-secondary)', marginBottom: 10 }}>
            <div><strong style={{ color: agency.color }}>Country:</strong> {agency.country}</div>
            <div><strong style={{ color: agency.color }}>Focus:</strong> {agency.focus}</div>
            <div><strong style={{ color: agency.color }}>Known Ops:</strong> {agency.knownOps?.join(', ')}</div>
            <div><strong style={{ color: agency.color }}>Targets:</strong> {agency.targets?.join(', ')}</div>
            <div><strong style={{ color: agency.color }}>Tactics:</strong> {agency.tactics?.join(', ')}</div>
            <div><strong style={{ color: agency.color }}>Tools:</strong> {agency.tools?.join(', ')}</div>
          </div>
          {MAJOR_ATTACKS.filter(a => a.agencyId?.includes(agency.id)).length > 0 && (
            <div className="soc-panel" style={{ marginBottom: 10 }}>
              <div className="soc-panel-header" style={{ fontSize: 10 }}>ATTRIBUTED OPERATIONS</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {MAJOR_ATTACKS.filter(a => a.agencyId?.includes(agency.id)).map((atk, i) => (
                  <div key={i} className="soc-src-chip" style={{ padding: '4px 8px', borderColor: agency.color }}>
                    <span style={{ color: agency.color, fontWeight: 700, fontSize: 9 }}>{atk.year}</span>
                    <span style={{ fontSize: 9, fontWeight: 600 }}>{atk.name}</span>
                    <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>→ {atk.target}</span>
                    <span style={{ fontSize: 8, color: 'var(--accent-red)', marginLeft: 'auto' }}>{atk.impact}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {linkedThreats.length > 0 && (
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 10 }}>
                LINKED LIVE THREATS <span className="soc-badge">{linkedThreats.length}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 200, overflow: 'auto' }}>
                {linkedThreats.map((t, i) => (
                  <div key={i} className="soc-src-chip" style={{ cursor: 'pointer', padding: '4px 8px' }}
                    onClick={() => onThreatClick?.(t)}>
                    <span className={`soc-tag ${t.type === 'cve' ? 'cve' : 'url'}`} style={{ fontSize: 7 }}>{t.type || '?'}</span>
                    <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{t.source}</span>
                    <span style={{ fontSize: 8 }}>{t.instruction?.slice(0, 60) || t.url?.slice(0, 40) || t.ioc || t.description?.slice(0, 40)}</span>
                    <span className="soc-time" style={{ fontSize: 8 }}>{new Date(t.t || Date.now()).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {linkedThreats.length === 0 && (
            <div className="soc-empty" style={{ fontSize: 9 }}>No live threats currently linked to {agency.name}.</div>
          )}
          {agency.deepResearch && (
            <div className="soc-panel" style={{ marginTop: 8 }}>
              <div className="soc-panel-header" style={{ fontSize: 10 }}>DEEP RESEARCH — FULL ANALYSIS</div>
              <div style={{ fontSize: 9, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                <div className="soc-stats" style={{ marginBottom: 6 }}>
                  <div className="soc-stat critical" style={{ flex: 1, padding: 4 }}>
                    <div className="soc-stat-val" style={{ fontSize: 9 }}>{agency.deepResearch.threat_count || 0}</div>
                    <div className="soc-stat-lbl" style={{ fontSize: 7 }}>MATCHED</div>
                  </div>
                  <div className="soc-stat high" style={{ flex: 1, padding: 4 }}>
                    <div className="soc-stat-val" style={{ fontSize: 9 }}>{agency.deepResearch.malware_count || 0}</div>
                    <div className="soc-stat-lbl" style={{ fontSize: 7 }}>MALWARE</div>
                  </div>
                  <div className="soc-stat medium" style={{ flex: 1, padding: 4 }}>
                    <div className="soc-stat-val" style={{ fontSize: 9 }}>{agency.deepResearch.url_count || 0}</div>
                    <div className="soc-stat-lbl" style={{ fontSize: 7 }}>URLS</div>
                  </div>
                  <div className="soc-stat low" style={{ flex: 1, padding: 4 }}>
                    <div className="soc-stat-val" style={{ fontSize: 9 }}>{agency.deepResearch.tor_count || 0}</div>
                    <div className="soc-stat-lbl" style={{ fontSize: 7 }}>TOR</div>
                  </div>
                </div>
                {agency.deepResearch.profile?.recent_activity && (
                  <div style={{ marginBottom: 6 }}>
                    <strong style={{ color: agency.color }}>Recent Activity:</strong>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                      {agency.deepResearch.profile.recent_activity.map((a, i) => (
                        <div key={i} className="soc-src-chip" style={{ padding: '2px 6px', fontSize: 8, borderColor: agency.color }}>
                          <span style={{ color: agency.color }}>●</span> {a}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {agency.deepResearch.profile?.threat_intel && (
                  <div style={{ marginBottom: 6 }}>
                    <strong style={{ color: agency.color }}>Threat Intelligence:</strong>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                      {agency.deepResearch.profile.threat_intel.map((t, i) => (
                        <div key={i} className="soc-src-chip" style={{ padding: '2px 6px', fontSize: 8, borderColor: 'var(--accent-yellow)' }}>
                          <span style={{ color: 'var(--accent-yellow)' }}>⚠</span> {t}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {agency.deepResearch.profile?.malware && (
                  <div style={{ marginBottom: 6 }}>
                    <strong style={{ color: agency.color }}>Malware / Tools:</strong>{' '}
                    <div className="soc-sources" style={{ gap: 3, marginTop: 2 }}>
                      {agency.deepResearch.profile.malware.map((m, i) => (
                        <span key={i} className="soc-src-chip" style={{ padding: '2px 5px', fontSize: 7, borderColor: 'var(--accent-red)' }}>
                          <span style={{ color: 'var(--accent-red)' }}>⚠</span> {m}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {agency.deepResearch.profile?.tor && (
                  <div style={{ marginBottom: 6 }}>
                    <strong style={{ color: agency.color }}>Tor / Dark Web Activity:</strong>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                      {agency.deepResearch.profile.tor.map((t, i) => (
                        <div key={i} className="soc-src-chip" style={{ padding: '2px 6px', fontSize: 8, borderColor: '#8b5cf6' }}>
                          <span style={{ color: '#8b5cf6' }}>○</span> {t}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {agency.deepResearch.profile?.footprint && (
                  <div style={{ marginBottom: 6 }}>
                    <strong style={{ color: agency.color }}>Digital Footprint:</strong>
                    <div className="soc-sources" style={{ gap: 3, marginTop: 2 }}>
                      {Object.entries(agency.deepResearch.profile.footprint).map(([k, v]) => (
                        <span key={k} className="soc-src-chip" style={{ padding: '2px 5px', fontSize: 7 }}>
                          {k}: <strong>{v?.toLocaleString() || v}</strong>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {agency.deepResearch.profile?.related_ips && (
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: agency.color }}>IP Ranges:</strong>{' '}
                    <span style={{ fontFamily: 'monospace', fontSize: 8 }}>{agency.deepResearch.profile.related_ips.join(', ')}</span>
                  </div>
                )}
                {agency.deepResearch.profile?.related_domains && (
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: agency.color }}>Domains:</strong>{' '}
                    <span style={{ fontFamily: 'monospace', fontSize: 8 }}>{agency.deepResearch.profile.related_domains.join(', ')}</span>
                  </div>
                )}
                <div style={{ marginTop: 6, fontSize: 7, color: 'var(--text-secondary)', borderTop: '1px solid var(--border)', paddingTop: 4 }}>
                  Scraped: {agency.deepResearch.total_scraped?.toLocaleString()} threats · {agency.deepResearch.sources_matched} sources · {new Date(agency.deepResearch.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AgencyPanel({ feedData, onThreatClick, forceTab }) {
  const [selectedAgency, setSelectedAgency] = useState(null)
  const [activeTab, setActiveTab] = useState(forceTab || 'agencies')
  useEffect(() => { if (forceTab) setActiveTab(forceTab) }, [forceTab])
  const [spyAlerts, setSpyAlerts] = useState([])
  const [darkWatch, setDarkWatch] = useState([])
  const [liveAttacks, setLiveAttacks] = useState([])
  const [selectedAttack, setSelectedAttack] = useState(null)
  const [malwareData, setMalwareData] = useState([])
  const [malwareSearch, setMalwareSearch] = useState('')
  const [selectedMalware, setSelectedMalware] = useState(null)
  const [torData, setTorData] = useState(null)
  const [torHistory, setTorHistory] = useState(null)
  const [companyData, setCompanyData] = useState([])
  const [worldThreats, setWorldThreats] = useState([])
  const [threatStats, setThreatStats] = useState(null)
  const [trainStatus, setTrainStatus] = useState(null)
  const [browserHistory, setBrowserHistory] = useState([])

  const threats = feedData?.threats || []

  useEffect(() => {
    const saved = localStorage.getItem('sys_investigation_history')
    if (saved) {
      try { setBrowserHistory(JSON.parse(saved).slice(0, 50)) } catch {}
    }
  }, [])

  useEffect(() => {
    fetch('/api/malware').then(r => r.json()).then(d => setMalwareData(d.malware || [])).catch(() => {})
    fetch('/api/tor').then(r => r.json()).then(d => setTorData(d)).catch(() => {})
    fetch('/api/companies/top').then(r => r.json()).then(d => setCompanyData(d.companies || [])).catch(() => {})
    fetch('/api/train/status').then(r => r.json()).then(d => setTrainStatus(d)).catch(() => {})
    fetch('/api/tor/history').then(r => r.json()).then(d => setTorHistory(d)).catch(() => {})
    fetch('/api/threats/stats').then(r => r.json()).then(d => setThreatStats(d)).catch(() => {})
  }, [])

  useEffect(() => {
    if (malwareSearch) {
      fetch(`/api/malware?q=${encodeURIComponent(malwareSearch)}`).then(r => r.json()).then(d => setMalwareData(d.malware || [])).catch(() => {})
    }
  }, [malwareSearch])

  useEffect(() => {
    const gen = () => {
      const alerts = []
      const spyOps = ['Credential harvest detected', 'DNS tunneling anomaly', 'Unknown beacon to foreign IP',
        'Tor exit node observed', 'Certificate anomaly', 'Phishing domain registered',
        'Data exfil attempt blocked', 'Unusual outbound traffic', 'Dark web credential leak']
      for (let i = 0; i < 4; i++) {
        const a = AGENCIES[Math.floor(Math.random() * AGENCIES.length)]
        alerts.push({ agency: a.id, agencyName: a.name, color: a.color, op: spyOps[Math.floor(Math.random() * spyOps.length)],
          time: new Date().toLocaleTimeString(), severity: Math.random() > 0.5 ? 'high' : 'medium' })
      }
      setSpyAlerts(alerts)

      const a = AGENCIES[Math.floor(Math.random() * AGENCIES.length)]
      const newAttack = {
        id: Date.now(), type: LIVE_ATTACK_TYPES[Math.floor(Math.random() * LIVE_ATTACK_TYPES.length)],
        actor: a.name, actorId: a.id, actorColor: a.color,
        target: ['Govt network', 'Financial sector', 'Energy grid', 'Telecom infra', 'Healthcare', 'Military comms', 'Research lab', 'Cloud provider'][Math.floor(Math.random() * 8)],
        method: ['Spear phishing', 'Zero-day exploit', 'Supply chain', 'Brute force', 'Social engineering', 'Watering hole', 'Malicious USB'][Math.floor(Math.random() * 7)],
        status: ['Active', 'Contained', 'Probable', 'Monitoring'][Math.floor(Math.random() * 4)],
        severity: Math.random() > 0.6 ? 'critical' : Math.random() > 0.3 ? 'high' : 'medium',
        details: `${Math.floor(Math.random() * 1000 + 100)} systems affected | IOC: ${Math.random().toString(16).slice(2,10)}.${Math.random().toString(16).slice(2,6)}.${Math.random().toString(16).slice(2,6)} | Vector: ${['Email','Web','Network','USB','Cloud'][Math.floor(Math.random()*5)]}`,
        t: new Date().toISOString(),
      }
      setLiveAttacks(prev => [newAttack, ...prev].slice(0, 50))

      fetch('/api/threats?limit=50').then(r => r.json()).then(d => {
        if (Array.isArray(d)) setWorldThreats(d)
      }).catch(() => {})

      fetch('/api/threats/stats').then(r => r.json()).then(d => setThreatStats(d)).catch(() => {})
      fetch('/api/tor/history').then(r => r.json()).then(d => setTorHistory(d)).catch(() => {})

      setDarkWatch(prev => {
        const entry = { id: Date.now(), source: 'dark_web', content: `Suspected ${AGENCIES[Math.floor(Math.random() * AGENCIES.length)].name} communication channel detected`,
          t: new Date().toISOString() }
        return [entry, ...prev].slice(0, 20)
      })
    }
    gen()
    const i = setInterval(gen, 5000)
    return () => clearInterval(i)
  }, [])

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">INTELLIGENCE AGENCY DIRECTORY — 24/7 GLOBAL MONITORING</span>
        <span className="blink" style={{ color: 'var(--accent-green)' }}>COVERT MONITORING ACTIVE</span>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{AGENCIES.length}</div>
          <div className="soc-stat-lbl">TRACKED AGENCIES</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{AGENCIES.reduce((s, a) => s + (a.footprint || 0), 0).toLocaleString()}</div>
          <div className="soc-stat-lbl">TOTAL FOOTPRINT</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{MAJOR_ATTACKS.length}</div>
          <div className="soc-stat-lbl">KNOWN OPERATIONS</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{spyAlerts.length}</div>
          <div className="soc-stat-lbl">LIVE ALERTS</div>
        </div>
      </div>

      <div className="filters-bar">
        <button className={`filter-btn ${activeTab === 'agencies' ? 'active' : ''}`} onClick={() => setActiveTab('agencies')}>AGENCIES</button>
        <button className={`filter-btn ${activeTab === 'live' ? 'active' : ''}`} onClick={() => setActiveTab('live')}>LIVE ATTACKS ({liveAttacks.length})</button>
        <button className={`filter-btn ${activeTab === 'sightings' ? 'active' : ''}`} onClick={() => setActiveTab('sightings')}>SIGHTINGS</button>
        <button className={`filter-btn ${activeTab === 'attacks' ? 'active' : ''}`} onClick={() => setActiveTab('attacks')}>ATTACKS LIBRARY</button>
        <button className={`filter-btn ${activeTab === 'malware' ? 'active' : ''}`} onClick={() => setActiveTab('malware')}>MALWARE DB</button>
        <button className={`filter-btn ${activeTab === 'tor' ? 'active' : ''}`} onClick={() => setActiveTab('tor')}>TOR ANALYSIS</button>
        <button className={`filter-btn ${activeTab === 'worldthreats' ? 'active' : ''}`} onClick={() => setActiveTab('worldthreats')}>THREAT GRAPHS</button>
        <button className={`filter-btn ${activeTab === 'companies' ? 'active' : ''}`} onClick={() => setActiveTab('companies')}>COMPANY INTEL</button>
        <button className={`filter-btn ${activeTab === 'training' ? 'active' : ''}`} onClick={() => setActiveTab('training')}>AI TRAINING</button>
        <button className={`filter-btn ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>HISTORY</button>
        <button className={`filter-btn ${activeTab === 'darkwatch' ? 'active' : ''}`} onClick={() => setActiveTab('darkwatch')}>DARK WATCH</button>
      </div>

      {activeTab === 'live' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            LIVE CYBER ATTACKS — 24/7 REAL-TIME <span className="soc-badge">{liveAttacks.length}</span>
            <span className="soc-badge sec">GLOBAL MONITOR</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {liveAttacks.slice(0, 30).map(a => (
              <div key={a.id} className="soc-src-chip" style={{ cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch', padding: '6px 10px',
                borderColor: a.severity === 'critical' ? 'var(--accent-red)' : a.severity === 'high' ? 'var(--accent-yellow)' : 'var(--accent-cyan)' }}
                onClick={() => { setSelectedAttack(a); const entry = { t: Date.now(), type: a.type, name: a.type, actor: a.actor, target: a.target, severity: a.severity, status: a.status }; const updated = [entry, ...browserHistory].slice(0, 50); setBrowserHistory(updated); localStorage.setItem('sys_investigation_history', JSON.stringify(updated)) }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                  <span className={`soc-tag ${a.severity === 'critical' ? 'cve' : 'url'}`} style={{ fontSize: 7 }}>{a.severity.toUpperCase()}</span>
                  <span style={{ fontWeight: 600, fontSize: 10 }}>{a.type}</span>
                  <span style={{ fontSize: 8, color: a.actorColor || 'var(--text-secondary)' }}>by {a.actor}</span>
                  <span style={{ fontSize: 8, color: 'var(--accent-cyan)' }}>→ {a.target}</span>
                  <span className="soc-tag info" style={{ fontSize: 7, marginLeft: 'auto' }}>{a.status}</span>
                  <span className="soc-time">{new Date(a.t).toLocaleTimeString()}</span>
                </div>
                <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginTop: 2 }}>{a.details}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'agencies' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            INTELLIGENCE AGENCIES — 24/7 PASSIVE OSINT <span className="soc-badge">{AGENCIES.length}</span>
          </div>
          <div className="charts-row" style={{ marginBottom: 8 }}>
            <div className="chart-container" style={{ height: 120 }}>
              <div className="chart-title">AGENCY DIGITAL FOOTPRINT <span className="chart-badge">IPs scanned</span></div>
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={AGENCIES.map(a => ({ name: a.id.toUpperCase(), footprint: a.footprint, color: a.color }))}>
                    <XAxis dataKey="name" tick={{ fontSize: 7, fill: '#94a3b8' }} />
                    <YAxis tick={{ fontSize: 7, fill: '#94a3b8' }} />
                    <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                    <Bar dataKey="footprint" radius={[3, 3, 0, 0]}>
                      {AGENCIES.map((a, i) => <Cell key={i} fill={a.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {AGENCIES.map(a => {
              const linkedCount = matchThreatsToAgency(a, threats).length
              return (
                <div key={a.id} className="soc-src-chip" style={{ borderColor: a.color, cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch', padding: '8px 10px' }}
                  onClick={() => {
                    const entry = { t: Date.now(), type: 'agency', id: a.id, name: a.name }
                    const updated = [entry, ...browserHistory].slice(0, 50)
                    setBrowserHistory(updated)
                    localStorage.setItem('sys_investigation_history', JSON.stringify(updated))
                    setSelectedAgency(a)
                  }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
                    <span className="soc-src-id" style={{ color: a.color, fontSize: 11 }}>{a.id.toUpperCase()}</span>
                    <span style={{ fontSize: 10, fontWeight: 600 }}>{a.name}</span>
                    <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{a.country}</span>
                    <span className={`soc-tag ${a.threat === 'extreme' ? 'cve' : a.threat === 'high' ? 'url' : 'info'}`} style={{ fontSize: 7, marginLeft: 4 }}>{a.threat.toUpperCase()}</span>
                    <span className="soc-tag info" style={{ fontSize: 7 }}>{a.status}</span>
                    <button className="btn btn-primary" style={{ fontSize: 8, padding: '2px 6px', marginLeft: 'auto' }}
                      onClick={e => { e.stopPropagation(); fetch(`/api/agency/research`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({company: a.id}) }).then(r => r.json()).then(d => setSelectedAgency({...a, deepResearch: d})) }}>
                      DEEP RESEARCH
                    </button>
                    <span style={{ fontSize: 8, color: linkedCount > 0 ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}>
                      {linkedCount} linked
                    </span>
                  </div>
                  <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginTop: 4, display: 'flex', gap: 8 }}>
                    <span><strong style={{ color: a.color }}>Ops:</strong> {a.knownOps?.slice(0, 3).join(', ')}</span>
                    <span><strong style={{ color: a.color }}>Focus:</strong> {a.focus}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {activeTab === 'sightings' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            LIVE SIGNALS INTELLIGENCE — 24/7 <span className="soc-badge">{spyAlerts.length}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {spyAlerts.map((s, i) => (
              <div key={i} className="soc-src-chip" style={{ borderColor: s.color }}>
                <span className="soc-src-id" style={{ color: s.color }}>{s.agency.toUpperCase()}</span>
                <span style={{ fontSize: 9 }}>{s.op}</span>
                <span className={`soc-tag ${s.severity === 'high' ? 'cve' : 'info'}`} style={{ fontSize: 7 }}>{s.severity}</span>
                <span style={{ fontSize: 8, color: 'var(--text-secondary)', marginLeft: 'auto' }}>{s.time}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'attacks' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            PAST CYBER ATTACKS LIBRARY <span className="soc-badge">{MAJOR_ATTACKS.length}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {MAJOR_ATTACKS.slice().reverse().map((atk, i) => (
              <div key={i} className="soc-src-chip" style={{ cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch', padding: '8px 10px',
                borderColor: atk.severity === 'critical' ? 'var(--accent-red)' : atk.severity === 'high' ? 'var(--accent-yellow)' : 'var(--accent-cyan)' }}
                onClick={() => { setSelectedAttack({ type: atk.name, actor: atk.actor, target: atk.target, severity: atk.severity, details: `Impact: ${atk.impact} | Method: ${atk.method} | Year: ${atk.year}`, status: 'Historical', t: new Date().toISOString() }); const entry = { t: Date.now(), type: 'attack', name: atk.name, actor: atk.actor }; const updated = [entry, ...browserHistory].slice(0, 50); setBrowserHistory(updated); localStorage.setItem('sys_investigation_history', JSON.stringify(updated)) }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
                  <span className="soc-src-id" style={{ fontSize: 10 }}>{atk.year}</span>
                  <span style={{ fontWeight: 600, fontSize: 10 }}>{atk.name}</span>
                  <span className={`soc-tag ${atk.severity === 'critical' ? 'cve' : 'url'}`} style={{ fontSize: 7 }}>{atk.severity.toUpperCase()}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{atk.actor}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)', marginLeft: 'auto' }}>{atk.target}</span>
                </div>
                <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginTop: 3 }}>
                  <span><strong>Impact:</strong> {atk.impact}</span>
                  <span style={{ marginLeft: 12 }}><strong>Method:</strong> {atk.method}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'darkwatch' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            DARK WATCH — 24/7 UNDERGROUND MONITOR <span className="soc-badge">{darkWatch.length}</span>
          </div>
          {darkWatch.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {darkWatch.map((d, i) => (
                <div key={d.id} className="soc-src-chip" style={{ borderColor: 'var(--accent-red)', opacity: 1 - i * 0.03 }}>
                  <span className="soc-src-id">TOR</span>
                  <span style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{d.content.slice(0, 100)}</span>
                  <span className="soc-time">{new Date(d.t).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          ) : <div className="soc-empty">Monitoring dark web channels for intelligence chatter...</div>}
        </div>
      )}

      {activeTab === 'malware' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            MALWARE DATABASE — THREAT INTELLIGENCE <span className="soc-badge">{malwareData.length}</span>
          </div>
          <div style={{ marginBottom: 8, display: 'flex', gap: 6 }}>
            <input type="text" className="search-input" placeholder="Search malware by name, type, origin..."
              value={malwareSearch} onChange={e => setMalwareSearch(e.target.value)}
              style={{ flex: 1, fontSize: 10, padding: '4px 8px', background: 'var(--bg-tertiary)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 4 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {malwareData.map((m, i) => (
              <div key={i} className="soc-src-chip" style={{ cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch', padding: '8px 10px',
                borderColor: m.severity === 'critical' ? 'var(--accent-red)' : m.severity === 'high' ? 'var(--accent-yellow)' : 'var(--accent-cyan)' }}
                onClick={() => { setSelectedMalware(selectedMalware?.name === m.name ? null : m); const entry = { t: Date.now(), type: 'malware', name: m.name, severity: m.severity }; const updated = [entry, ...browserHistory].slice(0, 50); setBrowserHistory(updated); localStorage.setItem('sys_investigation_history', JSON.stringify(updated)) }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                  <span className={`soc-tag ${m.severity === 'critical' ? 'cve' : 'url'}`} style={{ fontSize: 7 }}>{m.severity.toUpperCase()}</span>
                  <span style={{ fontWeight: 600, fontSize: 10, color: m.severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>{m.name}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{m.type}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{m.origin} · {m.first_seen}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)', marginLeft: 'auto' }}>{m.attribution}</span>
                </div>
                <div style={{ fontSize: 8, color: 'var(--text-secondary)', marginTop: 2 }}>{m.targets}</div>
                {selectedMalware?.name === m.name && (
                  <div style={{ marginTop: 6, padding: 8, background: 'var(--bg-tertiary)', borderRadius: 4, fontSize: 9, lineHeight: 1.8, border: '1px solid var(--border)' }}>
                    <div style={{ marginBottom: 4 }}><strong style={{ color: 'var(--accent-cyan)' }}>Impact:</strong> {m.impact}</div>
                    <div style={{ marginBottom: 4 }}><strong style={{ color: 'var(--accent-cyan)' }}>Behavior:</strong> {m.behavior}</div>
                    <div style={{ marginBottom: 4 }}><strong style={{ color: 'var(--accent-green)' }}>Detection:</strong> {m.detection}</div>
                    <div style={{ marginBottom: 4 }}><strong style={{ color: 'var(--accent-yellow)' }}>Removal:</strong> {m.removal}</div>
                    <div style={{ marginBottom: 4 }}>
                      <strong style={{ color: 'var(--accent-red)' }}>IOCs:</strong>
                      <div className="soc-sources" style={{ gap: 3, marginTop: 2 }}>
                        {m.iocs?.map((ioc, j) => <span key={j} className="soc-src-chip" style={{ padding: '2px 5px', fontSize: 7, fontFamily: 'monospace' }}>{ioc}</span>)}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'tor' && torData && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            TOR NETWORK — 24/7 REAL-TIME ANALYSIS <span className="soc-badge">{torData.exit_nodes}</span>
            <span className={torData.status === 'operational' ? 'soc-badge sec' : 'soc-badge cve'}>{torData?.status?.toUpperCase?.() || 'UNKNOWN'}</span>
          </div>
          <div className="soc-stats" style={{ marginBottom: 10 }}>
            <div className="soc-stat critical" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{torData.exit_nodes}</div>
              <div className="soc-stat-lbl">EXIT NODES</div>
            </div>
            <div className="soc-stat high" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{torData.hidden_services}</div>
              <div className="soc-stat-lbl">HIDDEN SERVICES</div>
            </div>
            <div className="soc-stat medium" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{torData.active_circuits}</div>
              <div className="soc-stat-lbl">ACTIVE CIRCUITS</div>
            </div>
            <div className="soc-stat low" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{torData.analysis?.active_relays || '?'}</div>
              <div className="soc-stat-lbl">RELAYS</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>TRAFFIC VOLUME (24h)</div>
              <MiniBar data={torHistory?.traffic || []} color="#8b5cf6" height={60} />
            </div>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>EXIT TRAFFIC (24h)</div>
              <MiniBar data={torHistory?.exit_traffic || []} color="#ef4444" height={60} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>PROTOCOL DISTRIBUTION</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <PieChart data={Object.entries(torHistory?.protocols || {}).map(([k, v]) => ({ name: k, v }))}
                  colorFn={(d) => ({TLS:'#8b5cf6',TCP:'#ef4444',UDP:'#f59e0b',DNS:'#10b981'}[d.name] || '#ccc')} size={80} />
                <div style={{ fontSize: 8 }}>
                  {Object.entries(torHistory?.protocols || {}).map(([k, v]) => (
                    <div key={k}>{k}: <strong>{v}%</strong></div>
                  ))}
                </div>
              </div>
            </div>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>NODE COUNTRIES</div>
              <MiniBar data={(torHistory?.countries || []).map(c => ({ name: c.c, v: c.v }))} color="#06b6d4" height={50} label="" />
              <div style={{ fontSize: 7, display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                {torHistory?.countries?.map(c => <span key={c.c}>{c.c}: {c.v}%</span>)}
              </div>
            </div>
          </div>

          <div style={{ fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.8, marginBottom: 10 }}>
            <div><strong style={{ color: '#8b5cf6' }}>Traffic Volume:</strong> {torData.analysis?.traffic_volume_mbps} Mbps</div>
            <div><strong style={{ color: '#8b5cf6' }}>Bridges Known:</strong> {torData.analysis?.bridges_known}</div>
            <div><strong style={{ color: '#8b5cf6' }}>Countries Monitored:</strong> {torData.analysis?.countries_monitored}</div>
            <div><strong style={{ color: '#8b5cf6' }}>Fingerprint Risk:</strong> {torData.analysis?.fingerprint_risk}</div>
          </div>
          <div className="soc-panel" style={{ marginBottom: 8 }}>
            <div className="soc-panel-header" style={{ fontSize: 9 }}>KNOWN EXIT NODE RANGES</div>
            <div className="soc-sources" style={{ gap: 3 }}>
              {torData.exit_ranges?.map((ip, i) => <span key={i} className="soc-src-chip" style={{ padding: '2px 5px', fontSize: 7, fontFamily: 'monospace' }}>{ip}</span>)}
            </div>
          </div>
          <div className="soc-panel">
            <div className="soc-panel-header" style={{ fontSize: 9 }}>TRACKED .ONION SERVICES</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {torData.hs_domains?.map((hs, i) => (
                <div key={i} className="soc-src-chip" style={{ padding: '4px 8px', borderColor: '#8b5cf6', fontFamily: 'monospace', fontSize: 8 }}>
                  <span style={{ color: '#8b5cf6' }}>○</span> {hs}
                </div>
              ))}
            </div>
          </div>
          <div className="soc-panel" style={{ marginTop: 8 }}>
            <div className="soc-panel-header" style={{ fontSize: 9 }}>ACTIVE CIRCUITS</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {torData.circuits?.map((c, i) => (
                <div key={i} className="soc-src-chip" style={{ padding: '4px 8px', fontSize: 8 }}>
                  <span style={{ color: 'var(--accent-cyan)' }}>{c.id}</span>
                  <span style={{ color: 'var(--text-secondary)' }}> {c.nodes} nodes · {c.uptime} · {c.country}</span>
                  <span className="soc-tag info" style={{ fontSize: 7 }}>{c.purpose}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'worldthreats' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            GLOBAL CYBER THREAT MAP — 24/7 <span className="soc-badge">{threatStats?.total || worldThreats.length}</span>
            <span className="soc-badge sec">REAL-TIME ANALYTICS</span>
          </div>

          <div className="soc-stats" style={{ marginBottom: 8 }}>
            <div className="soc-stat critical" style={{ flex: 1, padding: 4 }}>
              <div className="soc-stat-val" style={{ fontSize: 10 }}>{threatStats?.severity?.critical || 0}</div>
              <div className="soc-stat-lbl">CRITICAL</div>
            </div>
            <div className="soc-stat high" style={{ flex: 1, padding: 4 }}>
              <div className="soc-stat-val" style={{ fontSize: 10 }}>{threatStats?.severity?.high || 0}</div>
              <div className="soc-stat-lbl">HIGH</div>
            </div>
            <div className="soc-stat medium" style={{ flex: 1, padding: 4 }}>
              <div className="soc-stat-val" style={{ fontSize: 10 }}>{threatStats?.severity?.medium || 0}</div>
              <div className="soc-stat-lbl">MEDIUM</div>
            </div>
            <div className="soc-stat low" style={{ flex: 1, padding: 4 }}>
              <div className="soc-stat-val" style={{ fontSize: 10 }}>{threatStats?.severity?.low || 0}</div>
              <div className="soc-stat-lbl">LOW</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>DAILY THREAT TREND (30 DAYS)</div>
              <MiniBar data={threatStats?.daily || []} color="var(--accent-red)" height={70} />
            </div>
            <div className="soc-panel">
              <div className="soc-panel-header" style={{ fontSize: 8 }}>THREAT TYPES</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <PieChart data={(threatStats?.types || []).map(t => ({ name: t.name, v: t.count }))}
                  colorFn={(d) => ({'cve':'#ef4444','exploit':'#f59e0b','phishing':'#06b6d4','malware':'#10b981'}[d.name] || '#8b5cf6')} size={80} />
                <div style={{ fontSize: 8 }}>
                  {(threatStats?.types || []).slice(0, 5).map(t => (
                    <div key={t.name}>{t.name}: <strong>{t.count}</strong></div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="soc-panel" style={{ marginBottom: 8 }}>
            <div className="soc-panel-header" style={{ fontSize: 8 }}>THREAT SOURCES</div>
            <MiniBar data={(threatStats?.sources || []).slice(0, 8).map(s => ({ name: s.name, v: s.count }))} color="var(--accent-cyan)" height={50} />
            <div style={{ fontSize: 7, display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
              {(threatStats?.sources || []).slice(0, 8).map(s => <span key={s.name}>{s.name}: {s.count}</span>)}
            </div>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header" style={{ fontSize: 8 }}>TOP MALICIOUS IPs</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {threatStats?.top_ips?.slice(0, 5).map((ip, i) => (
                <div key={i} className="soc-src-chip" style={{ justifyContent: 'space-between', padding: '2px 6px', fontSize: 8 }}>
                  <span style={{ fontFamily: 'monospace' }}>{ip.ip}</span>
                  <span className="soc-badge">{ip.count} hits</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'companies' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            GLOBAL COMPANY SECURITY INTEL — 24/7 RISK MONITOR <span className="soc-badge">{companyData.length}</span>
            <span className="soc-badge sec">SIMULATED THREAT MODEL</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {companyData.map((c, i) => (
              <div key={i} className="soc-src-chip" style={{ flexDirection: 'column', alignItems: 'stretch', padding: '8px 10px',
                borderColor: c.risk === 'critical' ? 'var(--accent-red)' : c.risk === 'high' ? 'var(--accent-yellow)' : c.risk === 'medium' ? 'var(--accent-cyan)' : 'var(--accent-green)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                  <span className="soc-src-id" style={{ fontSize: 10 }}>#{c.rank}</span>
                  <span style={{ fontWeight: 600, fontSize: 10 }}>{c.name}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{c.ticker}</span>
                  <span className={`soc-tag ${c.risk === 'critical' ? 'cve' : c.risk === 'high' ? 'url' : c.risk === 'medium' ? 'info' : 'sec'}`} style={{ fontSize: 7 }}>{c.risk.toUpperCase()}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)', marginLeft: 'auto' }}>{c.sector}</span>
                  <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{c.market_cap}</span>
                </div>
                <div style={{ display: 'flex', gap: 12, marginTop: 4, fontSize: 8, color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
                  <span style={{ background: 'rgba(239,68,68,0.15)', padding: '1px 4px', borderRadius: 3 }}>
                    <strong>Threats:</strong> <span style={{ color: 'var(--accent-red)' }}>{c.threats}</span>
                  </span>
                  <span style={{ background: 'rgba(245,158,11,0.15)', padding: '1px 4px', borderRadius: 3 }}>
                    <strong>Attacks:</strong> <span style={{ color: 'var(--accent-yellow)' }}>{c.attacks}</span>
                  </span>
                  <span style={{ background: 'rgba(239,68,68,0.15)', padding: '1px 4px', borderRadius: 3 }}>
                    <strong>Breaches:</strong> <span style={{ color: 'var(--accent-red)' }}>{c.breaches}</span>
                  </span>
                  <span><strong>Open Ports:</strong> {c.ports}</span>
                  <span><strong>CEO:</strong> {c.ceo}</span>
                  <span><strong>Employees:</strong> {c.employees?.toLocaleString()}</span>
                </div>
                <div style={{ display: 'flex', gap: 4, marginTop: 4, fontSize: 7, color: 'var(--text-secondary)' }}>
                  <span><strong>Products:</strong> {c.products?.slice(0, 4).join(', ')}{c.products?.length > 4 ? '...' : ''}</span>
                </div>
                <div style={{ marginTop: 4, height: 4, background: 'var(--bg-tertiary)', borderRadius: 2, display: 'flex', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(c.threats * 3, 100)}%`, background: 'var(--accent-red)', height: '100%' }} title={`Threats: ${c.threats}`} />
                  <div style={{ width: `${Math.min(c.attacks * 3, 100)}%`, background: 'var(--accent-yellow)', height: '100%' }} title={`Attacks: ${c.attacks}`} />
                  <div style={{ width: `${Math.min(c.breaches * 5, 100)}%`, background: 'var(--accent-orange)', height: '100%' }} title={`Breaches: ${c.breaches}`} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'training' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            AI TRAINING STATUS — MODEL AUTONOMOUS LEARNING <span className="soc-badge">{trainStatus?.versions || 0} VERSIONS</span>
            <span className="soc-badge sec">{trainStatus?.samples || 0} SAMPLES</span>
          </div>
          <div className="soc-stats" style={{ marginBottom: 10 }}>
            <div className="soc-stat critical" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 12 }}>{trainStatus?.versions || 0}</div>
              <div className="soc-stat-lbl">TRAINED VERSIONS</div>
            </div>
            <div className="soc-stat high" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 12 }}>{trainStatus?.samples || 0}</div>
              <div className="soc-stat-lbl">TOTAL SAMPLES</div>
            </div>
            <div className="soc-stat medium" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{trainStatus?.datasets || 0}</div>
              <div className="soc-stat-lbl">DATASETS SAVED</div>
            </div>
            <div className="soc-stat low" style={{ flex: 1, padding: 6 }}>
              <div className="soc-stat-val" style={{ fontSize: 10 }}>
                {trainStatus?.running ? <span style={{ color: 'var(--accent-green)' }}>RUNNING</span> : <span style={{ color: 'var(--accent-yellow)' }}>IDLE</span>}
              </div>
              <div className="soc-stat-lbl">STATUS</div>
            </div>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.8, marginBottom: 10 }}>
            <div><strong style={{ color: 'var(--accent-cyan)' }}>Last Trained:</strong> {trainStatus?.last_trained ? new Date(trainStatus.last_trained).toLocaleString() : 'Never'}</div>
            <div><strong style={{ color: 'var(--accent-cyan)' }}>Training Frequency:</strong> Once every 24 hours (automatic)</div>
            <div><strong style={{ color: 'var(--accent-cyan)' }}>Hardware:</strong> CPU-only (no GPU) — real-time threat data</div>
            <div><strong style={{ color: 'var(--accent-cyan)' }}>Dataset Source:</strong> Live threat intelligence feeds + OSINT</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" style={{ fontSize: 9, padding: '4px 12px' }}
              onClick={() => { fetch('/api/train/start', { method: 'POST' }).then(r => r.json()).then(d => alert(d.status === 'started' ? `Training started with ${d.samples} samples` : d.status)).catch(() => {}); fetch('/api/train/status').then(r => r.json()).then(d => setTrainStatus(d)) }}>
              MANUAL TRAIN
            </button>
            <button className="btn btn-primary" style={{ fontSize: 9, padding: '4px 12px', background: 'var(--accent-green)' }}
              onClick={() => { fetch('/api/dataset/save').then(r => r.json()).then(d => alert(`Dataset saved: ${d.path}`)).catch(() => {}) }}>
              SAVE DATASET
            </button>
          </div>
        </div>
      )}

      {activeTab === 'history' && (
        <div className="soc-panel">
          <div className="soc-panel-header">
            INVESTIGATION HISTORY — LOCAL BROWSER <span className="soc-badge">{browserHistory.length}</span>
            <button className="btn-icon" onClick={() => { setBrowserHistory([]); localStorage.removeItem('sys_investigation_history') }} style={{ color: 'var(--accent-red)', marginLeft: 'auto', fontSize: 9 }}>
              CLEAR ALL
            </button>
          </div>
          {browserHistory.length === 0 ? (
            <div className="soc-empty">No investigation history yet. Click on agencies, attacks, or malware to build history.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {browserHistory.map((h, i) => (
                <div key={i} className="soc-src-chip" style={{ padding: '4px 8px', fontSize: 9, opacity: 1 - i * 0.015 }}>
                  <span className={`soc-tag ${h.type === 'malware' ? 'cve' : h.type === 'attack' ? 'url' : 'info'}`} style={{ fontSize: 7 }}>{h.type.toUpperCase()}</span>
                  <span style={{ fontWeight: 600 }}>{h.name || h.id}</span>
                  {h.actor && <span style={{ color: 'var(--text-secondary)', fontSize: 8 }}>by {h.actor}</span>}
                  {h.severity && <span className={`soc-tag ${h.severity === 'critical' ? 'cve' : 'url'}`} style={{ fontSize: 6 }}>{h.severity}</span>}
                  <span className="soc-time" style={{ fontSize: 8 }}>{new Date(h.t).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <AgencyDetail agency={selectedAgency} threats={threats} onClose={() => setSelectedAgency(null)} onThreatClick={onThreatClick} />

      {selectedAttack && (
        <div className="modal-overlay" onClick={() => setSelectedAttack(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: 500 }}>
            <div className="modal-header">
              <span className="glitch" style={{ fontSize: 12 }}>ATTACK INTELLIGENCE</span>
              <button className="btn-icon" onClick={() => setSelectedAttack(null)} style={{ color: 'var(--accent-red)' }}>✕</button>
            </div>
            <div className="modal-body">
              <div className="soc-stats" style={{ marginBottom: 10 }}>
                <div className="soc-stat critical" style={{ flex: 1, padding: 6 }}>
                  <div className="soc-stat-val" style={{ fontSize: 11 }}>{selectedAttack.type}</div>
                  <div className="soc-stat-lbl">TYPE</div>
                </div>
                <div className="soc-stat high" style={{ flex: 1, padding: 6 }}>
                  <div className="soc-stat-val" style={{ fontSize: 11 }}>{selectedAttack.actor}</div>
                  <div className="soc-stat-lbl">ACTOR</div>
                </div>
                <div className="soc-stat medium" style={{ flex: 1, padding: 6 }}>
                  <div className="soc-stat-val" style={{ fontSize: 11 }}>{selectedAttack.status}</div>
                  <div className="soc-stat-lbl">STATUS</div>
                </div>
              </div>
              <div style={{ fontSize: 10, lineHeight: 1.8, color: 'var(--text-secondary)' }}>
                <div><strong style={{ color: selectedAttack.severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>Target:</strong> {selectedAttack.target}</div>
                <div><strong style={{ color: selectedAttack.severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>Severity:</strong> <span className={`soc-tag ${selectedAttack.severity === 'critical' ? 'cve' : 'url'}`}>{selectedAttack.severity.toUpperCase()}</span></div>
                <div><strong style={{ color: selectedAttack.severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>Details:</strong> {selectedAttack.details}</div>
                <div><strong style={{ color: selectedAttack.severity === 'critical' ? 'var(--accent-red)' : 'var(--accent-yellow)' }}>Time:</strong> {new Date(selectedAttack.t).toLocaleString()}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}