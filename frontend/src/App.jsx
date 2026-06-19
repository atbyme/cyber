import { useState, useEffect, useCallback, useRef } from 'react'
import Dashboard from './Dashboard'
import ScraperPanel from './ScraperPanel'
import ResearchPanel from './ResearchPanel'
import TrainingPanel from './TrainingPanel'
import FootprintPanel from './FootprintPanel'
import CompanyIntelPanel from './CompanyIntelPanel'
import AgencyPanel from './AgencyPanel'
import ThreatDetailModal from './ThreatDetailModal'

const AGENCY_COLORS = { 'isi': '#10b981', 'mossad': '#06b6d4', 'raw': '#f59e0b', 'nsa': '#ef4444', 'gchq': '#8b5cf6', 'gru': '#ec4899', 'msrc': '#f97316' }

function GlobalMap({ onThreatClick }) {
  const [events, setEvents] = useState([])
  const [agencies, setAgencies] = useState([])
  const [popupInfo, setPopupInfo] = useState(null)

  useEffect(() => {
    fetch('/api/agencies').then(r => r.json()).then(d => setAgencies(Object.entries(d.agencies || {}))).catch(() => {})
  }, [])

  useEffect(() => {
    const gen = () => {
      const list = []
      const positions = [
        { x: 15, y: 22, label: 'NA' }, { x: 28, y: 50, label: 'SA' },
        { x: 48, y: 18, label: 'EU' }, { x: 50, y: 45, label: 'AF' },
        { x: 62, y: 15, label: 'RU' }, { x: 54, y: 30, label: 'ME' },
        { x: 65, y: 32, label: 'AS' }, { x: 76, y: 22, label: 'CN' },
        { x: 72, y: 42, label: 'SEA' }, { x: 84, y: 55, label: 'AU' },
      ]
      for (let i = 0; i < 8; i++) {
        const p = positions[i % positions.length]
        list.push({
          id: i, x: p.x + (Math.random() - 0.5) * 4, y: p.y + (Math.random() - 0.5) * 4,
          sev: Math.random() > 0.6 ? '#ef4444' : Math.random() > 0.3 ? '#f59e0b' : '#06b6d4',
          sz: 1.5 + Math.random() * 2.5, label: p.label,
          name: ['DDoS', 'Ransomware', 'Phishing', 'APT', 'Malware', 'Zero-Day', 'Botnet', 'Data Breach'][Math.floor(Math.random() * 8)],
          desc: `${['DDoS', 'Ransomware', 'Phishing', 'APT', 'Malware', 'Zero-Day', 'Botnet', 'Data Breach'][Math.floor(Math.random() * 8)]} attack detected in ${p.label} region — ${Math.random() > 0.5 ? 'Active' : 'Probable'} threat level ${Math.random() > 0.6 ? 'CRITICAL' : Math.random() > 0.3 ? 'HIGH' : 'MEDIUM'}`,
        })
      }
      setEvents(list)
    }
    gen()
    const i = setInterval(gen, 5000)
    return () => clearInterval(i)
  }, [])

  return (
    <div className="global-map-bar">
      <svg viewBox="0 0 100 50" className="global-map-svg" style={{ width: 280, height: 42 }}>
        {/* North America */}
        <path d="M8,8 L16,6 L20,10 L22,16 L20,22 L16,28 L12,30 L8,28 L6,22 L5,16 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* South America */}
        <path d="M16,32 L20,30 L24,34 L24,40 L22,46 L18,48 L15,44 L14,38 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Europe */}
        <path d="M42,10 L48,8 L52,10 L54,14 L52,18 L48,20 L44,18 L42,14 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Africa */}
        <path d="M44,22 L50,20 L54,24 L54,32 L52,38 L48,40 L44,36 L42,30 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Russia */}
        <path d="M54,6 L62,4 L68,6 L70,10 L68,16 L64,18 L58,18 L54,16 L52,12 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Middle East */}
        <path d="M52,20 L56,18 L60,20 L60,24 L56,26 L52,24 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Asia */}
        <path d="M62,22 L70,20 L74,24 L74,30 L70,34 L64,34 L60,30 L58,26 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* China */}
        <path d="M72,18 L78,16 L82,20 L80,26 L76,28 L72,26 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* SE Asia */}
        <path d="M68,34 L74,32 L78,36 L76,42 L72,44 L68,42 L66,38 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />
        {/* Australia */}
        <path d="M80,46 L86,44 L90,48 L88,52 L84,54 L80,52 Z" fill="none" stroke="#2d3a50" strokeWidth="0.3" opacity="0.6" />

        {/* Attack event dots — clickable */}
        {events.map(d => (
          <g key={d.id} style={{ cursor: 'pointer' }}
            onClick={() => setPopupInfo({ title: `${d.name} — ${d.label}`, desc: d.desc, sev: d.sev, x: d.x * 2.8 + 20, y: 35 })}
            onMouseEnter={() => setPopupInfo({ title: `${d.name} — ${d.label}`, desc: d.desc, sev: d.sev, x: d.x * 2.8 + 20, y: 35 })}
            onMouseLeave={() => setTimeout(() => setPopupInfo(null), 2000)}>
            <circle cx={d.x} cy={d.y} r={d.sz * 2} fill="none" stroke={d.sev} strokeWidth="0.4" opacity="0.2" className="map-pulse" />
            <circle cx={d.x} cy={d.y} r={d.sz * 0.7} fill={d.sev} opacity="0.9" />
          </g>
        ))}

        {/* Agency dots — clickable */}
        {agencies.slice(0, 7).map(([key, a], i) => {
          const cx = [12,20,55,72,46,62,78][i]; const cy = [14,38,14,32,48,12,24][i]
          return (
            <g key={key} style={{ cursor: 'pointer' }}
              onClick={() => setPopupInfo({ title: `${key.toUpperCase()} — ${a.name}`, desc: `Country: ${a.country} | Focus: ${a.focus} | Status: ${a.active ? 'Active' : 'Dormant'} | Last seen: ${a.last_seen || 'Unknown'}`, sev: a.color || '#8b5cf6', x: cx * 2.8 + 20, y: 35 })}
              onMouseEnter={() => setPopupInfo({ title: `${key.toUpperCase()} — ${a.name}`, desc: `Country: ${a.country} | Focus: ${a.focus}`, sev: a.color || '#8b5cf6', x: cx * 2.8 + 20, y: 35 })}
              onMouseLeave={() => setTimeout(() => setPopupInfo(null), 2000)}>
              <circle cx={cx} cy={cy} r="2.2" fill={a.color || '#8b5cf6'} opacity="0.8" />
              <text x={cx} y={cy - 4} textAnchor="middle" fill={a.color || '#8b5cf6'} fontSize="2" opacity="0.8">{key.toUpperCase()}</text>
            </g>
          )
        })}
      </svg>

      {/* Map popup tooltip */}
      {popupInfo && (
        <div style={{
          position: 'absolute', left: popupInfo.x, top: popupInfo.y, zIndex: 100,
          background: '#1a2332', border: `1px solid ${popupInfo.sev}`, borderRadius: 6,
          padding: '4px 8px', fontSize: 9, maxWidth: 250, boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
        }}>
          <div style={{ color: popupInfo.sev, fontWeight: 700, fontSize: 10, marginBottom: 2 }}>{popupInfo.title}</div>
          <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>{popupInfo.desc}</div>
        </div>
      )}

      <div className="global-map-info">
        <span style={{ color: 'var(--accent-cyan)', fontSize: 9 }}>● {events.length} live events</span>
        <span style={{ color: 'var(--text-secondary)', fontSize: 8 }}>Click any dot for intel</span>
      </div>
      <div className="global-map-actions">
        <button className="btn btn-primary" style={{ fontSize: 9, padding: '2px 8px' }}
          onClick={() => fetch('/api/report/save', { method: 'POST' }).then(r => r.json()).then(d => alert(`Report saved!\n${d.path}\n${d.report.total_threats} threats`))}>
          SAVE REPORT
        </button>
        <button className="btn btn-primary" style={{ fontSize: 9, padding: '2px 8px' }}
          onClick={() => window.open('/api/threats/export', '_blank')}>
          EXPORT
        </button>
      </div>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState(() => localStorage.getItem('aura_page') || 'dashboard')
  const [status, setStatus] = useState({})
  const [connected, setConnected] = useState(false)
  const [notifications, setNotifications] = useState([])
  const [showN, setShowN] = useState(false)
  const [unread, setUnread] = useState(0)
  const [feedData, setFeedData] = useState({})
  const [detailThreat, setDetailThreat] = useState(null)
  const ws = useRef(null)
  const autoExportDone = useRef(localStorage.getItem('aura_export_today') === new Date().toDateString())

  const connect = useCallback(() => {
    try {
      const host = location.host.includes('5173') ? 'localhost:8000' : location.host
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      const s = new WebSocket(`${proto}//${host}/ws`)
      s.onopen = () => setConnected(true)
      s.onmessage = e => {
        try {
          const m = JSON.parse(e.data)
          if (m.event === 'notification') { setNotifications(p => [m.data, ...p].slice(0, 500)); setUnread(c => c + 1) }
          if (m.event === 'notifications_cleared') { setNotifications([]); setUnread(0) }
          if (m.event === 'train_complete') setStatus(p => ({ ...p, training: { ...p.training, running: false, lastTrain: m.data } }))
          if (m.event === 'train_status') setStatus(p => ({ ...p, training: { ...p.training, running: true } }))
        } catch {}
      }
      s.onclose = () => { setConnected(false); setTimeout(connect, 2000) }
      ws.current = s
    } catch {}
  }, [])

  const loadFeed = useCallback(async () => {
    try {
      const r = await fetch('/api/feed')
      const d = await r.json()
      setFeedData(d)
      setStatus(d.status || {})
      setNotifications(d.notifications || [])
      setUnread(0)
    } catch {
      try { const r = await fetch('/api/status'); setStatus(await r.json()) } catch {}
    }
  }, [])

  useEffect(() => {
    connect()
    loadFeed()
    const i = setInterval(loadFeed, 3000)
    return () => { clearInterval(i); ws.current?.close() }
  }, [connect, loadFeed])

  useEffect(() => { localStorage.setItem('aura_page', page) }, [page])

  // Auto-save daily export
  useEffect(() => {
    if (!autoExportDone.current && feedData.threats?.length > 10) {
      autoExportDone.current = true
      localStorage.setItem('aura_export_today', new Date().toDateString())
      try {
        const existing = JSON.parse(localStorage.getItem('aura_threat_history') || '[]')
        const day = new Date().toDateString()
        if (!existing.some(e => e.day === day)) {
          existing.push({ day, count: feedData.threats.length, threats: feedData.threats.slice(0, 50), t: new Date().toISOString() })
          localStorage.setItem('aura_threat_history', JSON.stringify(existing.slice(-365)))
        }
      } catch {}
      setTimeout(() => {
        const a = document.createElement('a')
        a.href = '/api/threats/export'
        a.download = `aura_threats_${new Date().toISOString().slice(0,10)}.txt`
        a.click()
      }, 5000)
    }
  }, [feedData])

  const clearN = async () => {
    try { await fetch('/api/notifications/clear', { method: 'POST' }) } catch {}
    setNotifications([]); setUnread(0)
  }

  const P = { dashboard: Dashboard, scraper: ScraperPanel, research: ResearchPanel, training: TrainingPanel, footprint: FootprintPanel, company: CompanyIntelPanel, agencies: AgencyPanel }[page]

  const s = status
  const totalScraped = (s.total_scraped || 0).toLocaleString()
  const rtActive = s.rt_cycle || 0
  const deepCycle = s.deep_cycle || 0
  const trainingRunning = s.training?.running

  const navItems = [
    { key: 'dashboard', label: 'Dashboard', icon: '◈' },
    { key: 'scraper', label: 'Scraper', icon: '⚡' },
    { key: 'research', label: 'Research', icon: '◎' },
    { key: 'training', label: 'Training', icon: '⟳' },
    { key: 'footprint', label: 'Footprint', icon: '☉' },
    { key: 'company', label: 'Company Intel', icon: '◆' },
    { key: 'agencies', label: 'Agencies', icon: '●' },
  ]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="logo">AURA <span className="accent">AI</span></div>
        <nav>
          {navItems.map(({ key, label, icon }) => (
            <button key={key} className={`nav-btn ${page === key ? 'active' : ''}`} onClick={() => setPage(key)}>
              <span style={{ width: 16, textAlign: 'center', fontSize: 12 }}>{icon}</span>
              {label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-line">
            <span className={`status-dot ${connected ? 'online' : 'offline'}`} />
            {connected ? 'LIVE 24/7' : 'CONNECTING...'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4, display: 'flex', flexDirection: 'column', gap: 1 }}>
            <div className="status-line" style={{ justifyContent: 'space-between' }}>
              <span>RT: {rtActive}</span>
              <span>Deep: {deepCycle}</span>
            </div>
            <div className="status-line" style={{ justifyContent: 'space-between' }}>
              <span>Threats: {totalScraped}</span>
              <span>{trainingRunning ? '⟳ Training' : '● Ready'}</span>
            </div>
          </div>
        </div>
      </aside>
      <main className="main-content">
        <div className="notif-bell">
          <button className="btn-icon" onClick={() => setShowN(!showN)} style={{ position: 'relative' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
            {unread > 0 && <span className="notif-count">{unread > 9 ? '9+' : unread}</span>}
          </button>
          {showN && <div className="notif-dropdown">
            <div className="notif-header"><span>Notifications</span><button className="btn-text" onClick={clearN}>Clear</button></div>
            {notifications.length === 0 ? <div className="notif-empty">No notifications</div> :
              notifications.slice(0, 50).map(n => (
                <div key={n.id} className="notif-item" style={{ borderLeftColor: n.level === 'error' ? 'var(--accent-red)' : n.level === 'warning' ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
                  <div className="notif-title">{n.title}</div>
                  <div className="notif-msg">{n.message}</div>
                </div>
              ))}
          </div>}
        </div>
        <GlobalMap onThreatClick={setDetailThreat} />
        <P status={status} feedData={feedData} onThreatClick={setDetailThreat} />
      </main>
      <ThreatDetailModal threat={detailThreat} onClose={() => setDetailThreat(null)} />
    </div>
  )
}
