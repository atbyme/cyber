import { useState, useEffect, useCallback, useRef } from 'react'
import Dashboard from './Dashboard'
import ScraperPanel from './ScraperPanel'
import ResearchPanel from './ResearchPanel'
import TrainingPanel from './TrainingPanel'
import FootprintPanel from './FootprintPanel'
import CompanyIntelPanel from './CompanyIntelPanel'
import AgencyPanel from './AgencyPanel'
import MalwarePanel from './MalwarePanel'
import TorPanel from './TorPanel'
import DarkWatchPanel from './DarkWatchPanel'
import WorldTrackerPanel from './WorldTrackerPanel'
import DailyReportPanel from './DailyReportPanel'
import ThreatDetailModal from './ThreatDetailModal'

const AGENCY_MAP_POS = { isi: {x:68,y:26}, mossad: {x:53,y:24}, raw: {x:70,y:28}, nsa: {x:14,y:12}, gchq: {x:46,y:13}, gru: {x:60,y:12}, msrc: {x:74,y:20}, cia: {x:16,y:14}, mi6: {x:44,y:15}, dgse: {x:48,y:17}, bnd: {x:50,y:14}, fsb: {x:62,y:11}, asis: {x:82,y:44}, csis: {x:12,y:8} }
const REGION_POS = [
  {x:10,y:14,l:'North America'},{x:18,y:36,l:'South America'},{x:44,y:12,l:'Europe'},
  {x:46,y:30,l:'Africa'},{x:60,y:10,l:'Russia'},{x:54,y:22,l:'Middle East'},
  {x:66,y:24,l:'Asia'},{x:74,y:18,l:'China'},{x:70,y:36,l:'SE Asia'},{x:82,y:46,l:'Australia'},
]

function GlobalMap() {
  const [mapData, setMapData] = useState([])
  const [agencyAct, setAgencyAct] = useState({})
  const [agencies, setAgencies] = useState([])
  const [popup, setPopup] = useState(null)
  const [threatCount, setThreatCount] = useState(0)

  const load = useCallback(async () => {
    try {
      const [mapR, agActR, agR] = await Promise.all([
        fetch('/api/threats/map').then(r=>r.json()),
        fetch('/api/agencies/activity').then(r=>r.json()),
        fetch('/api/agencies').then(r=>r.json()),
      ])
      setMapData(mapR.map || [])
      setThreatCount(mapR.total_threats_mapped || 0)
      setAgencyAct(agActR.agencies || {})
      setAgencies(Object.entries(agR.agencies || {}))
    } catch {}
  }, [])

  useEffect(() => { load(); const i = setInterval(load, 10000); return () => clearInterval(i) }, [load])

  const maxCount = Math.max(1, ...mapData.map(m => m.count))
  const sevFromPct = p => p > 20 ? '#ef4444' : p > 10 ? '#f59e0b' : p > 5 ? '#06b6d4' : '#8b5cf6'

  const cntToReg = mapData.reduce((a, c) => {
    const region = REGION_POS.find(r => {
      const dx = r.x - (c.lng+180)/3.6; const dy = r.y - (90-c.lat)/1.8
      return Math.sqrt(dx*dx+dy*dy) < 12
    })
    if (region) a[region.l] = (a[region.l]||0) + c.count
    return a
  }, {})

  const events = REGION_POS.map((r,i) => {
    const c = cntToReg[r.l] || Math.floor(threatCount / 20)
    const sev = sevFromPct((c / Math.max(1,threatCount))*100)
    return { id: i, x: r.x + (Math.random()-0.5)*2, y: r.y + (Math.random()-0.5)*2, sev, sz: Math.max(0.8, Math.min(3, c/10)), label: r.l, name: `Threats: ${c}` }
  })

  return (
    <div className="global-map-bar" style={{position:'relative'}}>
      <svg viewBox="0 0 100 50" className="global-map-svg" style={{width:300,height:45}}>
        {REGION_POS.map(r => <path key={r.l} d="M0,0h100v50H0Z" fill="none" stroke="#2d3a50" strokeWidth="0.1" opacity="0.02"/>)}
        {events.map(d => (
          <g key={d.id} style={{cursor:'pointer'}}
            onClick={() => setPopup({title:`${d.name} — ${d.label}`,desc:`${d.label} region: ${d.name} threats active`,sev:d.sev,x:d.x*3+10,y:38})}
            onMouseEnter={() => setPopup({title:`${d.name} — ${d.label}`,desc:`${d.label} region: ${d.name} threats active`,sev:d.sev,x:d.x*3+10,y:38})}
            onMouseLeave={() => setTimeout(() => setPopup(null),2000)}>
            <circle cx={d.x} cy={d.y} r={d.sz*1.5} fill="none" stroke={d.sev} strokeWidth="0.3" opacity="0.15" className="map-pulse"/>
            <circle cx={d.x} cy={d.y} r={d.sz*0.5} fill={d.sev} opacity="0.85"/>
          </g>
        ))}
        {agencies.slice(0,14).map(([key,a]) => {
          const pos = AGENCY_MAP_POS[key] || {x:30,y:30}
          const act = agencyAct[key] || {}
          const sz = Math.max(1.2, Math.min(3, (act.total_threats||0)/5))
          return (
            <g key={key} style={{cursor:'pointer'}}
              onClick={() => setPopup({title:`${key.toUpperCase()} — ${a.name}`,desc:`Country: ${a.country} | Threats: ${act.total_threats||0} | Tools: ${(act.tools_detected||[]).slice(0,3).join(', ')}`,sev:a.color||'#8b5cf6',x:pos.x*3+10,y:38})}
              onMouseEnter={() => setPopup({title:`${key.toUpperCase()} — ${a.name}`,desc:`Country: ${a.country} | Threats tracked: ${act.total_threats||0}`,sev:a.color||'#8b5cf6',x:pos.x*3+10,y:38})}
              onMouseLeave={() => setTimeout(() => setPopup(null),2000)}>
              <circle cx={pos.x} cy={pos.y} r={sz} fill={a.color||'#8b5cf6'} opacity="0.7"/>
              <text x={pos.x} y={pos.y-sz-1} textAnchor="middle" fill={a.color||'#8b5cf6'} fontSize="1.8" opacity="0.9">{key.toUpperCase()}</text>
            </g>
          )
        })}
      </svg>
      {popup && (
        <div style={{position:'absolute',left:popup.x-60,top:popup.y-30,zIndex:100,
          background:'#1a2332',border:`1px solid ${popup.sev}`,borderRadius:6,
          padding:'4px 8px',fontSize:9,maxWidth:260,boxShadow:'0 4px 20px rgba(0,0,0,0.5)'}}>
          <div style={{color:popup.sev,fontWeight:700,fontSize:10,marginBottom:2}}>{popup.title}</div>
          <div style={{color:'var(--text-secondary)',lineHeight:1.4}}>{popup.desc}</div>
        </div>
      )}
      <div className="global-map-info">
        <span style={{color:'var(--accent-cyan)',fontSize:9}}>● {mapData.length} countries, {threatCount} threats</span>
        <span style={{color:'var(--text-secondary)',fontSize:8}}>{agencies.length} agencies tracked</span>
      </div>
      <div className="global-map-actions">
        <button className="btn btn-primary" style={{fontSize:9,padding:'2px 8px'}}
          onClick={()=>fetch('/api/report/save',{method:'POST'}).then(r=>r.json()).then(d=>alert(`Report saved!\n${d.path}`))}>
          SAVE REPORT
        </button>
        <button className="btn btn-primary" style={{fontSize:9,padding:'2px 8px'}}
          onClick={()=>window.open('/api/threats/export','_blank')}>
          EXPORT
        </button>
      </div>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState(() => localStorage.getItem('sys_page') || 'dashboard')
  const [status, setStatus] = useState({})
  const [connected, setConnected] = useState(false)
  const [notifications, setNotifications] = useState([])
  const [showN, setShowN] = useState(false)
  const [unread, setUnread] = useState(0)
  const [feedData, setFeedData] = useState({})
  const [detailThreat, setDetailThreat] = useState(null)
  const ws = useRef(null)
  const autoExportDone = useRef(localStorage.getItem('sys_export_today') === new Date().toDateString())
  const connect = useCallback(() => {
    try {
      const host = import.meta.env.DEV ? 'localhost:8000' : location.host
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

  useEffect(() => { localStorage.setItem('sys_page', page) }, [page])

  useEffect(() => {
    if (!autoExportDone.current && feedData.threats?.length > 10) {
      autoExportDone.current = true
      localStorage.setItem('sys_export_today', new Date().toDateString())
      try {
        const existing = JSON.parse(localStorage.getItem('sys_threat_history') || '[]')
        const day = new Date().toDateString()
        if (!existing.some(e => e.day === day)) {
          existing.push({ day, count: feedData.threats.length, threats: feedData.threats.slice(0, 50), t: new Date().toISOString() })
          localStorage.setItem('sys_threat_history', JSON.stringify(existing.slice(-365)))
        }
      } catch {}
      setTimeout(() => {
        const a = document.createElement('a')
        a.href = '/api/threats/export'
        a.download = `threats_${new Date().toISOString().slice(0,10)}.txt`
        a.click()
      }, 5000)
    }
  }, [feedData])

  const clearN = async () => {
    try { await fetch('/api/notifications/clear', { method: 'POST' }) } catch {}
    setNotifications([]); setUnread(0)
  }

  const P = { dashboard: Dashboard, scraper: ScraperPanel, research: ResearchPanel, training: TrainingPanel, footprint: FootprintPanel, company: CompanyIntelPanel, agencies: AgencyPanel, malware: MalwarePanel, tor: TorPanel, darkwatch: DarkWatchPanel, world: WorldTrackerPanel, report: DailyReportPanel }[page]

  const s = status
  const totalScraped = (s.total_scraped || 0).toLocaleString()
  const rtActive = s.rt_cycle || 0
  const deepCycle = s.deep_cycle || 0
  const trainingRunning = s.training?.running

  const navItems = [
    { key: 'dashboard', label: 'Dashboard', icon: '◈' },
    { key: 'world', label: 'World', icon: '🌐' },
    { key: 'report', label: 'Report', icon: '📄' },
    { key: 'scraper', label: 'Scraper', icon: '⚡' },
    { key: 'research', label: 'Research', icon: '◎' },
    { key: 'training', label: 'Training', icon: '⟳' },
    { key: 'footprint', label: 'Footprint', icon: '☉' },
    { key: 'company', label: 'Companies', icon: '◆' },
    { key: 'agencies', label: 'Agencies', icon: '●' },
    { key: 'malware', label: 'Malware', icon: '☠' },
    { key: 'tor', label: 'Tor Net', icon: '◉' },
    { key: 'darkwatch', label: 'Dark Web', icon: '◆' },
  ]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="logo">SYS<span className="accent">MON</span></div>
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