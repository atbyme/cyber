import { useState, useEffect, useCallback, useRef } from 'react'
import Dashboard from './Dashboard'
import ScraperPanel from './ScraperPanel'
import ResearchPanel from './ResearchPanel'
import TrainingPanel from './TrainingPanel'
import FootprintPanel from './FootprintPanel'

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [status, setStatus] = useState({})
  const [connected, setConnected] = useState(false)
  const [notifications, setNotifications] = useState([])
  const [showN, setShowN] = useState(false)
  const [unread, setUnread] = useState(0)
  const ws = useRef(null)

  const connect = useCallback(() => {
    const host = location.host.includes('5173') ? 'localhost:8000' : location.host
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const s = new WebSocket(`${proto}//${host}/ws`)
    s.onopen = () => setConnected(true)
    s.onmessage = e => {
      try {
        const m = JSON.parse(e.data)
        if (m.event === 'notification') { setNotifications(p => [m.data, ...p].slice(0, 300)); setUnread(c => c + 1) }
        if (m.event === 'notifications_cleared') { setNotifications([]); setUnread(0) }
        if (m.event === 'scrape_update' || m.event === 'deep_research_update') setStatus(p => ({ ...p, scraper: { ...p.scraper, lastScrape: m.data } }))
        if (m.event === 'research_update') setStatus(p => ({ ...p, research: m.data }))
        if (m.event === 'train_status') setStatus(p => ({ ...p, training: { ...p.training, running: true, samples: m.data.samples } }))
        if (m.event === 'train_complete') setStatus(p => ({ ...p, training: { ...p.training, running: false, lastTrain: m.data } }))
      } catch {}
    }
    s.onclose = () => { setConnected(false); setTimeout(connect, 2000) }
    ws.current = s
  }, [])

  useEffect(() => {
    connect()
    fetch('/api/status').then(r => r.json()).then(setStatus).catch(() => {})
    fetch('/api/notifications').then(r => r.json()).then(n => { setNotifications(n); setUnread(0) }).catch(() => {})
    const i = setInterval(() => fetch('/api/status').then(r => r.json()).then(setStatus).catch(() => {}), 5000)
    return () => { clearInterval(i); ws.current?.close() }
  }, [connect])

  const clearN = async () => { await fetch('/api/notifications/clear', { method: 'POST' }); setNotifications([]); setUnread(0) }

  const P = { dashboard: Dashboard, scraper: ScraperPanel, research: ResearchPanel, training: TrainingPanel, footprint: FootprintPanel }[page]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="logo">AURA <span>AI</span></div>
        <nav>{Object.entries({ dashboard: '◉ Dashboard', scraper: '◈ Scraper', research: '◎ Research', training: '◆ Training', footprint: '◈ Footprint' }).map(([k, v]) => (
          <button key={k} className={page === k ? 'active' : ''} onClick={() => setPage(k)}>{v}</button>
        ))}</nav>
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-secondary)' }}>
          <span className={`status-dot ${connected ? 'online' : 'offline'}`} />{connected ? 'Live · Research Active' : 'Reconnecting'}
          <div style={{ marginTop: 4 }}>RT: 3min · Deep: 2hr · Cloud: ModelScope</div>
        </div>
      </aside>
      <main style={{ marginLeft: 260, flex: 1, padding: 32, maxWidth: 1400, position: 'relative' }}>
        <div style={{ position: 'fixed', top: 28, right: 28, zIndex: 1000 }}>
          <button className="btn" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', padding: '8px 14px', borderRadius: 8, cursor: 'pointer', color: 'var(--text-primary)', fontSize: 16, position: 'relative' }} onClick={() => setShowN(!showN)}>
            🔔{unread > 0 && <span style={{ position: 'absolute', top: -6, right: -6, background: 'var(--accent-red)', color: 'white', borderRadius: '50%', width: 18, height: 18, fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{unread > 9 ? '9+' : unread}</span>}
          </button>
          {showN && <div style={{ position: 'absolute', top: 44, right: 0, width: 380, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 12, maxHeight: 500, overflow: 'auto', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}><strong style={{ fontSize: 14 }}>Notifications</strong><button onClick={clearN} style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: 12 }}>Clear</button></div>
            {notifications.length === 0 ? <div style={{ padding: 20, color: 'var(--text-secondary)', textAlign: 'center', fontSize: 13 }}>No notifications</div> :
              notifications.map(n => (
                <div key={n.id} style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', borderLeft: `3px solid ${n.level === 'error' ? 'var(--accent-red)' : n.level === 'warning' ? 'var(--accent-yellow)' : 'var(--accent-green)'}` }}>
                  <div style={{ fontSize: 13, fontWeight: 500 }}>{n.title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{n.message}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2, opacity: 0.5 }}>{new Date(n.timestamp).toLocaleTimeString()}</div>
                </div>
              ))}
          </div>}
        </div>
        <P status={status} />
      </main>
    </div>
  )
}
