import { useState, useEffect, useCallback, useRef } from 'react'
import Dashboard from './Dashboard'
import ScraperPanel from './ScraperPanel'
import TrainingPanel from './TrainingPanel'
import FootprintPanel from './FootprintPanel'

const NAV = [
  { key: 'dashboard', label: 'Dashboard', icon: '◉' },
  { key: 'scraper', label: 'Threat Scraper', icon: '◈' },
  { key: 'training', label: 'AI Training', icon: '◆' },
  { key: 'footprint', label: 'Footprint Analysis', icon: '◎' },
]

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [status, setStatus] = useState({ scraper: {}, training: {} })
  const [connected, setConnected] = useState(false)
  const wsRef = useRef(null)

  const connectWs = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host.includes('5173') ? 'localhost:8000' : window.location.host
    const ws = new WebSocket(`${proto}//${host}/ws`)
    ws.onopen = () => { setConnected(true) }
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.event === 'scrape_update') {
          setStatus(prev => ({ ...prev, scraper: { ...prev.scraper, lastScrape: msg.data } }))
        }
        if (msg.event === 'train_status') {
          setStatus(prev => ({ ...prev, training: { ...prev.training, running: true, samples: msg.data.samples } }))
        }
        if (msg.event === 'train_complete') {
          setStatus(prev => ({ ...prev, training: { ...prev.training, running: false, lastTrain: msg.data } }))
        }
        if (msg.event === 'train_error') {
          setStatus(prev => ({ ...prev, training: { ...prev.training, running: false, error: msg.data.error } }))
        }
      } catch {}
    }
    ws.onclose = () => { setConnected(false); setTimeout(connectWs, 3000) }
    ws.onerror = () => ws.close()
    wsRef.current = ws
  }, [])

  useEffect(() => {
    connectWs()
    fetch('/api/status').then(r => r.json()).then(setStatus).catch(() => {})
    const interval = setInterval(() => {
      fetch('/api/status').then(r => r.json()).then(setStatus).catch(() => {})
    }, 5000)
    return () => { clearInterval(interval); wsRef.current?.close() }
  }, [connectWs])

  const pages = { dashboard: Dashboard, scraper: ScraperPanel, training: TrainingPanel, footprint: FootprintPanel }
  const Page = pages[page]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="logo">AURA <span>AI</span></div>
        <nav>
          {NAV.map(n => (
            <button
              key={n.key}
              className={page === n.key ? 'active' : ''}
              onClick={() => setPage(n.key)}
            >
              {n.icon} {n.label}
            </button>
          ))}
        </nav>
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border)', fontSize: 12, color: 'var(--text-secondary)' }}>
          <span className={`status-dot ${connected ? 'online' : 'offline'}`} />
          {connected ? 'Server Connected' : 'Reconnecting...'}
        </div>
      </aside>
      <main className="main-content">
        <Page status={status} />
      </main>
    </div>
  )
}
