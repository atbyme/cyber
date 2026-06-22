import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts'

// OpSec: no hostname leak — use relative protocol
const WS_PROTO = location.protocol === 'https:' ? 'wss:' : 'ws:'

const COLORS = { critical: '#ef4444', high: '#f59e0b', medium: '#06b6d4', low: '#8b5cf6' }
const TYPE_COLORS = { cve: '#ef4444', ioc: '#f59e0b', botnet: '#f97316', malicious_ssl: '#ec4899', malicious_url: '#8b5cf6', phishing_url: '#a855f7', malware_url: '#d946ef', exploit: '#ef4444', cert: '#06b6d4', pulse: '#14b8a6', crawl_result: '#64748b', social_media: '#f59e0b', research_paper: '#8b5cf6' }

function riskLevel(score) {
  if (!score || score < 10) return 'low'
  if (score < 40) return 'medium'
  if (score < 70) return 'high'
  return 'critical'
}

function ThreatCard({ t, onClick }) {
  const risk = riskLevel(t.score)
  const url = t.url || t.ioc || ''
  const desc = t.instruction || t.response || t.description || ''
  return (
    <div className={`threat-card ${risk}`} style={{ cursor: 'pointer' }} onClick={() => onClick?.(t)}>
      <div className="threat-card-header">
        <span className={`threat-card-type ${risk}`}>{t.type || 'unknown'}</span>
        <span className={`threat-card-risk ${risk}`}>{risk.toUpperCase()} {(t.score || 0)}</span>
      </div>
      <div className="threat-card-source">{t.source || 'unknown'}</div>
      {desc && <div className="threat-card-desc" title={desc}>{desc.slice(0, 160)}</div>}
      {url && <div className="threat-card-url" title={url}>{url.slice(0, 100)}</div>}
      <div className="threat-card-meta">
        <span className="threat-card-time">{new Date(t.t || Date.now()).toLocaleTimeString()}</span>
        {t.malware && <span>Malware: {t.malware}</span>}
        {t.cvss_score && <span>CVSS: {t.cvss_score}</span>}
      </div>
    </div>
  )
}

function SocialFeed() {
  const [feed, setFeed] = useState([])
  const [loading, setLoading] = useState(true)
  const [scraperStatus, setScraperStatus] = useState(null)
  useEffect(() => {
    const load = async () => {
      try {
        const [tR, sR] = await Promise.all([
          fetch('/api/threats?limit=300').then(r=>r.json()),
          fetch('/api/scrapers/status').then(r=>r.json()).catch(()=>null),
        ])
        const threats = Array.isArray(tR) ? tR : []
        const social = threats.filter(t => t.source === 'reddit_cyber' || t.source === 'hackernews' || t.source === 'arxiv_cyber' || t.source === 'bleepingcomputer' || t.source === 'thehackernews')
        setFeed(social.length > 0 ? social.slice(0, 30) : threats.slice(0, 30))
        setScraperStatus(sR)
      } catch {}
      setLoading(false)
    }
    load()
    const i = setInterval(load, 15000)
    return () => clearInterval(i)
  }, [])
  if (loading) return <div className="soc-empty">Loading intelligence feed...</div>
  if (feed.length === 0) return <div className="soc-empty">Collecting threat intelligence data — system online</div>
  const isLive = scraperStatus?.internet_connected && scraperStatus?.source_live > 0
  return (
    <div className="soc-versions">
      {!isLive && <div style={{fontSize:7,color:'var(--accent-yellow)',marginBottom:4,padding:'2px 4px',background:'rgba(245,158,11,0.1)',borderRadius:3}}>⚠ OFFLINE MODE — showing reference data</div>}
      {feed.map((t, i) => {
        const srcColor = { reddit_cyber: '#ff4500', hackernews: '#f60', arxiv_cyber: '#8b5cf6', bleepingcomputer: '#06b6d4', thehackernews: '#ef4444' }
        const color = srcColor[t.source] || '#64748b'
        return (
          <div key={i} className="soc-ver" style={{ fontSize: 10, borderLeft: `2px solid ${color}`, paddingLeft: 6 }}>
            <span className="soc-tag" style={{ background: color, marginRight: 6 }}>{t.source || 'threat'}</span>
            <span style={{ color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.description?.slice(0, 120) || t.instruction?.slice(0, 80) || t.url?.slice(0, 60) || t.ioc?.slice(0, 40) || '-'}
            </span>
            <span className="soc-ver-time">{new Date(t.t || Date.now()).toLocaleTimeString()}</span>
          </div>
        )
      })}
    </div>
  )
}

function LiveWorldTracker() {
  const [mapData, setMapData] = useState([])
  const [agencyAct, setAgencyAct] = useState([])
  const [companyAtt, setCompanyAtt] = useState([])
  const [total, setTotal] = useState(0)
  useEffect(() => {
    const load = async () => {
      try {
        const [mapR, agR, coR] = await Promise.all([
          fetch('/api/threats/map').then(r=>r.json()),
          fetch('/api/agencies/activity').then(r=>r.json()),
          fetch('/api/companies/attacks').then(r=>r.json()),
        ])
        setMapData(mapR.map || [])
        setTotal(mapR.total_threats_mapped || 0)
        setAgencyAct(Object.entries(agR.agencies || {}).map(([k,v]) => ({id:k,...v})))
        setCompanyAtt((coR.companies || []).map(c => ({name:c.name,attacks:c.total_attacks,current:c.current_threats})))
      } catch {}
    }
    load()
    const i = setInterval(load, 10000)
    return () => clearInterval(i)
  }, [])
  const topThreats = mapData.slice(0, 10)
  const totalWorldThreats = mapData.reduce((s, c) => s + c.count, 0)
  return (
    <>
      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">WORLD THREAT MAP <span className="chart-badge">{mapData.length} countries</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topThreats.length > 0 ? topThreats : [{country:'...',count:0}]} layout="vertical">
                <XAxis type="number" tick={{fontSize:8,fill:'#94a3b8'}} />
                <YAxis type="category" dataKey="country" tick={{fontSize:8,fill:'#94a3b8'}} width={30} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="count" radius={[0,3,3,0]}>
                  {topThreats.map((e,i) => <Cell key={i} fill={e.count > totalWorldThreats/5 ? '#ef4444' : e.count > totalWorldThreats/10 ? '#f59e0b' : '#06b6d4'}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={{fontSize:8,color:'var(--text-secondary)',textAlign:'center',marginTop:4}}>{totalWorldThreats.toLocaleString()} threats mapped across {mapData.length} countries</div>
        </div>
        <div className="chart-container">
          <div className="chart-title">INTELLIGENCE AGENCY <span className="chart-badge">{agencyAct.length} agencies</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={agencyAct.length > 0 ? agencyAct.map(a => ({name:a.name,threats:a.total_threats||0})) : [{name:'...',threats:0}]}>
                <XAxis dataKey="name" tick={{fontSize:7,fill:'#94a3b8'}} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="threats" radius={[3,3,0,0]}>
                  {agencyAct.map((a,i) => <Cell key={i} fill={a.color||'#8b5cf6'}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">COMPANY ATTACKS <span className="chart-badge">{companyAtt.length} companies</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={companyAtt.length > 0 ? companyAtt : [{name:'...',attacks:0}]}>
                <XAxis dataKey="name" tick={{fontSize:7,fill:'#94a3b8'}} angle={-20} textAnchor="end" height={40} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="attacks" fill="#f59e0b" radius={[3,3,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">SOCIAL MEDIA FEED <span className="chart-badge">Reddit HN arXiv BC THN</span></div>
          <div style={{height:'100%',overflow:'auto'}}>
            <SocialFeed />
          </div>
        </div>
      </div>
    </>
  )
}

export default function Dashboard({ status: initialStatus, onThreatClick }) {
  const [status, setStatus] = useState(initialStatus || {})
  const [allThreats, setAllThreats] = useState([])
  const [knowledge, setKnowledge] = useState({ cves: 0, iocs: 0, malware: 0, urls: 0, total: 0, history: [] })
  const [sources, setSources] = useState({})
  const [versions, setVersions] = useState([])
  const [activity, setActivity] = useState([])
  const [liveSources, setLiveSources] = useState({})
  const [insights, setInsights] = useState([])
  const [filterType, setFilterType] = useState('all')
  const [filterRisk, setFilterRisk] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState('cards')
  const [threatHistory, setThreatHistory] = useState([])
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const wsRef = useRef(null)
  const pollRef = useRef(null)

  const fetchThreats = useCallback(() => {
    fetch('/api/threats?limit=200').then(r => r.json()).then(t => {
      setAllThreats(t)
      setThreatHistory(prev => {
        const now = Date.now()
        const recent = t.filter(th => th.t && (now - new Date(th.t).getTime()) < 300000)
        const updated = [...prev, ...recent.map(th => ({ ...th, bucket: new Date(th.t || now).toLocaleTimeString() }))]
        return updated.slice(-500)
      })
    }).catch(() => {})
  }, [])

  const fetchAll = useCallback(() => {
    fetch('/api/status').then(r => r.json()).then(setStatus).catch(() => {})
    fetchThreats()
    fetch('/api/knowledge').then(r => r.json()).then(setKnowledge).catch(() => {})
    fetch('/api/sources').then(r => r.json()).then(setSources).catch(() => {})
    fetch('/api/train/versions').then(r => r.json()).then(d => setVersions(d.versions || [])).catch(() => {})
    fetch('/api/insights').then(r => r.json()).then(setInsights).catch(() => {})
  }, [fetchThreats])

  useEffect(() => {
    fetchAll()
    pollRef.current = setInterval(fetchAll, 3000)
    return () => clearInterval(pollRef.current)
  }, [fetchAll])

  useEffect(() => {
    const ws = new WebSocket(`${WS_PROTO}//${location.host}/ws`)
    wsRef.current = ws
    ws.onmessage = e => {
      try {
        const m = JSON.parse(e.data)
        const now = new Date().toLocaleTimeString()

        if (m.event === 'source_result') {
          setLiveSources(p => ({ ...p, [m.data.source]: { count: m.data.count, scan_type: m.data.scan_type, cycle: m.data.cycle, t: m.t, fresh: true } }))
          setTimeout(() => setLiveSources(p => {
            const n = { ...p }
            if (n[m.data.source]) n[m.data.source] = { ...n[m.data.source], fresh: false }
            return n
          }), 2000)
          setThreatHistory(prev => [...prev, { type: 'source_result', source: m.data.source, count: m.data.count, bucket: now }].slice(-500))
          fetchThreats()
        }

        if (m.event === 'research' || m.event === 'deep_research') {
          setActivity(p => [{ event: m.event, data: m.data, t: m.t }, ...p].slice(0, 150))
          if (m.data.knowledge) setKnowledge(m.data.knowledge)
          setThreatHistory(prev => [...prev, { type: m.event, count: m.data.count, bucket: now }].slice(-500))
          generateAiInsight(m)
          fetchThreats()
        }

        if (m.event === 'crawl') {
          setActivity(p => [{ event: m.event, data: m.data, t: m.t }, ...p].slice(0, 150))
          fetchThreats()
        }

        if (m.event === 'passive_scan') {
          setActivity(p => [{ event: m.event, data: m.data, t: m.t }, ...p].slice(0, 150))
          fetchThreats()
        }

        if (m.event === 'footprint') {
          setActivity(p => [{ event: m.event, data: m.data, t: m.t }, ...p].slice(0, 150))
        }

        if (m.event === 'research_insights') {
          setActivity(p => [{ event: 'insights', data: m.data, t: m.t }, ...p].slice(0, 150))
          setInsights(m.data.insights || [])
        }

        if (m.event === 'train_complete') {
          setVersions(p => [{ cycle: m.data.cycle, version: m.data.version, samples: m.data.samples, t: m.t }, ...p].slice(0, 50))
          setActivity(p => [{ event: 'train_complete', data: m.data, t: m.t }, ...p].slice(0, 150))
        }

        if (m.event === 'notification') {
          setActivity(p => [{ event: 'notif', data: m.data, t: m.t }, ...p].slice(0, 150))
        }

        if (m.event === 'research_collected') {
          setActivity(p => [{ event: 'research_collected', data: m.data, t: m.t }, ...p].slice(0, 150))
        }
      } catch {}
    }
    ws.onclose = () => {
      setTimeout(() => {
        if (wsRef.current === ws) {
          const w = new WebSocket(`${WS_PROTO}//${location.host}/ws`)
          wsRef.current = w
        }
      }, 2000)
    }
    return () => { ws.close(); if (wsRef.current !== ws) wsRef.current?.close() }
  }, [fetchThreats])

  function generateAiInsight(m) {
    const types = m.data.types || {}
    const typeEntries = Object.entries(types)
    const topType = typeEntries.sort((a, b) => b[1] - a[1])[0]
    let insight = `Scan complete — ${m.data.count} threats. `
    if (topType) insight += `Dominant: ${topType[0]} (${topType[1]}). `
    if (m.data.count > 100) insight += '⚠ High volume detected. '
    if (typeEntries.length > 5) insight += 'Broad threat diversity. '
    if (m.data.sources) {
      const srcEntries = Object.entries(m.data.sources)
      const topSrc = srcEntries.sort((a, b) => b[1] - a[1])[0]
      if (topSrc) insight += `Top source: ${topSrc[0]} (${topSrc[1]} threats). `
    }
    setAiAnalysis({ insight, at: new Date().toLocaleTimeString(), cycle: m.data.cycle, count: m.data.count })
  }

  const k = knowledge; const s = status
  const totalK = (k.cves || 0) + (k.iocs || 0) + (k.malware || 0) + (k.urls || 0)
  const sourceCount = Object.keys(sources).length
  const lastEvent = activity[0]

  const filteredThreats = useMemo(() => {
    let ft = allThreats
    if (filterType !== 'all') ft = ft.filter(t => t.type === filterType)
    if (filterRisk !== 'all') ft = ft.filter(t => riskLevel(t.score) === filterRisk)
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      ft = ft.filter(t =>
        (t.instruction || '').toLowerCase().includes(q) ||
        (t.response || '').toLowerCase().includes(q) ||
        (t.url || '').toLowerCase().includes(q) ||
        (t.ioc || '').toLowerCase().includes(q) ||
        (t.source || '').toLowerCase().includes(q)
      )
    }
    return ft
  }, [allThreats, filterType, filterRisk, searchQuery])

  const uniqueTypes = useMemo(() => [...new Set(allThreats.map(t => t.type).filter(Boolean))], [allThreats])

  const typeDist = useMemo(() => {
    const map = {}
    allThreats.slice(0, 300).forEach(t => { if (t.type) map[t.type] = (map[t.type] || 0) + 1 })
    return Object.entries(map).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  }, [allThreats])

  const sourceDist = useMemo(() => {
    const map = {}
    allThreats.slice(0, 300).forEach(t => { if (t.source) map[t.source] = (map[t.source] || 0) + 1 })
    return Object.entries(map).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 10)
  }, [allThreats])

  const riskDist = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }
    allThreats.slice(0, 300).forEach(t => { counts[riskLevel(t.score)]++ })
    return Object.entries(counts).map(([name, value]) => ({ name, value }))
  }, [allThreats])

  const timelineData = useMemo(() => {
    const buckets = {}
    const now = Date.now()
    threatHistory.forEach(t => {
      const key = t.bucket || new Date(t.t || now).toLocaleTimeString()
      if (!buckets[key]) buckets[key] = { time: key, threats: 0, scans: 0 }
      buckets[key].threats += t.count || 1
      buckets[key].scans++
    })
    return Object.values(buckets).slice(-20)
  }, [threatHistory])

  const knowledgeGrowth = useMemo(() => {
    const hist = k.history || []
    return hist.slice(-30).map(h => ({
      cycle: `#${h.cycle}`, total: h.cves + h.iocs + h.malware + h.urls,
      cves: h.cves || 0, iocs: h.iocs || 0, urls: h.urls || 0,
    }))
  }, [k])

  const ticker = lastEvent ? {
    research: `RT SCAN: ${lastEvent.data.count} threats from ${Object.keys(lastEvent.data.sources || {}).length} sources`,
    deep_research: `DEEP SCAN #${lastEvent.data.cycle}: ${lastEvent.data.count} threats across ${Object.keys(lastEvent.data.sources || {}).length} sources`,
    crawl: `CRAWL: ${lastEvent.data.count} pages, ${lastEvent.data.threat_pages || 0} threats`,
    passive_scan: `PASSIVE: ${lastEvent.data.count} targets analyzed`,
    train_complete: `TRAINED v${lastEvent.data.version}: ${lastEvent.data.samples} samples to ModelScope`,
    train_status: 'TRAINING ON MODELScope CLOUD GPU...',
    insights: (lastEvent.data.insights?.[0]?.message) || 'Research insights ready',
    footprint: `FOOTPRINT: ${lastEvent.data.count} analyzed, ${lastEvent.data.malicious} malicious`,
    notif: lastEvent.data.title,
    research_collected: `RESEARCH: ${lastEvent.data.threat_count} threats, ${lastEvent.data.countries_mapped} countries mapped`,
  }[lastEvent.event] : 'INITIALIZING...'

  const totalRiskScore = useMemo(() => allThreats.slice(0, 300).reduce((sum, t) => sum + (t.score || 0), 0), [allThreats])
  const highValueThreats = useMemo(() => allThreats.filter(t => (t.score || 0) >= 40).length, [allThreats])
  const liveEntries = Object.entries(liveSources)

  const latestThreats = useMemo(() => allThreats.slice(0, 10), [allThreats])

  return (
    <div>
      <div className="soc-header">
        <div className="soc-title">
          <span className="soc-glitch">CORE</span>
          <span className="soc-sub">CYBER THREAT INTELLIGENCE · AI-POWERED SOC · 24/7 REAL-TIME TRACKING</span>
        </div>
        <div className="soc-status">
          <span className={`soc-dot ${s.active ? '' : 'off'}`} />
          <span className="soc-mode">{s.active ? 'LIVE 24/7' : 'STANDBY'}</span>
          <span className="soc-cycles">RT:{s.rt_cycle||0} · DEEP:{s.deep_cycle||0}</span>
        </div>
      </div>

      <div className="soc-ticker">
        <span className="ticker-label">LIVE</span>
        <span className="ticker-text" key={ticker}>{ticker}</span>
        <span className="soc-badge sec">{allThreats.length} threats</span>
      </div>

      {aiAnalysis && (
        <div className="ai-insight-panel">
          <div className="ai-insight-header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            AI THREAT ANALYSIS · Cycle #{aiAnalysis.cycle} · {aiAnalysis.count} threats
            <span className="soc-badge sec">{aiAnalysis.at}</span>
          </div>
          <div className="ai-insight-body">{aiAnalysis.insight}</div>
        </div>
      )}

      <div className="threat-ticker-wrap">
        <div className="threat-ticker-inner">
          {allThreats.slice(0, 20).map((t, i) => {
            const risk = riskLevel(t.score)
            return (
              <span key={i} className="threat-ticker-item">
                <span className={`threat-ticker-dot ${risk}`} />
                <span className="soc-tag" style={{ fontSize: 8, padding: '0 4px' }}>{t.type?.slice(0, 6) || '?'}</span>
                {t.instruction?.slice(0, 50) || t.url?.slice(0, 50) || t.ioc?.slice(0, 40) || t.response?.slice(0, 40) || '-'}
              </span>
            )
          })}
        </div>
      </div>

      <div className="scan-wave">
        <div className="scan-wave-inner">
          {liveEntries.slice(0, 16).map(([name, info], i) => (
            <div key={name} className="scan-wave-bar" style={{ height: `${Math.min(100, (info.count || 1) * 5)}%`, opacity: info.fresh ? 1 : 0.4 }} title={`${name}: +${info.count}`} />
          ))}
          {liveEntries.length === 0 && <span style={{ fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>WAITING FOR SCRAPE DATA...</span>}
        </div>
      </div>

      {liveEntries.length > 0 && (
        <div className="soc-panel" style={{ marginBottom: 14 }}>
          <div className="soc-panel-header">
            THREAT INTELLIGENCE BUREAU — ACTIVE SCRAPING <span className="soc-badge">{liveEntries.length} sources</span>
            <span className="soc-badge sec">{(s.total_scraped || 0).toLocaleString()} total</span>
          </div>
          <div className="scrape-animation">
            {liveEntries.slice(0, 20).map(([name, info]) => {
              const h = Math.min(100, (info.count || 1) * 8)
              const level = info.count > 50 ? 'critical' : info.count > 20 ? 'high' : info.count > 5 ? 'medium' : 'low'
              return (
                <div key={name} className={`scrape-bar anim-${level}`} style={{ height: `${h}%`, opacity: info.fresh ? 1 : 0.5 }} title={`${name}: +${info.count}`}>
                  <div style={{ fontSize: 6, textAlign: 'center', color: 'var(--text-secondary)', marginTop: 2 }}>{name.slice(0, 4)}</div>
                </div>
              )
            })}
          </div>
          <div className="source-grid-live" style={{ marginTop: 4 }}>
            {liveEntries.map(([name, info]) => (
              <div key={name} className={`source-live-item ${info.fresh ? 'active' : ''}`}>
                <span className="src-name">{name}</span>
                <span className="src-count">+{info.count} · {info.scan_type}#{info.cycle}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* LIVE WORLD TRACKER - Threat Map, Agencies, Companies, Social */}
      <LiveWorldTracker />

      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{(s.total_scraped || 0).toLocaleString()}</div>
          <div className="soc-stat-lbl">THREATS SCRAPED</div>
          <div className="soc-stat-sub">{s.last_scrape ? new Date(s.last_scrape).toLocaleTimeString() : '--'}</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{totalK.toLocaleString()}</div>
          <div className="soc-stat-lbl">AI KNOWLEDGE ITEMS</div>
          <div className="soc-stat-sub">CVE:{k.cves||0} IOC:{k.iocs||0} MAL:{k.malware||0} URL:{k.urls||0}</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{highValueThreats}</div>
          <div className="soc-stat-lbl">HIGH-VALUE THREATS</div>
          <div className="soc-stat-sub">{'Risk score >= 40'} | {totalRiskScore.toLocaleString()} total risk</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{(s.training?.total_samples || 0).toLocaleString()}</div>
          <div className="soc-stat-lbl">TRAINED SAMPLES</div>
          <div className="soc-stat-sub">{versions.length} versions | {s.training?.running ? 'TRAINING' : 'ModelScope'}</div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">THREAT TIMELINE <span className="chart-badge">Last 5 min</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData.length > 0 ? timelineData : [{ time: '...', threats: 0, scans: 0 }]}>
                <defs><linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient></defs>
                <XAxis dataKey="time" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#colorThreats)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">THREAT TYPE DISTRIBUTION <span className="chart-badge">{typeDist.length} types</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={typeDist.slice(0, 8)} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 8, fill: '#94a3b8' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 7, fill: '#94a3b8' }} width={65} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                  {typeDist.slice(0, 8).map((entry, i) => <Cell key={i} fill={TYPE_COLORS[entry.name] || '#64748b'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">SOURCE BREAKDOWN <span className="chart-badge">{sourceDist.length} sources</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={sourceDist.slice(0, 6)} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} innerRadius={30}>
                  {sourceDist.slice(0, 6).map((entry, i) => <Cell key={i} fill={['#06b6d4','#f59e0b','#8b5cf6','#ef4444','#10b981','#ec4899'][i]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Legend wrapperStyle={{ fontSize: 8, color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">RISK SEVERITY <span className="chart-badge">{allThreats.length} threats</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskDist}>
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 9, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {riskDist.map((entry, i) => <Cell key={i} fill={COLORS[entry.name] || '#64748b'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {knowledgeGrowth.length > 1 && (
        <div className="chart-container" style={{ marginBottom: 14 }}>
          <div className="chart-title">KNOWLEDGE GROWTH <span className="chart-badge">{knowledgeGrowth.length} cycles</span></div>
          <div className="chart-wrap" style={{ height: 120 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={knowledgeGrowth}>
                <defs><linearGradient id="knowGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3}/><stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/></linearGradient></defs>
                <XAxis dataKey="cycle" tick={{ fontSize: 7, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 7, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ background: '#1a2332', border: '1px solid #2d3a50', borderRadius: 6, fontSize: 10 }} />
                <Area type="monotone" dataKey="total" stroke="#8b5cf6" fill="url(#knowGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="filters-bar">
        <span className="filter-label">Type</span>
        <button className={`filter-btn ${filterType === 'all' ? 'active' : ''}`} onClick={() => setFilterType('all')}>All</button>
        {uniqueTypes.slice(0, 8).map(t => (
          <button key={t} className={`filter-btn ${filterType === t ? 'active' : ''}`} onClick={() => setFilterType(t)}>{t}</button>
        ))}
        <span className="filter-label" style={{ marginLeft: 8 }}>Risk</span>
        {['all', 'critical', 'high', 'medium', 'low'].map(r => (
          <button key={r} className={`filter-btn ${filterRisk === r ? 'active' : ''}`} onClick={() => setFilterRisk(r)}>{r.toUpperCase()}</button>
        ))}
        <span className="filter-label" style={{ marginLeft: 8 }}>View</span>
        <button className={`filter-btn ${viewMode === 'cards' ? 'active' : ''}`} onClick={() => setViewMode('cards')}>Cards</button>
        <button className={`filter-btn ${viewMode === 'table' ? 'active' : ''}`} onClick={() => setViewMode('table')}>Table</button>
        <input className="filter-search" placeholder="Search threats, URLs, IOCs..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
      </div>

      <div className="soc-grid">
        <div className="soc-panel feed">
          <div className="soc-panel-header">
            {viewMode === 'cards' ? 'THREAT INTELLIGENCE CARDS' : 'THREAT TABLE'} <span className="soc-badge">{filteredThreats.length}</span>
            <span className="soc-badge sec">RT 3S POLL</span>
          </div>
          {viewMode === 'cards' ? (
            <div className="threat-grid">
              {filteredThreats.slice(0, 60).map((t, i) => <ThreatCard key={`${t.t}-${i}`} t={t} onClick={onThreatClick} />)}
              {filteredThreats.length === 0 && <div className="soc-empty">No threats match filters</div>}
            </div>
          ) : (
            <div className="soc-feed">
              <table className="soc-table">
                <thead><tr><th style={{ width: 20 }}>#</th><th style={{ width: 48 }}>TYPE</th><th style={{ width: 40 }}>SRC</th><th>THREAT CONTENT / URL / DESCRIPTION</th><th style={{ width: 35 }}>RISK</th><th style={{ width: 55 }}>TIME</th></tr></thead>
                <tbody>
                  {filteredThreats.slice(0, 50).map((t, i) => (
                    <tr key={`${t.t}-${i}`} className="soc-tr">
                      <td className="soc-idx">{i + 1}</td>
                      <td><span className={`soc-tag ${t.type === 'cve' ? 'cve' : ['ioc','botnet','malicious_ssl'].includes(t.type) ? 'ioc' : ['malicious_url','phishing_url','malware_url'].includes(t.type) ? 'url' : 'info'}`}>{t.type?.slice(0, 10)}</span></td>
                      <td className="soc-src">{t.source?.slice(0, 8)}</td>
                      <td className="soc-desc" title={t.instruction || t.response || t.url || t.ioc || t.description}>{t.instruction?.slice(0, 120) || t.response?.slice(0, 120) || t.url?.slice(0, 80) || t.ioc?.slice(0, 60) || t.description?.slice(0, 80) || '-'}</td>
                      <td><span className={`soc-tag ${riskLevel(t.score) === 'critical' ? 'cve' : riskLevel(t.score) === 'high' ? 'ioc' : riskLevel(t.score) === 'medium' ? 'url' : 'info'}`}>{t.score || 0}</span></td>
                      <td className="soc-time">{new Date(t.t || Date.now()).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                  {filteredThreats.length === 0 && <tr><td colSpan={6} className="soc-empty">No threats match current filters</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="soc-side">
          <div className="soc-panel">
            <div className="soc-panel-header">AI KNOWLEDGE BASE <span className="soc-badge">{s.train_cycle || 0} cycles</span></div>
            <div className="soc-kgrid">
              {[
                { l: 'CVEs', v: (k.cves || 0).toLocaleString(), c: 'var(--accent-red)', p: totalK > 0 ? ((k.cves || 0) / totalK * 100).toFixed(1) : 0 },
                { l: 'IOCs', v: (k.iocs || 0).toLocaleString(), c: 'var(--accent-yellow)', p: totalK > 0 ? ((k.iocs || 0) / totalK * 100).toFixed(1) : 0 },
                { l: 'Malware', v: (k.malware || 0).toLocaleString(), c: 'var(--accent-cyan)', p: totalK > 0 ? ((k.malware || 0) / totalK * 100).toFixed(1) : 0 },
                { l: 'URLs', v: (k.urls || 0).toLocaleString(), c: 'var(--accent-purple)', p: totalK > 0 ? ((k.urls || 0) / totalK * 100).toFixed(1) : 0 },
              ].map((x, i) => (
                <div key={i} className="soc-kitem">
                  <div className="soc-klbl">{x.l}</div>
                  <div className="soc-kval" style={{ color: x.c }}>{x.v}</div>
                  <div className="soc-kbar"><div className="soc-kfill" style={{ width: `${x.p}%`, background: x.c }} /></div>
                </div>
              ))}
              <div className="soc-kitem total">
                <div className="soc-klbl" style={{ fontWeight: 600 }}>TOTAL</div>
                <div className="soc-kval" style={{ color: 'white' }}>{totalK.toLocaleString()}</div>
                <div className="soc-kbar"><div className="soc-kfill" style={{ width: '100%', background: 'linear-gradient(90deg, var(--accent-red), var(--accent-purple))' }} /></div>
              </div>
            </div>
            <div className="progress-track"><div className="progress-fill" style={{ width: `${Math.min(100, (totalK / 10000) * 100)}%` }} /></div>
          </div>

          {insights.length > 0 && (
            <div className="soc-panel">
              <div className="soc-panel-header">AI RESEARCH INSIGHTS</div>
              {insights.slice(0, 5).map((ins, i) => (
                <div key={i} className="soc-ver" style={{ fontSize: 10, flexDirection: 'column', alignItems: 'flex-start', gap: 2 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                    <span className={`soc-tag ${ins.type === 'high_confidence' ? 'cve' : ins.type === 'trending_up' ? 'ioc' : 'info'}`}>{ins.type}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{ins.message}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="soc-panel">
            <div className="soc-panel-header">LATEST THREATS <span className="soc-badge">{latestThreats.length}</span></div>
            <div className="soc-versions">
              {latestThreats.map((t, i) => (
                <div key={i} className="soc-ver" style={{ fontSize: 10 }}>
                  <span className={`soc-tag ${t.type === 'cve' ? 'cve' : ['ioc','botnet'].includes(t.type) ? 'ioc' : 'url'}`} style={{ marginRight: 6 }}>{t.type?.slice(0, 6)}</span>
                  <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{t.instruction?.slice(0, 40) || t.url?.slice(0, 40) || t.ioc?.slice(0, 40) || '-'}</span>
                  <span className="soc-ver-time">{new Date(t.t || Date.now()).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header">SOCIAL MEDIA & JOURNAL INTELLIGENCE <span className="soc-badge sec">5 SOURCES</span></div>
            <SocialFeed />
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header">MODEL SCOPE DATASETS <span className="soc-badge">{versions.length}</span></div>
            <div className="soc-versions">
              {versions.length > 0 ? [...versions].reverse().slice(0, 10).map((v, i) => (
                <div key={i} className="soc-ver">
                  <span className="soc-ver-id">#{v.cycle}</span>
                  <span className="soc-ver-name">{v.version}</span>
                  <span className="soc-ver-samples">{(v.samples || 0).toLocaleString()} samples</span>
                  <span className="soc-ver-time">{new Date(v.t).toLocaleTimeString()}</span>
                </div>
              )) : <div className="soc-empty">First training on ModelScope cloud pending...</div>}
            </div>
          </div>
        </div>
      </div>

      <div className="soc-panel" style={{ marginTop: 14 }}>
        <div className="soc-panel-header">
          REAL-TIME ACTIVITY STREAM <span className="soc-badge">{activity.length} events</span>
          <span className="soc-badge sec">{s.active ? 'LIVE' : 'OFFLINE'}</span>
        </div>
        <div className="soc-activity">
          <table className="soc-table">
            <thead><tr><th style={{ width: 65 }}>EVENT</th><th style={{ width: 35 }}>COUNT</th><th>DETAILS</th><th style={{ width: 60 }}>TIME</th></tr></thead>
            <tbody>
              {activity.slice(0, 20).map((a, i) => {
                const d = a.data
                const detail = {
                  research: `${d.count} threats, ${Object.keys(d.sources || {}).length} sources`,
                  deep_research: `Deep #${d.cycle}: ${d.count} threats`,
                  crawl: `${d.count} pages, ${d.threat_pages || 0} threats`,
                  passive_scan: `${d.count} targets scanned`,
                  train_complete: `v${d.version}: ${d.samples} samples to ModelScope`,
                  train_status: `${d.samples} samples training...`,
                  insights: (d.insights || []).slice(0, 2).map(x => x.message).join(' | ') || `${d.clusters} clusters`,
                  footprint: `${d.count} footprints, ${d.malicious} malicious`,
                  notif: d.title || '',
                  research_collected: `${d.threat_count} threats, ${d.countries_mapped} countries`,
                }[a.event] || ''
                return (
                  <tr key={i} className="soc-tr">
                    <td><span className={`soc-tag ${a.event === 'deep_research' ? 'cve' : a.event === 'crawl' || a.event === 'passive_scan' ? 'info' : a.event === 'train_complete' ? 'url' : a.event === 'footprint' ? 'ioc' : a.event === 'research_collected' ? 'url' : 'url'}`}>{a.event}</span></td>
                    <td style={{ fontWeight: 600 }}>{d.count || d.samples || '-'}</td>
                    <td className="soc-desc">{detail}</td>
                    <td className="soc-time">{new Date(a.t).toLocaleTimeString()}</td>
                  </tr>
                )
              })}
              {activity.length === 0 && <tr><td colSpan={4} className="soc-empty">Waiting for first scan...</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="soc-panel" style={{ marginTop: 14 }}>
        <div className="soc-panel-header">ALL DATA SOURCES <span className="soc-badge">{sourceCount}</span><span className="soc-badge sec">100+ SOURCES</span></div>
        <div className="soc-sources">
          {(Object.entries(sources).length > 0 ? Object.entries(sources) : []).map(([id, name]) => (
            <div key={id} className="soc-src-chip">
              <span className="soc-src-id">{id}</span>
              <span className="soc-src-name">{name}</span>
              <span className="soc-src-count">{allThreats.filter(t => t.source === id).length}</span>
            </div>
          ))}
        </div>
      </div>

      <AgencyTracker />
    </div>
  )
}

const AGENCY_LIST = [
  { id: 'nsa', name: 'NSA', country: 'USA', color: '#ef4444', focus: 'Mass surveillance, cyber warfare' },
  { id: 'mossad', name: 'Mossad', country: 'Israel', color: '#06b6d4', focus: 'Cyber espionage, zero-day ops' },
  { id: 'gru', name: 'GRU', country: 'Russia', color: '#ec4899', focus: 'Destructive malware, disinfo' },
  { id: 'msrc', name: 'MSS', country: 'China', color: '#f97316', focus: 'Supply chain attacks, IP theft' },
  { id: 'gchq', name: 'GCHQ', country: 'UK', color: '#8b5cf6', focus: 'Sigint, fiber tapping' },
  { id: 'raw', name: 'RAW', country: 'India', color: '#f59e0b', focus: 'Counter-terror, dark web' },
  { id: 'isi', name: 'ISI', country: 'Pakistan', color: '#10b981', focus: 'APT ops, Android malware' },
]

function AgencyTracker() {
  const [agencies, setAgencies] = useState([])
  const [agencyAct, setAgencyAct] = useState({})
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [agR, actR] = await Promise.all([
          fetch('/api/agencies').then(r => r.json()),
          fetch('/api/agencies/activity').then(r => r.json()),
        ])
        setAgencies(Object.entries(agR.agencies || {}))
        setAgencyAct(actR.agencies || {})
      } catch {}
    }
    load()
    const i = setInterval(load, 15000)
    return () => clearInterval(i)
  }, [])

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        INTELLIGENCE AGENCY TRACKING — PASSIVE OSINT
        <span className="soc-badge">{AGENCY_LIST.length} agencies</span>
        <span className="soc-badge sec">REAL-TIME</span>
      </div>
      <div className="soc-sources" style={{ flexDirection: 'column', gap: 4 }}>
        {AGENCY_LIST.map(a => {
          const live = agencyAct[a.id] || {}
          const threatCount = live.total_threats || 0
          return (
            <div key={a.id} className="soc-src-chip" style={{ borderColor: a.color, cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch' }}
              onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
                <span className="soc-src-id" style={{ color: a.color }}>{a.id.toUpperCase()}</span>
                <span style={{ fontSize: 10, fontWeight: 600 }}>{a.name}</span>
                <span style={{ fontSize: 8, color: 'var(--text-secondary)' }}>{a.country}</span>
                <span style={{ fontSize: 8, color: threatCount > 10 ? '#ef4444' : threatCount > 0 ? '#f59e0b' : 'var(--text-secondary)', fontWeight: 600 }}>{threatCount} threats</span>
                <span style={{ fontSize: 8, color: 'var(--text-secondary)', marginLeft: 'auto' }}>{a.focus}</span>
              </div>
              {live.timeline && live.timeline.length > 0 && (
                <div style={{ display: 'flex', gap: 2, marginTop: 4, height: 16, alignItems: 'flex-end' }}>
                  {live.timeline.slice(-20).map((p, i) => (
                    <div key={i} style={{ width: '4%', height: `${Math.min(100, (p.count || 1) * 10)}%`, background: a.color, opacity: 0.7, borderRadius: '1px 1px 0 0' }} title={`#${p.cycle}: ${p.count}`} />
                  ))}
                </div>
              )}
              {expanded === a.id && agencies.filter(([k]) => k === a.id).map(([key, profile]) => (
                <div key={key} style={{ marginTop: 6, padding: 6, background: 'var(--bg-primary)', borderRadius: 4, fontSize: 9 }}>
                  <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <div><strong style={{ color: a.color }}>Known Ops:</strong> {profile.known_ops?.join(', ') || '—'}</div>
                    <div><strong style={{ color: a.color }}>Tactics:</strong> {profile.tactics?.join(', ') || '—'}</div>
                    <div><strong style={{ color: a.color }}>Targets:</strong> {profile.targets?.join(', ') || '—'}</div>
                    <div><strong style={{ color: a.color }}>Tools:</strong> {profile.tools?.join(', ') || '—'}</div>
                    {live.tools_detected && live.tools_detected.length > 0 && (
                      <div><strong style={{ color: '#ef4444' }}>Detected in Wild:</strong> {live.tools_detected.join(', ')}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}