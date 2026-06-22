import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const COLORS = ['#8b5cf6','#06b6d4','#f59e0b','#ef4444','#10b981','#ec4899','#f97316']
const AGENCY_COLORS = { NSA:'#ef4444',GRU:'#ec4899',MSS:'#f97316',Mossad:'#06b6d4',SVR:'#dc2626',CIA:'#3b82f6',MI6:'#1d4ed8',FSB:'#dc2626',RAW:'#f59e0b',GCHQ:'#8b5cf6',ISI:'#10b981',DGSE:'#0055a4' }

export default function TorPanel({ onThreatClick }) {
  const [nodes, setNodes] = useState([])
  const [attacks, setAttacks] = useState([])
  const [onions, setOnions] = useState([])
  const [spies, setSpies] = useState([])
  const [marketItems, setMarketItems] = useState([])
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedSpy, setSelectedSpy] = useState(null)
  const [selectedItem, setSelectedItem] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [cycle, setCycle] = useState(0)

  const load = async () => {
    try {
      const [nR, aR, oR, sR, mR] = await Promise.all([
        fetch('/api/tor/nodes').then(r => r.ok ? r.json() : {nodes:[]}),
        fetch('/api/tor/attacks').then(r => r.ok ? r.json() : {attacks:[]}),
        fetch('/api/tor/onions').then(r => r.ok ? r.json() : {onions:[]}),
        fetch('/api/tor/agency-spies').then(r => r.ok ? r.json() : {spies:[]}),
        fetch('/api/tor/market-items').then(r => r.ok ? r.json() : {items:[]}),
      ])
      setNodes(nR.nodes || [])
      setAttacks(aR.attacks || [])
      setOnions(oR.onions || [])
      setSpies(sR.spies || [])
      setMarketItems(mR.items || [])
      setCycle(c => c + 1)
      setError(null)
    } catch { setError('Failed to load Tor data') }
    setLoading(false)
  }

  useEffect(() => { load(); const i = setInterval(load, 8000); return () => clearInterval(i) }, [])

  if (loading) return <div className="loading-bar">Scanning Tor network for exit nodes...</div>

  const totalBw = nodes.reduce((s, n) => s + (n.bandwidth||0), 0)
  const countryMap = {}
  nodes.forEach(n => { countryMap[n.country] = (countryMap[n.country]||0) + 1 })
  const torCountries = Object.entries(countryMap).map(([code, count]) => ({code, count, name: code})).sort((a, b) => b.count - a.count)

  return (
    <div>
      {error && <div className="explain-bar" style={{borderColor:'var(--accent-red)'}}><span className="explain-icon">⚠</span><div style={{color:'var(--accent-red)'}}>{error}</div></div>}
      <div className="terminal-bar">
        <span className="glitch">TOR NETWORK ANALYSIS — AGENCY SPIES & DARK WEB TRADING</span>
        <span className="blink">{nodes.length} NODES · {spies.length} AGENTS · {marketItems.length} ITEMS · #{cycle}</span>
      </div>

      <div className="explain-bar">
        <span className="explain-icon">◉</span>
        <div>
          <strong>Tor Network Intelligence — 24/7</strong> Tracks exit nodes, relay IPs, .onion services,
          <strong> agency spy operations in Tor</strong> (IPs, targets, operators), and
          <strong> dark web market items</strong> being built, sold, and traded.
        </div>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical"><div className="soc-stat-val">{nodes.length}</div><div className="soc-stat-lbl">EXIT/RELAY NODES</div><div className="soc-stat-sub">{nodes.filter(n=>n.type==='exit').length} exits</div></div>
        <div className="soc-stat high"><div className="soc-stat-val">{totalBw}</div><div className="soc-stat-lbl">TOTAL BW (Mbps)</div><div className="soc-stat-sub">Across all nodes</div></div>
        <div className="soc-stat medium"><div className="soc-stat-val">{onions.length}</div><div className="soc-stat-lbl">ONION SERVICES</div><div className="soc-stat-sub">Known .onion sites</div></div>
        <div className="soc-stat low"><div className="soc-stat-val">{torCountries.length}</div><div className="soc-stat-lbl">COUNTRIES</div><div className="soc-stat-sub">{torCountries.map(c=>c.code).join(' · ')}</div></div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">EXIT NODES BY COUNTRY <span className="chart-badge">{torCountries.length}</span></div>
          <div className="chart-wrap" style={{height:120}}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={torCountries}>
                <XAxis dataKey="code" tick={{fontSize:8,fill:'#94a3b8'}} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="count" radius={[3,3,0,0]}>
                  {torCountries.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">ATTACKS THROUGH TOR <span className="chart-badge">{attacks.length} types</span></div>
          <div className="chart-wrap" style={{height:120}}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attacks} layout="vertical">
                <XAxis type="number" tick={{fontSize:8,fill:'#94a3b8'}} unit="%" />
                <YAxis type="category" dataKey="type" tick={{fontSize:7,fill:'#94a3b8'}} width={70} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} formatter={(v,p)=>[`${v}%`,p.payload.desc]} />
                <Bar dataKey="pct" radius={[0,3,3,0]}>
                  {attacks.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          AGENCY SPY OPERATIONS IN TOR — 24/7 TRACKING <span className="soc-badge">{spies.length} agents</span>
          <span className="soc-badge sec">Cycle #{cycle}</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {spies.map(spy => {
            const ac = AGENCY_COLORS[spy.agency] || '#64748b'
            return (
              <div key={spy.id} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'5px 8px',
                borderColor: selectedSpy?.id === spy.id ? ac : 'var(--border)',
                boxShadow: selectedSpy?.id === spy.id ? `0 0 8px ${ac}40` : 'none'}}
                onClick={() => setSelectedSpy(selectedSpy?.id === spy.id ? null : spy)}>
                <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                  <span className="soc-src-id" style={{color:ac,fontSize:8,textTransform:'uppercase'}}>{spy.agency}</span>
                  <span style={{fontWeight:600,fontSize:10}}>{spy.operator}</span>
                  <span style={{fontFamily:'monospace',fontSize:8,color:'var(--accent-yellow)'}}>{spy.ip}</span>
                  <span className={`soc-tag ${spy.status==='active'?'cve':'info'}`} style={{fontSize:6}}>{spy.status.toUpperCase()}</span>
                  <span style={{fontSize:7,color:'var(--text-secondary)',marginLeft:'auto'}}>target: {spy.target?.slice(0,30)}</span>
                  <span className="soc-time">{new Date(spy.last_seen).toLocaleTimeString()}</span>
                </div>
                <div style={{display:'flex',alignItems:'center',gap:6,fontSize:7,color:'var(--text-secondary)'}}>
                  <span>Service: {spy.service}</span>
                </div>
                {selectedSpy?.id === spy.id && (
                  <div style={{marginTop:4,padding:'5px 8px',background:'var(--bg-primary)',borderRadius:4,fontSize:8,lineHeight:1.5,borderLeft:`3px solid ${ac}`}}>
                    <div><strong style={{color:ac}}>{spy.agency}</strong> — Operator: <strong>{spy.operator}</strong></div>
                    <div><strong>IP:</strong> <span style={{fontFamily:'monospace',color:'var(--accent-yellow)'}}>{spy.ip}</span> ({spy.country})</div>
                    <div><strong>Target:</strong> {spy.target}</div>
                    <div><strong>Service:</strong> {spy.service}</div>
                    <div><strong>Status:</strong> <span style={{color:spy.status==='active'?'var(--accent-red)':'var(--accent-yellow)'}}>{spy.status.toUpperCase()}</span></div>
                    <div><strong>Notes:</strong> <span style={{color:'var(--text-secondary)'}}>{spy.notes}</span></div>
                    <div style={{marginTop:4}}>
                      <button className="btn btn-primary" style={{fontSize:7,padding:'2px 6px'}}
                        onClick={e=>{e.stopPropagation();onThreatClick?.({type:'agency_tor_spy',agency:spy.agency,operator:spy.operator,ip:spy.ip,target:spy.target,notes:spy.notes,t:Date.now()})}}>
                        VIEW INTELLIGENCE
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          DARK WEB MARKET — WHAT IS BEING BUILT, SOLD & TRADED <span className="soc-badge">{marketItems.length} items</span>
          <span className="soc-badge sec">LIVE PRICES</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {marketItems.map(item => (
            <div key={item.name} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'5px 8px',
              borderColor: selectedItem?.name === item.name ? (item.status==='in stock'?'var(--accent-red)':item.status==='limited'?'var(--accent-yellow)':'var(--accent-cyan)') : 'var(--border)'}}
              onClick={() => setSelectedItem(selectedItem?.name === item.name ? null : item)}>
              <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                <span className={`soc-tag ${item.category==='Exploits'?'cve':item.category==='Malware'?'ioc':item.category==='Data'?'url':'info'}`} style={{fontSize:6}}>{item.category}</span>
                <span style={{fontWeight:600,fontSize:10,color:item.price.includes('500,000')||item.price.includes('1,500,000')?'var(--accent-red)':'var(--accent-cyan)'}}>{item.name}</span>
                <span style={{fontSize:9,fontWeight:700,color:'var(--accent-green)'}}>{item.price}</span>
                <span style={{fontSize:7,color:'var(--text-secondary)'}}>seller: {item.seller}</span>
                <span style={{fontSize:7,color:item.status==='in stock'?'var(--accent-red)':item.status==='sold out'?'var(--text-secondary)':'var(--accent-yellow)'}}>{item.status}</span>
                <span style={{fontSize:7,color:'var(--text-secondary)',marginLeft:'auto'}}>★{item.rating} · {item.sold.toLocaleString()} sold</span>
              </div>
              {selectedItem?.name === item.name && (
                <div style={{marginTop:4,padding:'5px 8px',background:'var(--bg-primary)',borderRadius:4,fontSize:8,lineHeight:1.5}}>
                  <div><strong>Description:</strong> <span style={{color:'var(--text-secondary)'}}>{item.description}</span></div>
                  <div><strong>Seller:</strong> {item.seller} · <strong>Price:</strong> {item.price} · <strong>Rating:</strong> ★{item.rating}</div>
                  <div><strong>Status:</strong> {item.status} · <strong>Total Sold:</strong> {item.sold.toLocaleString()}</div>
                  <div style={{marginTop:4}}>
                    <button className="btn btn-primary" style={{fontSize:7,padding:'2px 6px'}}
                      onClick={e=>{e.stopPropagation();onThreatClick?.({type:'darkweb_item',name:item.name,price:item.price,seller:item.seller,category:item.category,description:item.description,t:Date.now()})}}>
                      VIEW DETAIL
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          TOR EXIT NODE IP ADDRESSES — 24/7 LIVE <span className="soc-badge">{nodes.length} nodes</span>
          <span className="soc-badge sec">Cycle #{cycle}</span>
        </div>
        <div style={{maxHeight:200,overflow:'auto',display:'flex',flexDirection:'column',gap:2}}>
          {nodes.map((n, i) => (
            <div key={i} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'4px 8px',
              borderColor: selectedNode?.ip === n.ip ? (n.type==='exit'?'var(--accent-red)':'var(--accent-yellow)') : 'var(--border)'}}
              onClick={() => setSelectedNode(selectedNode?.ip === n.ip ? null : n)}>
              <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                <span style={{fontFamily:'monospace',fontSize:8,color:n.type==='exit'?'var(--accent-red)':'var(--accent-yellow)',fontWeight:600}}>{n.ip}</span>
                <span className={`soc-tag ${n.type==='exit'?'cve':'url'}`} style={{fontSize:6}}>{n.type.toUpperCase()}</span>
                <span style={{fontSize:8,color:'var(--text-secondary)'}}>{n.country}</span>
                <span style={{fontSize:8,color:'var(--accent-cyan)'}}>{n.bandwidth} Mbps</span>
                <span style={{fontSize:8,color:'var(--accent-green)'}}>{n.uptime}</span>
                <span style={{fontSize:7,color:'var(--text-secondary)',marginLeft:'auto'}}>{n.flags}</span>
              </div>
              {selectedNode?.ip === n.ip && (
                <div style={{marginTop:3,padding:'4px 6px',background:'var(--bg-primary)',borderRadius:4,fontSize:8}}>
                  IP: {n.ip}<br/>
                  Country: {n.country}<br/>
                  BW: {n.bandwidth} Mbps<br/>
                  Uptime: {n.uptime}<br/>
                  Type: {n.type}<br/>
                  Flags: {n.flags}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          KNOWN .ONION SERVICES — TRACKED <span className="soc-badge">{onions.length}</span>
        </div>
        <div style={{maxHeight:150,overflow:'auto',display:'flex',flexDirection:'column',gap:2}}>
          {onions.map((hs, i) => (
            <div key={i} className="soc-src-chip" style={{padding:'3px 8px',fontSize:7,fontFamily:'monospace',borderColor:'#8b5cf6',cursor:'pointer'}}
              onClick={() => onThreatClick?.({type:'onion_service',url:hs,t:Date.now()})}>
              <span style={{color:'#8b5cf6'}}>○</span> {hs}
            </div>
          ))}
        </div>
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">
          CYBER ATTACKS USING TOR NETWORK <span className="soc-badge">{attacks.length} categories</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {attacks.map((a, i) => (
            <div key={i} className="soc-src-chip" style={{cursor:'pointer',padding:'4px 8px',borderColor:COLORS[i]}}
              onClick={() => onThreatClick?.({type:'tor_attack',attack_type:a.type,pct:a.pct,description:a.desc,t:Date.now()})}>
              <span style={{width:25,fontWeight:700,color:COLORS[i]}}>{a.pct}%</span>
              <span style={{fontWeight:600,fontSize:10}}>{a.type}</span>
              <span style={{fontSize:8,color:'var(--text-secondary)',flex:1}}>{a.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
