import { useState, useEffect } from 'react'

const COLORS = ['#ef4444','#f59e0b','#06b6d4','#8b5cf6','#10b981','#ec4899','#14b8a6','#f97316','#a855f7','#64748b']

export default function DailyReportPanel({ onThreatClick }) {
  const [report, setReport] = useState(null)
  const [history, setHistory] = useState([])
  const [view, setView] = useState('today')

  useEffect(() => {
    const load = async () => {
      try {
        const [rR, hR] = await Promise.all([
          fetch('/api/report/daily').then(r => r.json()),
          fetch('/api/report/daily/history').then(r => r.json()),
        ])
        setReport(rR)
        setHistory(hR.reports || [])
      } catch {}
    }
    load()
    const i = setInterval(load, 60000)
    return () => clearInterval(i)
  }, [])

  const loadHistory = async (date) => {
    try {
      const r = await fetch(`/api/report/daily?date=${date}`)
      setReport(await r.json())
      setView(date)
    } catch {}
  }

  const printReport = () => {
    const styles = `
      @page { size: A4; margin: 15mm; }
      body { font-family: Arial, sans-serif; color: #1a1a2e; background: white; padding: 20px; }
      h1 { color: #06b6d4; border-bottom: 2px solid #06b6d4; padding-bottom: 8px; }
      h2 { color: #1a2332; margin-top: 20px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
      table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12px; }
      th { background: #1a2332; color: white; padding: 6px 8px; text-align: left; }
      td { padding: 4px 8px; border-bottom: 1px solid #eee; }
      .stat-grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 10px; margin: 10px 0; }
      .stat-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; }
      .stat-val { font-size: 20px; font-weight: 700; color: #06b6d4; }
      .stat-lbl { font-size: 10px; color: #64748b; text-transform: uppercase; }
      .footer { margin-top: 30px; font-size: 10px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 10px; }
      .verified { color: #10b981; font-weight: 700; }
    `
    const w = window.open('', '_blank')
    const r = report
    if (!r || !w) return
    w.document.write(`<!DOCTYPE html><html><head><title>Daily Threat Report — ${r.date}</title><style>${styles}</style></head><body>`)
    w.document.write(`<h1>Daily Cyber Threat Intelligence Report</h1>`)
    w.document.write(`<p style="color:#64748b;font-size:14px;">Date: ${r.date} | Generated: ${new Date(r.generated_at).toLocaleString()} | Classification: CONFIDENTIAL</p>`)
    w.document.write(`<h2>Executive Summary</h2>`)
    w.document.write(`<div class="stat-grid">`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.summary.total_threats_collected}</div><div class="stat-lbl">Threats Today</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.summary.unique_sources}</div><div class="stat-lbl">Active Sources</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.summary.countries_mapped}</div><div class="stat-lbl">Countries</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.summary.rt_cycles}</div><div class="stat-lbl">RT Scan Cycles</div></div>`)
    w.document.write(`</div>`)
    w.document.write(`<h2>Data Quality Assessment</h2>`)
    w.document.write(`<div class="stat-grid">`)
    w.document.write(`<div class="stat-card"><div class="stat-val ${r.data_quality.verified_pct >= 30 ? 'verified' : ''}">${r.data_quality.verified_pct}%</div><div class="stat-lbl">Cross-Source Verified</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.data_quality.avg_confidence}%</div><div class="stat-lbl">Avg Confidence Score</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.data_quality.high_confidence}</div><div class="stat-lbl">High-Confidence Threats</div></div>`)
    w.document.write(`<div class="stat-card"><div class="stat-val">${r.data_quality.total_knowledge_items.toLocaleString()}</div><div class="stat-lbl">AI Knowledge Base</div></div>`)
    w.document.write(`</div>`)
    w.document.write(`<h2>Threat Breakdown</h2>`)
    w.document.write(`<h3>By Type</h3><table><tr><th>Type</th><th>Count</th></tr>`)
    r.threat_breakdown.by_type.forEach(t => w.document.write(`<tr><td>${t.type}</td><td>${t.count}</td></tr>`))
    w.document.write(`</table>`)
    w.document.write(`<h3>By Source</h3><table><tr><th>Source</th><th>Count</th></tr>`)
    r.threat_breakdown.by_source.forEach(s => w.document.write(`<tr><td>${s.source}</td><td>${s.count}</td></tr>`))
    w.document.write(`</table>`)
    w.document.write(`<h3>By Continent</h3><table><tr><th>Continent</th><th>Count</th></tr>`)
    r.threat_breakdown.by_continent.forEach(c => w.document.write(`<tr><td>${c.continent}</td><td>${c.count}</td></tr>`))
    w.document.write(`</table>`)
    w.document.write(`<h2>Indicators of Compromise (IOCs)</h2>`)
    if (r.indicators.sample_iocs.length > 0) {
      w.document.write(`<p>Total unique IOCs: ${r.indicators.total_unique_iocs}</p><table><tr><th>IOC</th></tr>`)
      r.indicators.sample_iocs.forEach(ioc => w.document.write(`<tr><td style="font-family:monospace;font-size:10px;">${ioc}</td></tr>`))
      w.document.write(`</table>`)
    } else { w.document.write(`<p>No IOCs collected today.</p>`) }
    w.document.write(`<div class="footer">Daily Threat Intelligence Report | ${r.date} | Page 1 of 1</div>`)
    w.document.write(`</body></html>`)
    w.document.close()
    setTimeout(() => { w.focus(); w.print() }, 500)
  }

  if (!report?.summary || !report?.data_quality || !report?.threat_breakdown || !report?.indicators)
    return <div className="loading-bar">Generating daily intelligence report...</div>

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">DAILY THREAT INTELLIGENCE REPORT</span>
        <span className="blink">{report.date} · {report.summary.total_threats_collected} threats</span>
      </div>

      <div className="explain-bar">
        <span className="explain-icon">📊</span>
        <div>
          <strong>Professional Daily Report</strong> — Auto-generated summary of all 24/7 threat intelligence.
          <strong> Data quality: {report.data_quality.verified_pct}% cross-source verified · {report.data_quality.avg_confidence}% average confidence.</strong>
          Click <strong>Download PDF</strong> to save as professional report.
        </div>
      </div>

      <div className="filters-bar">
        <button className={`filter-btn ${view === 'today' ? 'active' : ''}`} onClick={() => { fetch('/api/report/daily').then(r=>r.json()).then(setReport); setView('today') }}>TODAY</button>
        {history.slice(0,7).map(h => (
          <button key={h.date} className={`filter-btn ${view === h.date ? 'active' : ''}`} onClick={() => loadHistory(h.date)}>
            {h.date.slice(5)} {h.total}t
          </button>
        ))}
        <button className="btn btn-primary" style={{marginLeft:'auto',fontSize:10,padding:'4px 12px'}} onClick={printReport}>
          📄 DOWNLOAD PDF
        </button>
        <button className="btn btn-primary" style={{fontSize:10,padding:'4px 12px',background:'var(--accent-purple)'}}
          onClick={() => { fetch('/api/report/save',{method:'POST'}).then(r=>r.json()).then(d=>alert(`Report saved!\n${d.path}`)) }}>
          SAVE REPORT
        </button>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical"><div className="soc-stat-val">{report.summary.total_threats_collected}</div><div className="soc-stat-lbl">THREATS TODAY</div><div className="soc-stat-sub">{report.summary.total_all_time} all-time</div></div>
        <div className="soc-stat high"><div className="soc-stat-val">{report.summary.unique_sources}</div><div className="soc-stat-lbl">ACTIVE SOURCES</div><div className="soc-stat-sub">{report.summary.rt_cycles} RT cycles</div></div>
        <div className="soc-stat medium"><div className="soc-stat-val">{report.summary.countries_mapped}</div><div className="soc-stat-lbl">COUNTRIES</div><div className="soc-stat-sub">{report.summary.deep_cycles} deep cycles</div></div>
        <div className="soc-stat low"><div className="soc-stat-val">{report.summary.train_cycles}</div><div className="soc-stat-lbl">TRAIN CYCLES</div><div className="soc-stat-sub">ModelScope cloud GPU</div></div>
      </div>

      {/* Data Quality Section */}
      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          DATA QUALITY & RESEARCH READINESS <span className="soc-badge">{report.data_quality.verified_pct}% verified</span>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
          <div>
            <div className="soc-kgrid">
              {[
                {l:'Cross-Source Verified', v:`${report.data_quality.verified_pct}%`, c: report.data_quality.verified_pct >= 30 ? 'var(--accent-green)' : 'var(--accent-yellow)'},
                {l:'Avg Confidence Score', v:`${report.data_quality.avg_confidence}%`, c: report.data_quality.avg_confidence >= 70 ? 'var(--accent-green)' : 'var(--accent-yellow)'},
                {l:'High-Confidence Threats', v:report.data_quality.high_confidence, c:'var(--accent-cyan)'},
                {l:'Verified Count', v:report.data_quality.verified_cross_source, c:'var(--accent-purple)'},
              ].map((x,i) => (
                <div key={i} className="soc-kitem">
                  <div className="soc-klbl">{x.l}</div>
                  <div className="soc-kval" style={{color:x.c}}>{x.v}</div>
                  <div className="soc-kbar"><div className="soc-kfill" style={{width:typeof x.v==='string'?x.v:`${Math.min(100,x.v)}%`,background:x.c}} /></div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <div style={{fontSize:9,color:'var(--text-secondary)',lineHeight:1.8,marginBottom:6}}>
              <strong style={{color:'var(--accent-cyan)'}}>Research Notes:</strong><br/>
              {report.data_quality.verified_pct >= 30
                ? '✓ Data meets research-grade threshold (30%+ cross-source verified)'
                : '⚠ Data still accumulating — more sources needed for research confidence'}
              <br/>
              AI Knowledge Base: <strong>{report.data_quality.total_knowledge_items.toLocaleString()}</strong> items
              <br/>
              {report.data_quality.avg_confidence >= 70
                ? '✓ Average confidence exceeds 70% — suitable for publication'
                : '⚠ Average confidence below 70% — verification ongoing'}
            </div>
            <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
              <span className="soc-src-chip" style={{padding:'2px 6px',fontSize:8,borderColor:report.data_quality.verified_pct>=30?'var(--accent-green)':'var(--accent-yellow)'}}>
                {report.data_quality.verified_pct>=30?'✓ RESEARCH READY':'⟳ BUILDING'}
              </span>
              <span className="soc-src-chip" style={{padding:'2px 6px',fontSize:8}}>Confidence: {report.data_quality.avg_confidence}%</span>
              <span className="soc-src-chip" style={{padding:'2px 6px',fontSize:8}}>Sources: {report.summary.unique_sources}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">THREATS BY TYPE <span className="chart-badge">{report.threat_breakdown.by_type.length}</span></div>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {report.threat_breakdown.by_type.slice(0,8).map((t,i) => (
              <div key={t.type} className="soc-src-chip" style={{padding:'4px 8px',fontSize:9,justifyContent:'space-between'}}>
                <span className={`soc-tag ${t.type==='cve'?'cve':['ioc','botnet'].includes(t.type)?'ioc':'url'}`} style={{fontSize:7}}>{t.type}</span>
                <span style={{fontWeight:700}}>{t.count}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">THREATS BY SOURCE <span className="chart-badge">{report.threat_breakdown.by_source.length}</span></div>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {report.threat_breakdown.by_source.slice(0,8).map(s => (
              <div key={s.source} className="soc-src-chip" style={{padding:'4px 8px',fontSize:9,justifyContent:'space-between'}}>
                <span style={{color:'var(--accent-cyan)'}}>{s.source}</span>
                <span style={{fontWeight:700}}>{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">CONTINENT DISTRIBUTION <span className="chart-badge">{report.threat_breakdown.by_continent.length}</span></div>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {report.threat_breakdown.by_continent.map(c => (
              <div key={c.continent} className="soc-src-chip" style={{padding:'4px 8px',fontSize:9,justifyContent:'space-between'}}>
                <span style={{fontWeight:600}}>{c.continent}</span>
                <span style={{fontWeight:700,color:'var(--accent-red)'}}>{c.count}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">INDICATORS OF COMPROMISE <span className="chart-badge">{report.indicators.total_unique_iocs} IOCs</span></div>
          <div style={{maxHeight:160,overflow:'auto',display:'flex',flexDirection:'column',gap:2}}>
            {report.indicators.sample_iocs.length > 0 ? report.indicators.sample_iocs.slice(0,15).map((ioc,i) => (
              <div key={i} className="soc-src-chip" style={{padding:'2px 6px',fontSize:7,fontFamily:'monospace',cursor:'pointer'}}
                onClick={() => onThreatClick?.({type:'ioc',ioc,source:'daily_report',description:`IOC from daily report: ${ioc}`,t:Date.now()})}>
                <span style={{color:'var(--accent-yellow)'}}>●</span> {ioc}
              </div>
            )) : <div className="soc-empty">No IOCs collected today</div>}
          </div>
        </div>
      </div>

      {/* System Summary */}
      <div className="soc-panel">
        <div className="soc-panel-header">
          SYSTEM OPERATIONS SUMMARY <span className="soc-badge">{report.summary.rt_cycles + report.summary.deep_cycles} cycles</span>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8,fontSize:9,lineHeight:1.8}}>
          <div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Real-Time Scans:</strong> {report.summary.rt_cycles} cycles</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Deep Scans:</strong> {report.summary.deep_cycles} cycles</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Research Cycles:</strong> {report.summary.research_cycles}</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Training Cycles:</strong> {report.summary.train_cycles}</div>
          </div>
          <div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Total Threats:</strong> {report.summary.total_threats_collected.toLocaleString()} today</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Unique Sources:</strong> {report.summary.unique_sources}</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>Countries Mapped:</strong> {report.summary.countries_mapped}</div>
            <div><strong style={{color:'var(--accent-cyan)'}}>All-Time Total:</strong> {report.summary.total_all_time.toLocaleString()}</div>
          </div>
        </div>
      </div>
    </div>
  )
}
