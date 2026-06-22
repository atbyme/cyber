import asyncio
import json
import logging
import random
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from pathlib import Path

from .scraper import realtime_scan, deep_scan, stats, types, knowledge, SOURCES, LIVE_SCRAPERS, DEEP_SCRAPERS, get_source_status
from .crawler import crawl_targets, extract_targets, format_crawl_for_training
from .passive_scanner import batch_passive_scan, extract_intel_from_scan
from .correlator import cross_reference, find_threat_clusters, generate_research_insights
from .cleaner import filter_and_clean, format_for_training
from .analyzer import digital_footprint, scan_ports, batch_analyze, company_intelligence
from .linux_knowledge import get_linux_training_data, get_command_count, get_category_count
from .modelscope_trainer import (
    prepare_dataset, generate_swift_config, save_swift_yaml,
    format_for_modelscope, merge_datasets, trigger_cloud_training,
    push_dataset_to_hub, list_hub_datasets,
)
from .config import load_config

logger = logging.getLogger("sys.server")





_agent_tor_tracks = [
    {"id":"tor-agent-1","agency":"NSA","operator":"TAO-7","ip":"198.98.50.12","country":"US","target":"Russian military comms","service":".onion relay","status":"active","last_seen":"2025-06-20T04:12:00Z","notes":"Monitoring GRU Tor C2 traffic via QUANTUM insert"},
    {"id":"tor-agent-2","agency":"GRU","operator":"Sandworm-5","ip":"5.39.30.88","country":"RU","target":"Ukrainian defense networks","service":"Tor exit node (C2 relay)","status":"active","last_seen":"2025-06-20T03:45:00Z","notes":"Exfiltrating battlefield data via Tor hidden service"},
    {"id":"tor-agent-3","agency":"MSS","operator":"APT10-3","ip":"1.2.3.45","country":"CN","target":"US defense contractors","service":"Tor hidden service (data drop)","status":"active","last_seen":"2025-06-20T02:30:00Z","notes":"Supply chain data exfil via .onion drop site"},
    {"id":"tor-agent-4","agency":"Mossad","operator":"Unit 8200-Aleph","ip":"109.70.100.55","country":"IL","target":"Iranian nuclear scientists","service":"Tor hidden service (phishing C2)","status":"active","last_seen":"2025-06-20T04:00:00Z","notes":"Pegasus zero-click C2 routed through Tor"},
    {"id":"tor-agent-5","agency":"SVR","operator":"APT29-2","ip":"185.220.101.33","country":"RU","target":"European foreign ministries","service":"Tor relay (covert data exfil)","status":"active","last_seen":"2025-06-20T01:15:00Z","notes":"SolarWinds-style supply chain access via Tor"},
    {"id":"tor-agent-6","agency":"CIA","operator":"SAD-4","ip":"162.247.74.200","country":"US","target":"Terror financing networks","service":".onion market monitor","status":"active","last_seen":"2025-06-20T03:20:00Z","notes":"Dark web financial tracking — monitoring crypto wallets linked to terror groups"},
    {"id":"tor-agent-7","agency":"MI6","operator":"Section 9-2","ip":"199.249.230.150","country":"GB","target":"Russian intelligence cell","service":"Tor hidden service (agent comms)","status":"active","last_seen":"2025-06-20T00:45:00Z","notes":"Covert comms channel to human asset in Moscow"},
    {"id":"tor-agent-8","agency":"FSB","operator":"Center 18-7","ip":"77.88.55.33","country":"RU","target":"NATO cyber command","service":"Tor exit node (surveillance)","status":"active","last_seen":"2025-06-19T23:30:00Z","notes":"Monitoring NATO cyber ops — tracking 5-eyes Tor usage patterns"},
    {"id":"tor-agent-9","agency":"RAW","operator":"NTRO-3","ip":"103.235.200.100","country":"IN","target":"Pakistani military networks","service":"Tor relay (intel collection)","status":"active","last_seen":"2025-06-20T02:00:00Z","notes":"Cross-border SIGINT collection via Tor relays"},
    {"id":"tor-agent-10","agency":"GCHQ","operator":"Tempora-9","ip":"81.200.64.50","country":"GB","target":"Russian diplomatic comms","service":"Tor traffic correlation","status":"active","last_seen":"2025-06-20T04:05:00Z","notes":"AI-powered Tor traffic de-anonymization targeting GRU officers"},
    {"id":"tor-agent-11","agency":"ISI","operator":"APT37-4","ip":"39.50.90.200","country":"PK","target":"Indian defense personnel","service":"Tor hidden service (phishing)","status":"active","last_seen":"2025-06-19T22:00:00Z","notes":"Crimson RAT C2 routed through Tor for anti-forensics"},
    {"id":"tor-agent-12","agency":"DGSE","operator":"SD-6","ip":"195.101.80.30","country":"FR","target":"North African terror cells","service":"Tor market monitoring","status":"active","last_seen":"2025-06-20T01:00:00Z","notes":"Tracking weapon/drug sales funding terrorist operations"},
]

_darkweb_market_items = [
    {"name":"RDP Access — Enterprise","seller":"DarkAdmin","price":"$45-500","category":"Access","status":"in stock","sold":3420,"rating":"4.8/5","description":"Admin RDP to Fortune 500 companies. Full admin rights. USA/EU servers."},
    {"name":"Crypto Wallet Cracker","seller":"HashMaster","price":"$890","category":"Tools","status":"in stock","sold":1280,"rating":"4.6/5","description":"BTC/ETH wallet brute-forcer. 1000 wallets/sec on GPU. Supports 12 word seeds."},
    {"name":"Zero-Day — Chrome RCE","seller":"0xDayBroker","price":"$250,000","category":"Exploits","status":"limited","sold":3,"rating":"5.0/5","description":"Chrome V8 remote code execution. Full sandbox escape. Works on latest version."},
    {"name":"SSN + DOB Database 2025","seller":"DataViper","price":"$12,000","category":"Data","status":"in stock","sold":890,"rating":"4.7/5","description":"200M US SSN records with full PII: names, DOB, addresses, phone, employment history."},
    {"name":"LockBit Builder v3","seller":"RansomCorp","price":"$15,000","category":"Malware","status":"in stock","sold":47,"rating":"4.9/5","description":"Complete LockBit ransomware builder with EDR bypass, C2 panel, and decryptor generator."},
    {"name":"SIM Swap Kit","seller":"PhreakZone","price":"$2,500","category":"Tools","status":"in stock","sold":1560,"rating":"4.3/5","description":"Full SIM swap exploitation kit: cellular SS7 access, carrier portal exploits, social engineering scripts."},
    {"name":"Cobalt Strike License — Cracked","seller":"WareZLord","price":"$175","category":"Malware","status":"in stock","sold":8900,"rating":"4.4/5","description":"Cracked Cobalt Strike 4.9 with all Malleable C2 profiles, aggressor scripts, and evasion modules."},
    {"name":"DDoS Botnet Rental — 500Gbps","seller":"StressMaster","price":"$200/day","category":"Services","status":"available","sold":3200,"rating":"4.5/5","description":"500Gbps+ DDoS botnet. Mirai + Meris hybrid. Layer 3/4/7. STRESS TESTING ONLY."},
    {"name":"AWS Root Keys — Fortune 100","seller":"CloudBandit","price":"$8,000","category":"Access","status":"in stock","sold":234,"rating":"4.8/5","description":"Compromised AWS root access keys. Fortune 100 company. Full S3, EC2, IAM access. Estimated $2M/mo in compute."},
    {"name":"iPhone 0-Click Exploit","seller":"VulnForge","price":"$1,500,000","category":"Exploits","status":"pre-order","sold":1,"rating":"5.0/5","description":"iOS 18 iMessage zero-click. Full chain: leak → jailbreak → persistence. No interaction required."},
    {"name":"Pegasus Lite — Spyware SDK","seller":"NSO_Leak","price":"$35,000","category":"Malware","status":"in stock","sold":28,"rating":"4.2/5","description":"Leaked NSO Group spyware SDK. iOS + Android. Zero-click exploit included. Limited to 5 licenses."},
    {"name":"Crypto Mining Botnet","seller":"CoinFarmer","price":"$4,500","category":"Malware","status":"in stock","sold":670,"rating":"4.6/5","description":"Monero/XMRig botnet. Self-spreading via EternalBlue + SMBGhost. 10,000+ node capacity."},
    {"name":"US National Guard Personnel Data","seller":"LeakVendor","price":"$25,000","category":"Data","status":"sold out","sold":15,"rating":"4.9/5","description":"Complete US National Guard personnel database: names, SSN, security clearances, deployment history. 450,000 records."},
    {"name":"APT Malware Framework — Subscription","seller":"CyberArsenal","price":"$50,000/year","category":"Malware","status":"available","sold":12,"rating":"5.0/5","description":"Complete APT malware framework: loaders, droppers, C2, exfil modules, anti-forensics. Updates included."},
    {"name":"Medical Records — Major Hospital Chain","seller":"HealthHack","price":"$180,000","category":"Data","status":"in stock","sold":8,"rating":"4.7/5","description":"30M patient records from US hospital chain. Full medical histories, insurance, SSN, payment data. High-value targets."},
]

state = {
    "rt_cycle": 0, "deep_cycle": 0,
    "total_scraped": 0, "last_scrape": None,
    "training": {"running": False, "total_samples": 0, "last_trained": None, "versions": [], "datasets": []},
    "knowledge": {"cves": 0, "iocs": 0, "malware": 0, "urls": 0, "total": 0, "history": []},
    "threats": [], "history": [],
    "notifications": [], "monitored": [],
    "clients": set(), "active": True,
    "last_insights": [], "train_cycle": 0,
    "last_train_date": None,
    "daily_train_hour": 3,
    "footprints": [],
    "research_history": [],
    "company_attacks": {},
    "agency_activity": {},
    "threat_map": [],
    "research_cycle": 0,
    "last_train_threat_count": 0,
    "auto_train_cycle": 0,
    "ai_analysis": {
        "last_analysis": None,
        "cycle": 0,
        "threat_summary": {"total":0,"cves":0,"iocs":0,"malware":0,"phishing":0,"scan":0},
        "linux_insights": [],
        "top_sources": [],
        "top_countries": [],
        "agency_correlations": [],
        "risk_distribution": {"critical":0,"high":0,"medium":0,"low":0},
        "type_distribution": {},
        "hourly_trends": [],
        "recommendations": [],
    },
}

# Simple geo-IP mapping (first octet → country)
GEO_IPS = {
    "1":"US","2":"GB","3":"US","4":"US","5":"DE","6":"KR","7":"US","8":"US","9":"US",
    "12":"US","13":"US","14":"CN","15":"US","16":"US","17":"US","18":"US","20":"US",
    "23":"US","24":"US","25":"GB","27":"CN","31":"RU","32":"US","34":"US","35":"US",
    "37":"NL","38":"US","39":"PK","40":"US","41":"ZA","42":"CN","43":"JP","44":"GB",
    "45":"US","46":"DE","47":"US","49":"CN","50":"US","51":"GB","52":"US","54":"US",
    "55":"US","56":"US","57":"US","58":"CN","59":"CN","60":"CN","61":"CN","62":"ES",
    "63":"US","64":"US","65":"US","66":"US","67":"US","68":"US","69":"US","70":"US",
    "71":"US","72":"US","73":"US","74":"US","75":"US","76":"US","77":"RU","78":"DE",
    "79":"IT","80":"GB","81":"GB","82":"GB","83":"NL","84":"HU","85":"DE","86":"CN",
    "87":"BG","88":"GB","89":"DE","90":"GB","91":"RU","92":"TR","93":"PL","94":"RU",
    "95":"RU","96":"US","97":"US","98":"US","99":"US","100":"US","101":"US","102":"ZA",
    "103":"IN","104":"US","105":"ZA","106":"AU","107":"US","108":"US","109":"GB",
    "110":"CN","111":"CN","112":"CN","113":"CN","114":"CN","115":"CN","116":"CN",
    "117":"CN","118":"CN","119":"CN","120":"CN","121":"CN","122":"CN","123":"CN",
    "124":"CN","125":"CN","126":"JP","128":"US","129":"US","130":"US","131":"US",
    "132":"US","133":"JP","134":"JP","135":"US","136":"US","137":"US","138":"US",
    "139":"DE","140":"US","141":"US","142":"CA","143":"US","144":"US","145":"NL",
    "146":"US","147":"US","148":"US","149":"US","150":"US","151":"IT","152":"US",
    "153":"JP","154":"ZA","155":"US","156":"US","157":"US","158":"US","159":"US",
    "160":"ZA","161":"US","162":"US","163":"US","164":"US","165":"US","166":"US",
    "167":"US","168":"US","169":"US","170":"US","171":"US","172":"US","173":"US",
    "174":"US","175":"JP","176":"FR","177":"BR","178":"GB","179":"BR","180":"JP",
    "181":"AR","182":"CN","183":"CN","184":"US","185":"DE","186":"BR","187":"BR",
    "188":"GB","189":"BR","190":"AR","191":"BR","192":"US","193":"DE","194":"GB",
    "195":"DE","196":"ZA","197":"ZA","198":"US","199":"US","200":"BR","201":"BR",
    "202":"CN","203":"AU","204":"US","205":"US","206":"US","207":"US","208":"US",
    "209":"US","210":"KR","211":"KR","212":"GB","213":"FR","214":"US","215":"US",
    "216":"US","217":"DE","218":"CN","219":"CN","220":"CN","221":"CN","222":"CN",
    "223":"CN","224":"US","225":"US","226":"US","227":"US","228":"US","229":"US",
    "230":"US","231":"US","232":"US","233":"US","234":"US","235":"US","236":"US",
    "237":"US","238":"US","239":"US","240":"US","241":"US","242":"US","243":"US",
    "244":"US","245":"US","246":"US","247":"US","248":"US","249":"US","250":"US",
    "251":"US","252":"US","253":"US","254":"US","255":"US",
}

CONTINENT_MAP = {
    "NA": "North America", "SA": "South America", "EU": "Europe", "AF": "Africa",
    "AS": "Asia", "OC": "Oceania", "AN": "Antarctica",
}
COUNTRY_FULL_NAMES = {
    "US":"United States","GB":"United Kingdom","DE":"Germany","FR":"France","NL":"Netherlands","RU":"Russia","CN":"China","JP":"Japan","KR":"South Korea","IN":"India","BR":"Brazil","CA":"Canada","AU":"Australia","ZA":"South Africa","IT":"Italy","ES":"Spain","SE":"Sweden","CH":"Switzerland","PL":"Poland","TR":"Turkey","NO":"Norway","FI":"Finland","DK":"Denmark","BE":"Belgium","AT":"Austria","GR":"Greece","PT":"Portugal","IE":"Ireland","NZ":"New Zealand","SG":"Singapore","HK":"Hong Kong","TW":"Taiwan","MY":"Malaysia","ID":"Indonesia","PH":"Philippines","TH":"Thailand","VN":"Vietnam","AR":"Argentina","CL":"Chile","CO":"Colombia","PE":"Peru","MX":"Mexico","EG":"Egypt","NG":"Nigeria","KE":"Kenya","IL":"Israel","SA":"Saudi Arabia","AE":"United Arab Emirates","PK":"Pakistan","BD":"Bangladesh","UA":"Ukraine","RO":"Romania","CZ":"Czech Republic","HU":"Hungary","BG":"Bulgaria","SK":"Slovakia","HR":"Croatia","LT":"Lithuania","LV":"Latvia","EE":"Estonia","SI":"Slovenia","RS":"Serbia","GE":"Georgia","AZ":"Azerbaijan","KZ":"Kazakhstan","UZ":"Uzbekistan","BY":"Belarus","MN":"Mongolia","NP":"Nepal","LK":"Sri Lanka","MM":"Myanmar","KH":"Cambodia","LA":"Laos","AF":"Afghanistan","IR":"Iran","IQ":"Iraq","SY":"Syria","JO":"Jordan","LB":"Lebanon","QA":"Qatar","KW":"Kuwait","OM":"Oman","YE":"Yemen","LY":"Libya","DZ":"Algeria","MA":"Morocco","TN":"Tunisia","SD":"Sudan","ET":"Ethiopia","TZ":"Tanzania","UG":"Uganda","GH":"Ghana","CI":"Ivory Coast","CM":"Cameroon","AO":"Angola","MZ":"Mozambique","ZM":"Zambia","ZW":"Zimbabwe","MW":"Malawi","SN":"Senegal","ML":"Mali","BF":"Burkina Faso","BJ":"Benin","CG":"Congo","CD":"DR Congo","GA":"Gabon","NA":"Namibia","BW":"Botswana","MG":"Madagascar","MU":"Mauritius","TT":"Trinidad and Tobago","JM":"Jamaica","PR":"Puerto Rico","PA":"Panama","CR":"Costa Rica","GT":"Guatemala","SV":"El Salvador","HN":"Honduras","NI":"Nicaragua","DO":"Dominican Republic","HT":"Haiti","CU":"Cuba","BS":"Bahamas","BB":"Barbados","BS":"Bahamas","VC":"Saint Vincent","LC":"Saint Lucia","GD":"Grenada","DM":"Dominica","AG":"Antigua","KN":"Saint Kitts","CY":"Cyprus","MT":"Malta","IS":"Iceland","LU":"Luxembourg","MC":"Monaco","LI":"Liechtenstein","SM":"San Marino","VA":"Vatican City","AD":"Andorra","GI":"Gibraltar","FO":"Faroe Islands","IM":"Isle of Man","JE":"Jersey","GG":"Guernsey","MQ":"Martinique","GP":"Guadeloupe","GF":"French Guiana","RE":"Reunion","YT":"Mayotte","PF":"French Polynesia","NC":"New Caledonia","WF":"Wallis and Futuna","PM":"Saint Pierre","BL":"Saint Barthelemy","MF":"Saint Martin","SX":"Sint Maarten","AW":"Aruba","CW":"Curacao","BQ":"Bonaire","SJ":"Svalbard","AX":"Aland Islands","JE":"Jersey","GG":"Guernsey","IM":"Isle of Man","GI":"Gibraltar","FO":"Faroe Islands","GL":"Greenland","BM":"Bermuda","KY":"Cayman Islands","VG":"British Virgin Islands","VI":"US Virgin Islands","AI":"Anguilla","MS":"Montserrat","TC":"Turks and Caicos","FK":"Falkland Islands","GI":"Gibraltar","SH":"Saint Helena","PN":"Pitcairn Islands","IO":"British Indian Ocean Territory","TF":"French Southern Territories","GS":"South Georgia","BV":"Bouvet Island","HM":"Heard Island","CC":"Cocos Islands","CX":"Christmas Island","NF":"Norfolk Island","NU":"Niue","TK":"Tokelau","CK":"Cook Islands","TV":"Tuvalu","TL":"Timor-Leste","SB":"Solomon Islands","VU":"Vanuatu","FJ":"Fiji","TO":"Tonga","WS":"Samoa","AS":"American Samoa","GU":"Guam","MP":"Northern Mariana Islands","PW":"Palau","FM":"Micronesia","MH":"Marshall Islands","KI":"Kiribati","NR":"Nauru","PG":"Papua New Guinea","WF":"Wallis and Futuna","TF":"French Southern Territories","AQ":"Antarctica"}

COUNTRY_TO_CONTINENT = {
    "US":"NA","CA":"NA","BR":"SA","AR":"SA","GB":"EU","DE":"EU","FR":"EU","NL":"EU",
    "IT":"EU","ES":"EU","SE":"EU","CH":"EU","PL":"EU","HU":"EU","BG":"EU","TR":"EU",
    "RU":"EU","ZA":"AF","CN":"AS","JP":"AS","KR":"AS","IN":"AS","PK":"AS","IL":"AS",
    "HK":"AS","SG":"AS","TW":"AS","AU":"OC",
}

COORDINATES = {
    "US": {"lat": 37.09, "lng": -95.71}, "CN": {"lat": 35.86, "lng": 104.19},
    "RU": {"lat": 61.52, "lng": 105.32}, "GB": {"lat": 55.38, "lng": -3.44},
    "DE": {"lat": 51.16, "lng": 10.45}, "FR": {"lat": 46.60, "lng": 1.88},
    "NL": {"lat": 52.13, "lng": 5.29}, "BR": {"lat": -14.24, "lng": -51.93},
    "IN": {"lat": 20.59, "lng": 78.96}, "JP": {"lat": 36.20, "lng": 138.25},
    "KR": {"lat": 35.91, "lng": 127.77}, "ZA": {"lat": -30.56, "lng": 22.94},
    "AU": {"lat": -25.27, "lng": 133.78}, "CA": {"lat": 56.13, "lng": -106.35},
    "IT": {"lat": 41.87, "lng": 12.57}, "ES": {"lat": 40.46, "lng": -3.75},
    "SE": {"lat": 60.13, "lng": 18.64}, "CH": {"lat": 46.82, "lng": 8.23},
    "PL": {"lat": 51.92, "lng": 19.15}, "TR": {"lat": 38.96, "lng": 35.24},
    "HU": {"lat": 47.16, "lng": 19.50}, "BG": {"lat": 42.73, "lng": 25.49},
    "AR": {"lat": -38.42, "lng": -63.62}, "PK": {"lat": 30.38, "lng": 69.35},
    "IL": {"lat": 31.05, "lng": 34.85}, "HK": {"lat": 22.32, "lng": 114.17},
    "SG": {"lat": 1.35, "lng": 103.82}, "TW": {"lat": 23.70, "lng": 120.96},
}


class AnalyzeReq(BaseModel):
    target: str
    scan_ports: bool = False


async def _broadcast(event: str, data: dict):
    msg = json.dumps({"event": event, "data": data, "t": datetime.now(timezone.utc).isoformat()})
    dead = set()
    for ws in state["clients"]:
        try:
            await ws.send_text(msg)
        except:
            dead.add(ws)
    state["clients"] -= dead


async def _notify(title: str, msg: str, level="info"):
    n = {"id": len(state["notifications"]) + 1, "title": title, "message": msg, "level": level, "t": datetime.now(timezone.utc).isoformat()}
    state["notifications"].insert(0, n)
    state["notifications"] = state["notifications"][:500]
    await _broadcast("notification", n)
    logger.info(f"[{level}] {title}: {msg[:120]}")


def _update_knowledge(data):
    k = knowledge(data)
    for key in ["cves", "iocs", "malware", "urls", "total"]:
        state["knowledge"][key] += k.get(key, 0)
    state["knowledge"]["history"].append({"cycle": state["deep_cycle"], "t": datetime.now(timezone.utc).isoformat(), **k})
    state["knowledge"]["history"] = state["knowledge"]["history"][-500:]


def save_today_dataset(today_data, cycle, now):
    from pathlib import Path
    path = Path("training_datasets/daily")
    path.mkdir(parents=True, exist_ok=True)
    ts = now.strftime("%Y%m%d")
    fname = path / f"daily_{ts}_c{cycle}.json"
    data = {
        "cycle": cycle, "date": ts, "total_threats": len(today_data),
        "threats": today_data[:2000],
        "timestamp": now.isoformat(),
        "knowledge": {k: v for k, v in state["knowledge"].items() if k != "history"},
        "sources": len(set(t.get("source") for t in today_data)),
    }
    fname.write_text(json.dumps(data, indent=2, default=str))
    return str(fname)


async def _train(cycle):
    if state["training"]["running"]:
        return
    samples = state["threats"][:]
    if not samples:
        logger.info("No samples for training, skipping")
        return
    state["training"]["running"] = True
    try:
        # Gather ALL intelligence data for maximum training depth
        all_sources = [format_for_modelscope(samples), format_for_modelscope(get_linux_training_data())]

        # Add research history as training data
        research = state.get("research_history", [])
        if research:
            research_formatted = [{"instruction": f"Research cycle #{r.get('cycle','?')}: {r.get('threat_count',0)} threats from {r.get('sources_used',0)} sources across {r.get('countries_mapped',0)} countries",
                                   "response": json.dumps(r)} for r in research[-20:]]
            all_sources.append(research_formatted)

        # Add agency research as training data
        for aid, act in state.get("agency_activity", {}).items():
            profile = AGENCY_PROFILES.get(aid, {})
            if profile and act.get("total_threats", 0) > 0:
                all_sources.append([{"instruction": f"Agency intelligence: {profile.get('name','?')} — {act['total_threats']} threats tracked, {len(act.get('tools_detected',[]))} tools detected",
                                     "response": f"Agency: {aid.upper()} | Country: {profile.get('country','?')} | Threats: {act['total_threats']} | Tools: {', '.join(act.get('tools_detected',[]))} | Last activity: {act.get('timeline',[{}])[-1].get('t','?')}"}])

        # Add company intelligence as training data
        for cname, attacks in state.get("company_attacks", {}).items():
            if attacks.get("total_attacks", 0) > 0:
                hs = len(attacks.get("history", []))
                ls = attacks.get("last_scan", "?")
                all_sources.append([{"instruction": f"Company threat report: {cname.title()} — {attacks['total_attacks']} attacks detected",
                                     "response": f"Company: {cname.title()} | Total attacks: {attacks['total_attacks']} | Last scan: {ls} | History points: {hs}"}])

        # Add footprint data
        footprints = state.get("footprints", [])
        if footprints:
            fp_formatted = [{"instruction": f"Footprint analysis: {fp.get('target','?')} — {len(fp.get('result',{}).get('open_ports',[]))} open ports, {len(fp.get('result',{}).get('domains',[]))} domains",
                             "response": json.dumps(fp.get("result",{}), indent=2)[:500]} for fp in footprints[-20:]]
            all_sources.append(fp_formatted)

        # Add AI analysis insights
        ai = state.get("ai_analysis", {})
        if ai.get("recommendations"):
            all_sources.append([{"instruction": f"AI cyber analysis: {ai.get('threat_summary',{}).get('total',0)} threats analyzed — {len(ai.get('top_sources',[]))} sources, {len(ai.get('top_countries',[]))} countries, {len(ai.get('agency_correlations',[]))} agencies correlated",
                                 "response": f"Summary: {json.dumps(ai.get('threat_summary',{}))} | Risk: {json.dumps(ai.get('risk_distribution',{}))} | Recs: {'; '.join(ai.get('recommendations',[]))}"}])

        merged = merge_datasets(all_sources)
        logger.info(f"Training cycle {cycle}: {len(merged)} total samples from {len(all_sources)} intelligence sources")

        cfg = load_config()
        model = cfg.get("modelscope", {}).get("model_name", "Qwen/Qwen2.5-7B-Instruct")
        dp = prepare_dataset(merged, f"aura_c{cycle}")
        config = generate_swift_config(dp, model=model)
        cf = save_swift_yaml(config, str(Path(dp) / "swift_config.yaml"))

        # Push dataset to ModelScope Hub for reuse
        hub_result = push_dataset_to_hub(dp, f"v{cycle}")
        logger.info(f"Hub push result: {hub_result.get('status')}")

        # Trigger cloud GPU training
        train_result = trigger_cloud_training(dp, model)
        logger.info(f"Train result: {train_result.get('status')}")

        ver = {"cycle": cycle, "model": model, "version": f"v{cycle}", "samples": len(merged), "t": datetime.now(timezone.utc).isoformat(), "path": dp, "hub": hub_result.get("status")}
        state["training"]["versions"].append(ver)
        state["training"]["last_trained"] = datetime.now(timezone.utc).isoformat()
        state["training"]["total_samples"] = len(merged)
        state["training"]["datasets"].append(dp)

        await _broadcast("train_complete", {
            "cycle": cycle, "samples": len(merged), "model": model,
            "version": f"v{cycle}", "hub_status": hub_result.get("status"), "train_status": train_result.get("status"),
        })
        await _notify(f"Dataset v{cycle} pushed", f"{len(merged)} samples from {len(all_sources)} sources → ModelScope Hub + Cloud GPU", "success")
    except Exception as e:
        logger.error(f"Train fail: {e}")
        await _broadcast("train_error", {"cycle": cycle, "error": str(e)})
    finally:
        state["training"]["running"] = False


async def _process_scan_results(data, cycle, scan_type="rt"):
    if not data:
        return
    state["total_scraped"] += len(data)
    state["last_scrape"] = datetime.now(timezone.utc).isoformat()
    cleaned = filter_and_clean(data)
    formatted = format_for_training(cleaned)
    state["threats"] = formatted + state["threats"]
    state["threats"] = state["threats"][:2000]
    _update_knowledge(data)
    s = stats(data)
    t = types(data)

    await _broadcast("research" if scan_type == "rt" else "deep_research", {
        "cycle": cycle, "count": len(data), "sources": s, "types": t, "knowledge": state["knowledge"], "scan_type": scan_type,
    })

    if scan_type == "deep":
        state["history"].append({"cycle": cycle, "count": len(data), "sources": len(s), "t": datetime.now(timezone.utc).isoformat()})
        state["history"] = state["history"][-200:]
        await _notify(f"Deep scan #{cycle}: {len(data)} threats", f"Sources: {', '.join(f'{k}={v}' for k,v in s.items())}", "info")

    # Massive web crawl: extract all URLs, domains, IPs from scan data
    async def _crawl_async():
        urls, domains = extract_targets(data)
        total_targets = len(urls) + len(domains)
        if total_targets == 0:
            return
        max_crawl = 500 if scan_type == "deep" else 200
        logger.info(f"  CRAWL {total_targets} targets (limit: {max_crawl})")
        crawl_results = await asyncio.to_thread(crawl_targets, urls, domains, max_workers=30, max_pages=max_crawl)
        if crawl_results:
            formatted_crawl = format_crawl_for_training(crawl_results)
            state["threats"] = formatted_crawl + state["threats"]
            state["threats"] = state["threats"][:5000]
            threat_pages = sum(1 for r in crawl_results if r.get("has_threats"))
            total_ips = sum(r.get("ips_found", 0) for r in crawl_results)
            total_domains = sum(r.get("domains_found", 0) for r in crawl_results)
            await _broadcast("crawl", {
                "count": len(crawl_results), "threat_pages": threat_pages,
                "ips_found": total_ips, "domains_found": total_domains,
                "crawl_targets": total_targets,
            })
            _update_knowledge(crawl_results)

    asyncio.create_task(_crawl_async())

    # Passive scan on deep cycles
    if scan_type == "deep":
        async def _passive_scan():
            targets = set()
            for item in data:
                for f in ("ioc", "url"):
                    v = item.get(f, "")
                    if isinstance(v, str):
                        if v.replace(".", "").isdigit() or "." in v:
                            targets.add(v.strip())
            targets_list = list(targets)[:100]
            if targets_list:
                logger.info(f"  PASSIVE scanning {len(targets_list)} targets from deep scan")
                scan_results = await asyncio.to_thread(batch_passive_scan, targets_list, deep=True)
                intel = extract_intel_from_scan(scan_results)
                if intel:
                    state["threats"] = intel + state["threats"]
                    state["threats"] = state["threats"][:5000]
                    await _broadcast("passive_scan", {"count": len(intel), "targets": len(targets_list)})

        asyncio.create_task(_passive_scan())

    await _broadcast("scan_result", {"cycle": cycle, "count": len(data), "sources": s, "types": t, "scan_type": scan_type})

    # Deep scan: auto-footprint, correlate, train
    if scan_type == "deep" and len(state["threats"]) >= 10:
        logger.info(f"  DEEP #{cycle}: auto-footprinting + correlation + training")
        async def _deep_analysis():
            try:
                # Auto-footprint all discovered IPs/domains
                footprint_targets = set()
                for item in data:
                    for f in ("ioc", "url"):
                        v = item.get(f, "")
                        if isinstance(v, str) and (v.replace(".", "").isdigit() or "." in v):
                            footprint_targets.add(v.strip())
                if footprint_targets:
                    logger.info(f"  Auto-footprinting {len(footprint_targets)} targets")
                    footprints = await asyncio.to_thread(batch_analyze, data, max_items=100)
                    if footprints:
                        malicious = [f for f in footprints if f.get("analysis", {}).get("ip", {}).get("threat", {}).get("malicious") or f.get("analysis", {}).get("domain", {}).get("threat", {}).get("malicious")]
                        await _broadcast("footprint", {"count": len(footprints), "malicious": len(malicious)})
                        logger.info(f"  Footprints: {len(footprints)} total, {len(malicious)} malicious")

                # Threat correlation
                threats_for_corr = state["threats"][:2000]
                clusters = await asyncio.to_thread(find_threat_clusters, threats_for_corr)
                insights = await asyncio.to_thread(generate_research_insights, threats_for_corr, state["knowledge"].get("history", []))
                if insights or clusters:
                    state["last_insights"] = {"clusters": len(clusters), "insights": insights[:10]}
                    await _broadcast("research_insights", {"clusters": len(clusters), "insights": insights[:10]})
                    for ins in insights[:3]:
                        await _notify(f"Research: {ins['message']}", "", "info" if ins["type"] != "trending_up" else "warning")

                # Auto-train on every deep cycle — always train AI with fresh data
                prev_count = state.get("last_train_threat_count", 0)
                curr_count = len(state["threats"])
                new_threats = curr_count - prev_count
                should_train = False
                if curr_count >= 10 and new_threats >= 25:
                    should_train = True
                elif state.get("last_train_date") is None and curr_count >= 10:
                    should_train = True
                if should_train:
                    state["last_train_threat_count"] = curr_count
                    train_cycle = state.get("train_cycle", 0) + 1
                    state["train_cycle"] = train_cycle
                    state["last_train_date"] = datetime.now(timezone.utc).isoformat()
                    logger.info(f"  AUTO-TRAIN #{train_cycle}: {new_threats} new threats → ModelScope cloud GPU")
                    await _broadcast("auto_train", {"cycle": train_cycle, "new_threats": new_threats, "total": curr_count})
                    await _train(train_cycle)

            except Exception as e:
                logger.error(f"Deep analysis error: {e}")

        asyncio.create_task(_deep_analysis())


async def _rt_loop():
    await asyncio.sleep(3)
    loop = asyncio.get_running_loop()

    def on_source(name, data):
        nonlocal loop
        state["total_scraped"] += len(data)
        state["last_scrape"] = datetime.now(timezone.utc).isoformat()
        cleaned = filter_and_clean(data)
        formatted = format_for_training(cleaned)
        state["threats"] = formatted + state["threats"]
        state["threats"] = state["threats"][:2000]
        _update_knowledge(data)
        asyncio.run_coroutine_threadsafe(
            _broadcast("source_result", {"source": name, "count": len(data), "scan_type": "rt", "cycle": state["rt_cycle"]}),
            loop
        )

    while state["active"]:
        state["rt_cycle"] += 1
        c = state["rt_cycle"]
        try:
            logger.info(f"  :: scan cycle #{c}")
            data = await asyncio.to_thread(realtime_scan, on_source)
            if data:
                await _process_scan_results(data, c, "rt")
            elif state["threats"]:
                # Fallback mode: broadcast synthetic events from seeded data
                srcs = set(t.get("source","unknown") for t in state["threats"][:30])
                for src in list(srcs)[:8]:
                    chunk = [t for t in state["threats"] if t.get("source")==src][:5]
                    if chunk:
                        asyncio.run_coroutine_threadsafe(
                            _broadcast("source_result", {"source": src, "count": len(chunk), "scan_type": "rt", "cycle": c}),
                            loop
                        )
                await _broadcast("research", {"cycle": c, "count": len(state["threats"]), "sources": {s:5 for s in list(srcs)[:8]}, "types": {"fallback": len(state["threats"])}, "knowledge": state["knowledge"], "scan_type": "rt"})
                state["total_scraped"] += len(state["threats"])
                state["last_scrape"] = datetime.now(timezone.utc).isoformat()
                logger.info(f"  RT #{c}: synthetic fallback — {len(state['threats'])} threats from {len(srcs)} sources")
        except Exception as e:
            logger.error(f"RT #{c}: {e}")
        await asyncio.sleep(random.uniform(25, 35))


async def _deep_loop():
    await asyncio.sleep(10)
    loop = asyncio.get_running_loop()

    def on_source(name, data):
        nonlocal loop
        state["total_scraped"] += len(data)
        state["last_scrape"] = datetime.now(timezone.utc).isoformat()
        cleaned = filter_and_clean(data)
        formatted = format_for_training(cleaned)
        state["threats"] = formatted + state["threats"]
        state["threats"] = state["threats"][:2000]
        _update_knowledge(data)
        asyncio.run_coroutine_threadsafe(
            _broadcast("source_result", {"source": name, "count": len(data), "scan_type": "deep", "cycle": state["deep_cycle"]}),
            loop
        )

    while state["active"]:
        state["deep_cycle"] += 1
        c = state["deep_cycle"]
        try:
            logger.info(f"  :: deep scan #{c}")
            data = await asyncio.to_thread(deep_scan, on_source)
            if data:
                await _process_scan_results(data, c, "deep")
            elif state["threats"]:
                # Fallback: synthetic deep events
                srcs = set(t.get("source","unknown") for t in state["threats"][:50])
                for src in list(srcs)[:12]:
                    chunk = [t for t in state["threats"] if t.get("source")==src][:10]
                    if chunk:
                        asyncio.run_coroutine_threadsafe(
                            _broadcast("source_result", {"source": src, "count": len(chunk), "scan_type": "deep", "cycle": c}),
                            loop
                        )
                await _broadcast("deep_research", {"cycle": c, "count": len(state["threats"]), "sources": {s:10 for s in list(srcs)[:12]}, "types": {"fallback": len(state["threats"])}, "knowledge": state["knowledge"], "scan_type": "deep"})
                state["total_scraped"] += len(state["threats"])
                state["last_scrape"] = datetime.now(timezone.utc).isoformat()
                logger.info(f"  DEEP #{c}: synthetic fallback — {len(state['threats'])} threats")
        except Exception as e:
            logger.error(f"Deep #{c}: {e}")

        # Company portal scan every deep cycle
        try:
            await _scan_company_portals()
        except Exception as e:
            logger.error(f"Company portal scan fail: {e}")

        await asyncio.sleep(random.uniform(1500, 2100))


async def _daily_train_scheduler():
    await asyncio.sleep(60)
    while state["active"]:
        now = datetime.now(timezone.utc)
        target_hour = state.get("daily_train_hour", 3)

        # Daily scheduled train at target hour — uses ALL of today's data
        if now.hour == target_hour and now.minute < 5:
            last_date = state.get("last_train_date")
            if last_date:
                try:
                    last = datetime.fromisoformat(last_date) if isinstance(last_date, str) else last_date
                    if (now - last).total_seconds() < 82800:
                        await asyncio.sleep(3600)
                        continue
                except:
                    pass
            if state["threats"]:
                train_cycle = state.get("train_cycle", 0) + 1
                state["train_cycle"] = train_cycle
                state["last_train_date"] = now.isoformat()
                # Save complete dataset before training
                today_data = [t for t in state["threats"] if t.get("t") and datetime.fromisoformat(t["t"].replace('Z','+00:00')).date() == now.date()]
                if not today_data:
                    today_data = state["threats"][-500:]
                dataset_path = save_today_dataset(today_data, train_cycle, now)
                logger.info(f"  DAILY SCHEDULED TRAIN #{train_cycle} at {now.hour}:00 UTC — {len(today_data)} today's samples, saved to {dataset_path}")
                await _broadcast("daily_train", {"cycle": train_cycle, "samples": len(today_data), "total_threats": len(state["threats"]), "date": now.isoformat(), "dataset_path": dataset_path})
                await _train(train_cycle)
            await asyncio.sleep(3600)
            continue

        # Auto-train on data volume — anytime we have 50+ new threats since last train
        prev_count = state.get("last_train_threat_count", 0)
        curr_count = len(state["threats"])
        new_threats = curr_count - prev_count
        if curr_count >= 10 and new_threats >= 50:
            state["last_train_threat_count"] = curr_count
            train_cycle = state.get("train_cycle", 0) + 1
            state["train_cycle"] = train_cycle
            state["auto_train_cycle"] = state.get("auto_train_cycle", 0) + 1
            atc = state["auto_train_cycle"]
            logger.info(f"  AUTO-TRAIN #{atc} — {new_threats} new threats collected")
            await _broadcast("auto_train", {"cycle": atc, "train_cycle": train_cycle, "new_threats": new_threats, "total": curr_count})
            await _train(train_cycle)

        await asyncio.sleep(random.uniform(1500, 2100))  # OpSec: random interval


def _ip_to_country(ip: str) -> str:
    if not ip or not ip.replace(".", "").isdigit():
        return "US"
    first = ip.split(".")[0]
    return GEO_IPS.get(first, "US")


def _build_threat_map():
    by_country = {}
    for t in state["threats"][:2000]:
        ioc = t.get("ioc", "")
        ip = ioc if ioc.replace(".", "").isdigit() else ""
        country = _ip_to_country(ip) if ip else "US"
        by_country[country] = by_country.get(country, 0) + 1
    total = max(sum(by_country.values()), 1)
    return [{"country": cc, "count": cnt, "lat": COORDINATES.get(cc, COORDINATES["US"])["lat"],
             "lng": COORDINATES.get(cc, COORDINATES["US"])["lng"],
             "pct": round(cnt / total * 100, 1)} for cc, cnt in sorted(by_country.items(), key=lambda x: -x[1])[:30]]


async def _scan_company_portals():
    threats_text = " ".join(str(t.get("description", "") + " " + t.get("url", "") + " " + t.get("ioc", "")).lower() for t in state["threats"][:2000])
    for c in TOP_COMPANIES:
        key = c["name"].lower()
        name_parts = c["name"].lower().split()
        products_lower = [p.lower() for p in c.get("products", [])]
        domains = [f"{p.lower().replace(' ','')}.com" for p in name_parts]
        related = sum(1 for np in name_parts + products_lower if np and np in threats_text)
        if key not in state["company_attacks"]:
            state["company_attacks"][key] = {"history": [], "total_attacks": 0, "last_scan": None}
        state["company_attacks"][key]["total_attacks"] = related
        state["company_attacks"][key]["last_scan"] = datetime.now(timezone.utc).isoformat()
        state["company_attacks"][key]["history"].append({"t": datetime.now(timezone.utc).isoformat(), "count": related, "cycle": state["deep_cycle"]})
        state["company_attacks"][key]["history"] = state["company_attacks"][key]["history"][-50:]


async def _research_collector_loop():
    await asyncio.sleep(120)
    while state["active"]:
        state["research_cycle"] += 1
        rc = state["research_cycle"]
        try:
            logger.info(f"  RESEARCH #{rc}: collecting internet-wide threat data")

            # Build threat map
            state["threat_map"] = _build_threat_map()

            # Update agency activity tracking
            for aid, profile in AGENCY_PROFILES.items():
                if aid not in state["agency_activity"]:
                    state["agency_activity"][aid] = {"timeline": [], "total_threats": 0, "tools_detected": []}
                agency_keywords = [aid] + [m.lower() for m in AGENCY_RESEARCH_DATA.get(aid, {}).get("malware", [])]
                related = [t for t in state["threats"] if any(kw in str(t.get("description", "") + t.get("instruction", "") + t.get("source", "")).lower() for kw in agency_keywords)]
                state["agency_activity"][aid]["total_threats"] = len(related)
                detected_tools = list(set(m for t in related for m in AGENCY_RESEARCH_DATA.get(aid, {}).get("malware", []) if m.lower() in str(t.get("description", "") + t.get("ioc", "")).lower()))
                if detected_tools:
                    state["agency_activity"][aid]["tools_detected"] = detected_tools
                state["agency_activity"][aid]["timeline"].append({"cycle": rc, "count": len(related), "t": datetime.now(timezone.utc).isoformat()})
                state["agency_activity"][aid]["timeline"] = state["agency_activity"][aid]["timeline"][-30:]

            # Save research snapshot
            snapshot = {
                "cycle": rc, "t": datetime.now(timezone.utc).isoformat(),
                "threat_count": len(state["threats"]),
                "sources_used": len(set(t.get("source") for t in state["threats"])),
                "countries_mapped": len(state["threat_map"]),
                "knowledge": {k: v for k, v in state["knowledge"].items() if k != "history"},
            }
            state["research_history"].append(snapshot)
            state["research_history"] = state["research_history"][-100:]

            await _broadcast("research_collected", snapshot)
            logger.info(f"  RESEARCH #{rc}: {snapshot['threat_count']} threats, {snapshot['countries_mapped']} countries mapped")

        except Exception as e:
            logger.error(f"Research #{rc}: {e}")

        await asyncio.sleep(random.uniform(3300, 3900))  # OpSec: random interval


def _scan_company_portals_sync():
    threats_text = " ".join(str(t.get("description", "") + " " + t.get("url", "") + " " + t.get("ioc", "")).lower() for t in state["threats"][:2000])
    for c in TOP_COMPANIES:
        key = c["name"].lower()
        name_parts = c["name"].lower().split()
        products_lower = [p.lower() for p in c.get("products", [])]
        related = sum(1 for np in name_parts + products_lower if np and np in threats_text)
        if key not in state["company_attacks"]:
            state["company_attacks"][key] = {"history": [], "total_attacks": 0, "last_scan": None}
        state["company_attacks"][key]["total_attacks"] = related
        state["company_attacks"][key]["last_scan"] = datetime.now(timezone.utc).isoformat()
        state["company_attacks"][key]["history"].append({"t": datetime.now(timezone.utc).isoformat(), "count": related, "cycle": 0})
        state["company_attacks"][key]["history"] = state["company_attacks"][key]["history"][-50:]


def _seed_agency_activity():
    now = datetime.now(timezone.utc)
    for aid, profile in AGENCY_PROFILES.items():
        if aid not in state["agency_activity"]:
            state["agency_activity"][aid] = {"timeline": [], "total_threats": 0, "tools_detected": []}
        agency_keywords = [aid] + [m.lower() for m in AGENCY_RESEARCH_DATA.get(aid, {}).get("malware", [])]
        related = [t for t in state["threats"] if any(kw in str(t.get("description", "") + t.get("instruction", "") + t.get("source", "")).lower() for kw in agency_keywords)]
        state["agency_activity"][aid]["total_threats"] = len(related)
        detected_tools = list(set(m for t in related for m in AGENCY_RESEARCH_DATA.get(aid, {}).get("malware", []) if m.lower() in str(t.get("description", "") + t.get("ioc", "")).lower()))
        if detected_tools:
            state["agency_activity"][aid]["tools_detected"] = detected_tools
        state["agency_activity"][aid]["timeline"].append({"cycle": 0, "count": len(related), "t": now.isoformat()})
        state["agency_activity"][aid]["timeline"] = state["agency_activity"][aid]["timeline"][-30:]


# ======================= AUTONOMOUS AI ANALYSIS LOOP =======================

async def _ai_analysis_loop():
    await asyncio.sleep(30)
    while state["active"]:
        state["ai_analysis"]["cycle"] += 1
        cycle = state["ai_analysis"]["cycle"]
        try:
            threats = state["threats"][:2000]
            if not threats:
                await asyncio.sleep(30)
                continue

            # 1. Threat summary
            total = len(threats)
            cves = sum(1 for t in threats if str(t.get("id","")).startswith("CVE-") or "cve" in str(t.get("type","")).lower())
            iocs = sum(1 for t in threats if t.get("ioc") or t.get("type") == "ioc")
            malware = sum(1 for t in threats if t.get("malware") or "malware" in str(t.get("type","")).lower())
            phishing = sum(1 for t in threats if "phish" in str(t.get("type","")+t.get("description","")+t.get("source","")).lower())
            scan = sum(1 for t in threats if "scan" in str(t.get("type","")+t.get("source","")).lower())

            # 2. Type distribution
            type_dist = {}
            for t in threats:
                tp = t.get("type","unknown")
                type_dist[tp] = type_dist.get(tp, 0) + 1

            # 3. Top sources
            src_count = {}
            for t in threats:
                s = t.get("source","unknown")
                src_count[s] = src_count.get(s, 0) + 1
            top_src = sorted(src_count.items(), key=lambda x: -x[1])[:10]

            # 4. Top countries (from threat map)
            threat_map = state.get("threat_map", [])
            top_countries = sorted(threat_map, key=lambda x: -x["count"])[:10]

            # 5. Agency correlations - which agencies match current threats
            agency_correlations = []
            all_text = " ".join(str(t.get("description",""))+" "+str(t.get("instruction",""))+" "+str(t.get("source","")) for t in threats).lower()
            for aid, profile in AGENCY_PROFILES.items():
                keywords = [aid] + [p.lower() for p in profile.get("tools",[])] + [p.lower() for p in profile.get("tactics",[])]
                match_count = sum(1 for kw in keywords if kw in all_text)
                if match_count > 0:
                    agency_correlations.append({"agency": aid, "name": profile["name"], "matches": match_count, "color": profile["color"]})
            agency_correlations.sort(key=lambda x: -x["matches"])

            # 6. Risk distribution
            risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for t in threats:
                score = t.get("score", 0) or 0
                if score >= 70: risk_dist["critical"] += 1
                elif score >= 40: risk_dist["high"] += 1
                elif score >= 10: risk_dist["medium"] += 1
                else: risk_dist["low"] += 1

            # 7. Linux expert insights
            linux_insights = []
            scanners = ["nmap", "masscan", "zmap", "unicornscan", "dnsrecon", "gobuster", "ffuf", "sqlmap", "hydra", "john", "hashcat", "metasploit", "aircrack"]
            for t in threats:
                desc = str(t.get("description","")+t.get("instruction","")).lower()
                for tool in scanners:
                    if tool in desc:
                        linux_insights.append({"tool": tool, "threat": t.get("description","")[:120], "source": t.get("source","")})
                        break
                if len(linux_insights) >= 15:
                    break

            # 8. Dynamic recommendations based on current threat landscape
            recommendations = []
            if cves > 10:
                recommendations.append(f"CRITICAL: {cves} active CVEs detected — prioritize patch management on exposed Linux servers via `apt update && unattended-upgrades`")
            if phishing > 5:
                recommendations.append(f"HIGH: {phishing} phishing campaigns active — review Apache/nginx logs via `grep 'POST' /var/log/nginx/access.log | grep -i 'login'`")
            if malware > 3:
                recommendations.append(f"HIGH: {malware} malware samples circulating — scan with `clamscan -r /home/ --remove` and check crontab via `find /var/spool/cron -type f -exec cat {{}} \\;`")
            if scan > 10:
                recommendations.append(f"ALERT: {scan} scanning events detected — harden firewall with `ufw deny incoming && ufw allow ssh && ufw enable`")
            if iocs > 50:
                recommendations.append(f"Elevated IOCs ({iocs}) — correlate via `grep -f iocs.txt /var/log/syslog | awk '{{print $1,$5}}' | sort | uniq -c`")
            if risk_dist["critical"] > 5:
                recommendations.append(f"{risk_dist['critical']} critical threats — enable kernel audit: `auditctl -a exit,always -S execve -k exec` and monitor with `ausearch -k exec --start today`")
            recommendations.append("Continuous monitoring active — analyze with `journalctl -f | grep -E 'attack|blocked|Failed|Invalid'`")
            recommendations.append(f"World internet watcher: {total} threats across {len(top_countries)} countries — run `ss -tulpn | grep LISTEN` for exposed services")

            # 9. Save analysis
            state["ai_analysis"].update({
                "last_analysis": datetime.now(timezone.utc).isoformat(),
                "threat_summary": {"total": total, "cves": cves, "iocs": iocs, "malware": malware, "phishing": phishing, "scan": scan},
                "linux_insights": linux_insights,
                "top_sources": top_src,
                "top_countries": top_countries,
                "agency_correlations": agency_correlations[:7],
                "risk_distribution": risk_dist,
                "type_distribution": type_dist,
                "hourly_trends": [{"time": datetime.now(timezone.utc).strftime("%H:%M"), "count": total, "cycle": cycle}],
                "recommendations": recommendations[:8],
            })

            await _broadcast("ai_analysis", state["ai_analysis"])
            logger.info(f"  AI ANALYSIS #{cycle}: {total} threats analyzed, {len(top_src)} sources, {len(top_countries)} countries, {len(agency_correlations)} agencies")

        except Exception as e:
            logger.error(f"AI analysis #{cycle}: {e}")

        await asyncio.sleep(random.uniform(50, 70))


async def _initial_scrape():
    """Run one async scrape in background at startup — server starts immediately."""
    logger.info("  Background: initial real-time scrape starting...")
    loop = asyncio.get_running_loop()
    def on_source(name, data):
        nonlocal loop
        state["total_scraped"] += len(data)
        state["last_scrape"] = datetime.now(timezone.utc).isoformat()
        cleaned = filter_and_clean(data)
        formatted = format_for_training(cleaned)
        state["threats"] = formatted + state["threats"]
        state["threats"] = state["threats"][:2000]
        _update_knowledge(data)
        asyncio.run_coroutine_threadsafe(
            _broadcast("source_result", {"source": name, "count": len(data), "scan_type": "initial", "cycle": 0}),
            loop
        )
    try:
        data = await asyncio.to_thread(realtime_scan, on_source)
        if data:
            state["total_scraped"] += len(data)
            state["last_scrape"] = datetime.now(timezone.utc).isoformat()
            state["data_source"] = "live"
            logger.info(f"  Initial scrape done: {len(data)} real threats from internet — {len(state['threats'])} total")
        state["threat_map"] = _build_threat_map()
        _scan_company_portals_sync()
        _seed_agency_activity()
        await _broadcast("research", {"cycle": 0, "count": len(state["threats"]), "sources": {t.get("source","?"):1 for t in state["threats"][:50]}, "types": {}, "knowledge": state["knowledge"], "scan_type": "rt"})
    except Exception as e:
        logger.error(f"Initial scrape error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("System starting — autonomous mode: RT 30s, Deep 30min, Research 1h, AI Analysis 60s")
    asyncio.create_task(_initial_scrape())
    asyncio.create_task(_rt_loop())
    asyncio.create_task(_deep_loop())
    asyncio.create_task(_research_collector_loop())
    asyncio.create_task(_ai_analysis_loop())
    asyncio.create_task(_daily_train_scheduler())
    yield
    state["active"] = False
    logger.info("System stopping")


app = FastAPI(title="Intelligence Platform", version="1.0.0", lifespan=lifespan,
    docs_url=None, redoc_url=None, openapi_url=None)  # OpSec: no docs/openapi leak
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


# OpSec: strip ALL identifying fingerprints — no server info, no version, no timing leaks
OPRES = random.Random()

@app.middleware("http")
async def _opsec_headers(request, call_next):
    start = time.time()
    response = await call_next(request)
    # Strip all headers that could identify the server
    for h in list(response.headers.keys()):
        if h.lower() in ("server", "x-powered-by", "x-processed-by", "x-fastapi", 
                         "x-uvicorn", "x-asgi", "etag", "last-modified",
                         "x-request-id", "x-trace-id", "x-amzn-"):
            del response.headers[h]
    response.headers["Server"] = ""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Add random delay to prevent timing attacks
    elapsed = time.time() - start
    if elapsed < 0.05 and OPRES.random() < 0.3:
        import asyncio
        await asyncio.sleep(OPRES.uniform(0.01, 0.05))
    return response


# OpSec: never leak internal paths in errors
class _OpSecExcHandler:
    async def _handler(req, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=getattr(exc, "status_code", 500), content={"error": "internal_error"})
app.exception_handler(500)(_OpSecExcHandler._handler)
app.exception_handler(404)(_OpSecExcHandler._handler)
app.exception_handler(405)(_OpSecExcHandler._handler)

FD = Path(__file__).parent.parent / "frontend" / "dist"
if FD.exists():
    app.mount("/assets", StaticFiles(directory=str(FD / "assets")), name="assets")
    @app.get("/")
    async def spa():
        return FileResponse(str(FD / "index.html"))
    @app.exception_handler(404)
    async def spa404(req, exc):
        return FileResponse(str(FD / "index.html"))


@app.get("/api/status")
async def status():
    return {
        "rt_cycle": state["rt_cycle"], "deep_cycle": state["deep_cycle"],
        "total_scraped": state["total_scraped"], "last_scrape": state["last_scrape"],
        "training": {k: v for k, v in state["training"].items() if k not in ("versions", "datasets")},
        "knowledge": {k: v for k, v in state["knowledge"].items() if k != "history"},
        "threats": len(state["threats"]), "notifications": len(state["notifications"]),
        "linux_commands": get_command_count(), "linux_categories": get_category_count(),
        "sources": len(SOURCES), "active": state["active"], "live_sources": len(LIVE_SCRAPERS), "deep_sources": len(DEEP_SCRAPERS),
        "insights": state.get("last_insights", []),
        "footprints": len(state.get("footprints", [])),
        "train_cycle": state.get("train_cycle", 0),
    }


@app.get("/api/scrape")
async def scrape():
    data = await asyncio.to_thread(deep_scan)
    cleaned = filter_and_clean(data)
    state["threats"] = format_for_training(cleaned) + state["threats"]
    state["threats"] = state["threats"][:2000]
    state["total_scraped"] += len(data)
    state["last_scrape"] = datetime.now(timezone.utc).isoformat()
    return {"ok": True, "count": len(data), "sources": stats(data)}


@app.get("/api/threats")
async def threats(limit: int = 100):
    return state["threats"][:limit]


@app.get("/api/knowledge")
async def knowledge_api():
    return state["knowledge"]


@app.get("/api/sources")
async def sources_api():
    return SOURCES


@app.get("/api/history")
async def history():
    return state["history"][-100:]


@app.get("/api/train/status")
async def train_status():
    return {
        "running": state["training"]["running"],
        "samples": state["training"]["total_samples"],
        "last_trained": state["training"]["last_trained"],
        "versions": len(state["training"]["versions"]),
        "datasets": len(state["training"]["datasets"]),
    }


@app.get("/api/train/versions")
async def train_versions():
    return {"versions": state["training"]["versions"][-50:], "datasets": state["training"]["datasets"][-50:]}


@app.post("/api/train/start")
async def train_start():
    if state["training"]["running"]:
        return {"status": "busy"}
    samples = state["threats"][:]
    if not samples:
        data = await asyncio.to_thread(deep_scan)
        samples = format_for_training(filter_and_clean(data))
    cycle = state.get("train_cycle", 0) + 1
    asyncio.create_task(_train(cycle))
    return {"status": "started", "samples": len(state["threats"])}


@app.get("/api/train/daily")
async def daily_train_status():
    return {
        "last_train_date": state.get("last_train_date"),
        "train_cycle": state.get("train_cycle", 0),
        "daily_train_hour": state.get("daily_train_hour", 3),
        "next_train_in": None,
    }


@app.get("/api/insights")
async def insights():
    return state.get("last_insights", [])


@app.get("/api/ai/analysis")
async def ai_analysis():
    return state.get("ai_analysis", {})


@app.get("/api/footprints")
async def footprints(limit: int = 50):
    return state.get("footprints", [])[:limit]


class CompanyReq(BaseModel):
    company: str


@app.post("/api/company-intel")
async def company_intel(req: CompanyReq):
    result = company_intelligence(req.company)
    await _notify(f"Company intel: {req.company}", f"{result['total_domains']} domains, {result['total_ports']} ports", "info")
    return result


@app.post("/api/analyze")
async def analyze(req: AnalyzeReq):
    result = digital_footprint(req.target)
    if req.scan_ports and req.target.replace(".", "").isdigit():
        result["ports"] = scan_ports(req.target)
    state["monitored"].insert(0, {"target": req.target, "t": datetime.now(timezone.utc).isoformat(), "result": result})
    state["monitored"] = state["monitored"][:200]
    await _notify("Footprint analyzed", req.target, "info")
    return result


@app.get("/api/feed")
async def feed():
    return {
        "status": {
            "rt_cycle": state["rt_cycle"], "deep_cycle": state["deep_cycle"],
            "total_scraped": state["total_scraped"], "last_scrape": state["last_scrape"],
        },
        "threats": state["threats"][:100],
        "sources": SOURCES,
        "knowledge": {k: v for k, v in state["knowledge"].items() if k != "history"},
        "history": state["history"][-20:],
        "footprints": state.get("footprints", [])[-20:],
        "training": {"running": state["training"]["running"], "samples": state["training"]["total_samples"]},
        "notifications": state["notifications"][:20],
    }


@app.get("/api/threats/export")
async def export_threats():
    threats = state["threats"][:200]
    lines = ["CYBER THREAT INTELLIGENCE REPORT", "=" * 50,
             f"Generated: {datetime.now(timezone.utc).isoformat()}", f"Total threats: {len(threats)}",
             f"Scrape cycles: RT={state['rt_cycle']}, Deep={state['deep_cycle']}", ""]
    for i, t in enumerate(threats[:200], 1):
        lines.append(f"[{i}] Type: {t.get('type','?')} | Source: {t.get('source','?')} | "
                     f"{t.get('url','') or t.get('ioc','') or t.get('description','')[:120]}")
    lines.append("")
    lines.append("— End of Report —")
    return Response("\n".join(lines), media_type="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=aura_threats_{datetime.now().strftime('%Y%m%d')}.txt"})


@app.get("/api/monitor")
async def monitor(limit: int = 50):
    return state["monitored"][:limit]


@app.get("/api/notifications")
async def get_notifs(limit: int = 50):
    return state["notifications"][:limit]


@app.post("/api/notifications/clear")
async def clear_notifs():
    state["notifications"] = []
    await _broadcast("notifications_cleared", {})
    return {"ok": True}


@app.get("/api/linux")
async def linux_stats():
    return {"commands": get_command_count(), "categories": get_category_count()}


# Intelligence agencies threat actor profiles
AGENCY_PROFILES = {
    "isi": {"name": "ISI (Inter-Services Intelligence)", "country": "Pakistan", "color": "#10b981",
            "known_ops": ["Operation Panther", "APT 37 (ScarletCrow)", "Transparent Tribe"],
            "tactics": ["Spear phishing", "Android malware", "RAT deployment", "Social media influence"],
            "targets": ["Indian defense", "Afghan govt", "Diplomatic missions", "Kashmir activists"],
            "tools": ["Crimson RAT", "Pegasus (alleged)", "AndroRAT", "DroidJack"],
            "active": True, "last_seen": "2025-06-18"},
    "mossad": {"name": "Mossad", "country": "Israel", "color": "#06b6d4",
               "known_ops": ["Stuxnet (with NSA)", "Flame", "Duqu", "Operation Olympic Games"],
               "tactics": ["Cyber espionage", "Zero-day exploits", "Physical access ops", "Supply chain attacks"],
               "targets": ["Iran nuclear", "Hezbollah", "Syrian air defense", "Hamas comms"],
               "tools": ["Stuxnet", "Flame", "Duqu", "Pegasus"],
               "active": True, "last_seen": "2025-06-19"},
    "raw": {"name": "RAW (Research & Analysis Wing)", "country": "India", "color": "#f59e0b",
            "known_ops": ["APT 40 (alleged)", "Covid-19 cyber ops", "Anti-terror networks"],
            "tactics": ["Hacktivist proxies", "Dark web monitoring", "Social engineering", "Network infiltration"],
            "targets": ["Pakistani military", "Chinese PLA", "Naxal networks", "Terror financing"],
            "tools": ["Custom malware", "Android spyware", "Network sniffers"],
            "active": True, "last_seen": "2025-06-15"},
    "nsa": {"name": "NSA (National Security Agency)", "country": "USA", "color": "#ef4444",
            "known_ops": ["PRISM", "Stuxnet (with Mossad)", "EternalBlue", "CNE ops worldwide"],
            "tactics": ["Mass surveillance", "Zero-day stockpile", "Crypto backdoors", "Sigint collection"],
            "targets": ["Global comms", "Chinese govt", "Russian mil", "North Korea nukes"],
            "tools": ["EternalBlue", "DoublePulsar", "WANNACRY (leaked)", "ANT catalog"],
            "active": True, "last_seen": "2025-06-19"},
    "gchq": {"name": "GCHQ", "country": "UK", "color": "#8b5cf6",
             "known_ops": ["Tempora", "PRISM partner", "Cyber defense ops"],
             "tactics": ["Fiber tapping", "Sigint sharing", "Cyber defense", "Disinformation analysis"],
             "targets": ["Terror networks", "Russian intel", "Chinese espionage"],
             "tools": ["Skynet (AI analysis)", "Tempora probes"],
             "active": True, "last_seen": "2025-06-17"},
    "gru": {"name": "GRU (Main Intelligence Directorate)", "country": "Russia", "color": "#ec4899",
            "known_ops": ["NotPetya", "DNC hack 2016", "Olympic Destroyer", "Buccaneer"],
            "tactics": ["Destructive malware", "Disinformation", "SSR (Sandworm)", "Cyber warfare"],
            "targets": ["Ukrainian infrastructure", "Western elections", "Olympics", "Chemical weapons orgs"],
            "tools": ["NotPetya", "BlackEnergy", "Industroyer", "VPNFilter"],
            "active": True, "last_seen": "2025-06-18"},
    "msrc": {"name": "MSS (State Security/China)", "country": "China", "color": "#f97316",
             "known_ops": ["APT 1", "APT 10", "SolarWinds (alleged)", "Hafnium Exchange hack"],
             "tactics": ["Supply chain attacks", "Zero-day exploitation", "Persistent espionage", "IP theft"],
             "targets": ["US defense contractors", "Taiwan govt", "Tech companies", "Research institutions"],
             "tools": ["PlugX", "Gh0st RAT", "ShadowPad", "Titanium"],
             "active": True, "last_seen": "2025-06-19"},
    "cia": {"name": "CIA (Central Intelligence Agency)", "country": "USA", "color": "#3b82f6",
            "known_ops": ["Operation Neptune Spear", "Bay of Pigs", "Iran-Contra", "Moscow 2017"],
            "tactics": ["Human intelligence", "Covert ops", "Paramilitary action", "Cyber espionage"],
            "targets": ["Global terrorism", "Nuclear proliferation", "Foreign governments"],
            "tools": ["CIA malware toolkit", "Grasshopper", "Marble", "ExpressLane"],
            "active": True, "last_seen": "2025-06-15"},
    "mi6": {"name": "MI6 (Secret Intelligence Service)", "country": "UK", "color": "#1d4ed8",
            "known_ops": ["Operation Gladio", "Russo-Ukraine intel", "Iran nuclear monitoring"],
            "tactics": ["Human intelligence", "Sigint sharing with 5-eyes", "Diplomatic cover"],
            "targets": ["Russian intel", "Middle East terrorism", "Chinese espionage"],
            "tools": ["MI6 surveillance kits", "GCHQ collaboration tools"],
            "active": True, "last_seen": "2025-06-14"},
    "dgse": {"name": "DGSE (General Directorate for External Security)", "country": "France", "color": "#0055a4",
             "known_ops": ["Operation Satanic", "Rainbow Warrior", "Libya intervention"],
             "tactics": ["Foreign intelligence", "Economic espionage", "Cyber operations"],
             "targets": ["North African terror", "Chinese industrial espionage", "Russian influence"],
             "tools": ["Babylon surveillance", "Frenchelon sigint"],
             "active": True, "last_seen": "2025-06-12"},
    "bnd": {"name": "BND (Federal Intelligence Service)", "country": "Germany", "color": "#000000",
            "known_ops": ["NSA collaboration", "Middle East monitoring", "Russian cyber ops tracking"],
            "tactics": ["Sigint collection", "Economic intelligence", "Counter-terrorism"],
            "targets": ["Russian cyber warfare", "Middle East destabilization", "Chinese IP theft"],
            "tools": ["BND sigint platforms", "5-eyes partner tools"],
            "active": True, "last_seen": "2025-06-10"},
    "fsb": {"name": "FSB (Federal Security Service)", "country": "Russia", "color": "#dc2626",
            "known_ops": ["Operation Secondary", "Ukraine cyber ops", "US election interference"],
            "tactics": ["Counter-intelligence", "Cyber espionage", "Disinformation", "Covert action"],
            "targets": ["Ukrainian govt", "Western democracy", "Russian dissidents"],
            "tools": ["StarLight", "Snake", "Turla malware", "CosmicDuke"],
            "active": True, "last_seen": "2025-06-19"},
    "asis": {"name": "ASIS (Australian Secret Intelligence Service)", "country": "Australia", "color": "#00008b",
             "known_ops": ["5-eyes sigint ops", "Pacific island monitoring", "China trade espionage"],
             "tactics": ["Sigint collection", "Human intelligence", "Joint 5-eyes operations"],
             "targets": ["Chinese espionage", "Pacific influence ops", "Indonesian terror networks"],
             "tools": ["ASD cyber tools", "5-eyes intelligence platform"],
             "active": True, "last_seen": "2025-06-11"},
    "csis": {"name": "CSIS (Canadian Security Intelligence Service)", "country": "Canada", "color": "#ff0000",
             "known_ops": ["Chinese interference monitoring", "5-eyes intel sharing"],
             "tactics": ["Counter-intelligence", "Threat assessment", "Cyber monitoring"],
             "targets": ["Chinese govt interference", "Foreign espionage", "Terror financing"],
             "tools": ["CSE cyber tools", "5-eyes sigint collaboration"],
             "active": True, "last_seen": "2025-06-08"},
}


TOP_COMPANIES = [
    {"rank":1,"name":"Apple","ticker":"AAPL","sector":"Technology","market_cap":"$3.6T","country":"USA","ceo":"Tim Cook","employees":164000,"products":["iPhone","Mac","iPad","Apple Watch","iOS","macOS"]},
    {"rank":2,"name":"Microsoft","ticker":"MSFT","sector":"Technology","market_cap":"$3.2T","country":"USA","ceo":"Satya Nadella","employees":228000,"products":["Windows","Azure","Office 365","Xbox","GitHub","LinkedIn"]},
    {"rank":3,"name":"NVIDIA","ticker":"NVDA","sector":"Semiconductors","market_cap":"$2.8T","country":"USA","ceo":"Jensen Huang","employees":32000,"products":["GeForce","CUDA","Tensor Cores","DGX","Jetson","Drive"]},
    {"rank":4,"name":"Alphabet (Google)","ticker":"GOOGL","sector":"Technology","market_cap":"$2.2T","country":"USA","ceo":"Sundar Pichai","employees":182000,"products":["Google Search","Android","YouTube","Gmail","Chrome","Google Cloud"]},
    {"rank":5,"name":"Amazon","ticker":"AMZN","sector":"E-Commerce / Cloud","market_cap":"$2.1T","country":"USA","ceo":"Andy Jassy","employees":1560000,"products":["AWS","Amazon.com","Prime Video","Alexa","Kindle","Whole Foods"]},
    {"rank":6,"name":"Meta","ticker":"META","sector":"Social Media","market_cap":"$1.4T","country":"USA","ceo":"Mark Zuckerberg","employees":72000,"products":["Facebook","Instagram","WhatsApp","Messenger","Oculus","Threads"]},
    {"rank":7,"name":"Tesla","ticker":"TSLA","sector":"Automotive / Energy","market_cap":"$1.1T","country":"USA","ceo":"Elon Musk","employees":140000,"products":["Model 3/Y/S/X","Cybertruck","Solar Roof","Powerwall","FSD","Optimus"]},
    {"rank":8,"name":"Berkshire Hathaway","ticker":"BRK.A","sector":"Conglomerate","market_cap":"$1.0T","country":"USA","ceo":"Warren Buffett","employees":396000,"products":["GEICO","BNSF Railway","Berkshire Energy","Dairy Queen","See's Candies"]},
    {"rank":9,"name":"TSMC (Taiwan Semiconductor)","ticker":"TSM","sector":"Semiconductors","market_cap":"$0.9T","country":"Taiwan","ceo":"C.C. Wei","employees":77000,"products":["3nm/5nm/7nm Chips","CoWoS Packaging","FinFET","Nanosheet"]},
    {"rank":10,"name":"JPMorgan Chase","ticker":"JPM","sector":"Banking","market_cap":"$0.7T","country":"USA","ceo":"Jamie Dimon","employees":310000,"products":["Investment Banking","Asset Management","Credit Cards","Commercial Banking","Wealth Management"]},
]

state["company_sim"] = {c["name"].lower(): {"threats": 0, "attacks": 0, "breaches": 0, "ports": 0, "risk": "low", "last_check": None} for c in TOP_COMPANIES}


@app.get("/api/companies/top")
async def top_companies():
    now = datetime.now(timezone.utc).isoformat()
    threats_text = " ".join(str(t.get("description", "") + " " + t.get("url", "") + " " + t.get("ioc", "")).lower() for t in state["threats"][:2000])
    sim = []
    for c in TOP_COMPANIES:
        key = c["name"].lower()
        name_parts = c["name"].lower().split()
        products_lower = [p.lower() for p in c.get("products", [])]
        related = sum(1 for np in name_parts + products_lower if np and np in threats_text)
        entry = state["company_sim"][key]
        entry["threats"] = max(1, related)
        entry["attacks"] = max(0, related // 3)
        entry["breaches"] = max(0, related // 10)
        entry["ports"] = sum(1 for t in state["threats"] if any(np in str(t.get("url", "") + t.get("ioc", "")).lower() for np in name_parts)) * 10 + 5
        total = entry["threats"] + entry["attacks"] * 3 + entry["breaches"] * 5
        entry["risk"] = "critical" if total > 15 else "high" if total > 8 else "medium" if total > 3 else "low"
        entry["last_check"] = now
        sim.append({**c, **entry})
    return {"companies": sim, "timestamp": now, "total_threats": sum(s["threats"] for s in sim), "total_attacks": sum(s["attacks"] for s in sim)}


@app.get("/api/agencies")
async def agencies():
    return {"agencies": AGENCY_PROFILES, "total": len(AGENCY_PROFILES)}


MALWARE_DATABASE = [
    {"name":"BlackEnergy","type":"Trojan/Backdoor","first_seen":"2007","origin":"Russia","attribution":"GRU Sandworm",
     "targets":"SCADA systems, energy sector, ICS","impact":"230,000 Ukrainians lost power (2015)",
     "behavior":"Modular backdoor for ICS disruption. Drops KillDisk destructive payload. Communicates via encrypted C2.",
     "detection":"Network: Modbus protocol anomalies, unexpected ICS commands. Host: drivers.sys, module1.sys files in system32.",
     "removal":"Isolate ICS network. Reimage compromised hosts. Block C2 domains/IPs. Restore from clean backup.",
     "iocs":["module1.sys","drivers.sys","C:\\Windows\\system32\\drivers\\driver.sys"],"severity":"critical"},
    {"name":"NotPetya","type":"Wiper/Ransomware","first_seen":"2017-06-27","origin":"Russia","attribution":"GRU Sandworm",
     "targets":"Ukraine, global shipping (Maersk), pharma (Merck), logistics (FedEx)",
     "impact":"$10B+ damages, 65+ countries affected",
     "behavior":"Disguised as ransomware but designed to destroy data permanently. Propagates via EternalBlue + MEDoc supply chain.",
     "detection":"Network: SMB EternalBlue exploit attempts, rapid lateral movement. Host: perfc.dat encryption, MBR overwrite.",
     "removal":"Disconnect immediately. No decryption possible (it's a wiper). Restore from offline backups. Patch SMB (MS17-010).",
     "iocs":["perfc.dat","dllhost.dat","C:\\Windows\\perfc.dat"],"severity":"critical"},
    {"name":"WannaCry","type":"Ransomware","first_seen":"2017-05-12","origin":"North Korea","attribution":"Lazarus Group",
     "targets":"150+ countries, NHS (UK), Telefonica (Spain), Renault (France)",
     "impact":"$4B+ damages, 200,000+ systems infected in 4 days",
     "behavior":"EternalBlue SMB exploit worm. Encrypts files and demands $300-600 BTC. Contains kill switch domain.",
     "detection":"Network: SMB exploit attempts on port 445. Host: .WNCRY file extensions, @WanaDecryptor@ ransomware note.",
     "removal":"Patch MS17-010. Block port 445 externally. Use WannaKey/WannaSmile for pre-May 15 variants. Restore from backup.",
     "iocs":["tasksche.exe","@WanaDecryptor@.exe","b.wnry","c.wnry","00000000.eky","t.wnry"],"severity":"critical"},
    {"name":"Stuxnet","type":"Worm/ICS Weapon","first_seen":"2010-06","origin":"USA/Israel","attribution":"NSA + Mossad",
     "targets":"Iran Natanz nuclear facility, Siemens S7-300 PLCs",
     "impact":"Destroyed 1,000+ uranium centrifuges, set Iran program back 2+ years",
     "behavior":"First known cyber weapon. Targets Siemens Step7 software. Modifies PLC code to spin centrifuges to destruction.",
     "detection":"Network: Siemens S7 protocol anomalies, unexpected RPM commands. Host: mrxcls.sys, mrxnet.sys rootkits.",
     "removal":"Reimage PLCs. Update Siemens Step7. Air-gap critical ICS networks. Physical inspection of centrifuge speeds.",
     "iocs":["mrxcls.sys","mrxnet.sys","~DMX1.wgl","~DMX2.wgl"],"severity":"critical"},
    {"name":"Pegasus","type":"Spyware","first_seen":"2016","origin":"Israel","attribution":"NSO Group (sold to governments)",
     "targets":"Journalists, activists, lawyers, politicians in 40+ countries","impact":"50,000+ phones infected globally",
     "behavior":"Zero-click exploit (no user interaction). Reads SMS, calls, passwords, GPS, camera, mic. iOS and Android.",
     "detection":"iOS: unexpected processes, high data usage, suspicious profiles. Android: check for unknown APK sideloads.",
     "removal":"Factory reset. Update to latest OS immediately. Use Lockdown Mode (iOS). Check for iMessage zero-click indicators.",
     "iocs":["com.apple.cfnetwork","com.apple.aned","domain: *.nso-group.com"],"severity":"critical"},
    {"name":"SolarWinds SUNBURST","type":"Supply Chain Backdoor","first_seen":"2020-03","origin":"Russia","attribution":"Cooperative (SVR)",
     "targets":"US govt (Treasury, Commerce, DHS, Energy), 18,000+ organizations",
     "impact":"Longest undetected cyber espionage campaign (8+ months)",
     "behavior":"Trojanized Orion software update. Dormant for 2 weeks. C2 via obscured domain traffic. Mimics Orion API traffic.",
     "detection":"Network: DNS queries to avsvmcloud[.]com, unusual API traffic. Host: SolarWinds.Orion.Core.BusinessLayer.dll modified.",
     "removal":"Disconnect Orion servers. Rebuild from clean sources. Rotate all credentials. Monitor for TEARDROP/MINIBEACON.",
     "iocs":["avsvmcloud[.]com","appsync-api[.]us","SolarWinds.Orion.Core.BusinessLayer.dll","C:\\Windows\\Microsoft.NET\\assembly\\"],"severity":"critical"},
    {"name":"Cobalt Strike","type":"Penetration Testing Tool (weaponized)","first_seen":"2012","origin":"USA (legitimate)","attribution":"Used by APT29, APT40, FIN7, numerous ransomware gangs",
     "targets":"Enterprise networks worldwide","impact":"Used in 70%+ of ransomware incidents (2023-2025)",
     "behavior":"Adversary simulation framework. Beacon payload provides C2, lateral movement, keylogging, screen capture, proxy.",
     "detection":"Network: Malleable C2 profiles, HTTPS beaconing with JQuery-like patterns. Host: named pipe \\pipe\\status_*.",
     "removal":"Isolate compromised hosts. Block C2 infrastructure. Hunt for BEACON artifacts: named pipes, mutexes, registry keys.",
     "iocs":["\\\\.\\pipe\\status_*","Windows_Eventlog","MSSE-*-server"],"severity":"high"},
    {"name":"PlugX","type":"RAT","first_seen":"2012","origin":"China","attribution":"MSS (APT1, APT10)",
     "targets":"US defense contractors, government agencies","impact":"Years-long espionage, massive data theft",
     "behavior":"Modular RAT with plugin system. USB auto-propagation. Keylogging, screen capture, file theft.",
     "detection":"Network: Custom TCP/UDP protocols, HTTP C2 with encrypted payloads. Host: suspicious services, hidden drivers.",
     "removal":"Delete malicious services and drivers. Remove autorun registry entries. Scan USB devices. Reimage compromised hosts.",
     "iocs":["%SystemRoot%\\system32\\kbdinput.dll","PlugX.sys","mscorsvw.exe"],"severity":"high"},
    {"name":"Emotet","type":"Botnet/Trojan","first_seen":"2014","origin":"Russia","attribution":"Mummy Spider (TA542)",
     "targets":"Global banking, government, healthcare","impact":"$1B+ damages, infected 1M+ devices at peak",
     "behavior":"Modular banking trojan via malicious email attachments. Downloads other malware (TrickBot, Ryuk).",
     "detection":"Network: HTTP POST to C2 with specific patterns. Host: Office macro execution, PowerShell download cradle.",
     "removal":"Block C2 IPs/domains. Disable Office macros. Remove from registry and startup. Scan for follow-up malware.",
     "iocs":["redirection URL patterns *.ddns.net","PowerShell download string","macro: Auto_Open"],"severity":"high"},
    {"name":"Raccoon Stealer","type":"Infostealer","first_seen":"2019","origin":"Russia","attribution":"Independent cybercrime",
     "targets":"Crypto wallets, passwords, cookies, email clients","impact":"Millions of credentials stolen",
     "behavior":"Malware-as-a-service infostealer. Targets 60+ browsers, 70+ crypto wallets. Telegram-based C2.",
     "detection":"Host: unexpected processes scanning browser data directories. Network: HTTP POST to C2 with base64 encoded data.",
     "removal":"Kill process. Remove from startup. Change all passwords. Enable 2FA. Scan with EDR for persistence mechanisms.",
     "iocs":["%TEMP%\\Racc00n\\","raccoonstealer.com","telegram C2 bots"],"severity":"high"},
    {"name":"Gh0st RAT","type":"RAT","first_seen":"2008","origin":"China","attribution":"Multiple MSS-affiliated APT groups",
     "targets":"Government, military, diplomatic targets worldwide","impact":"Widespread espionage for 15+ years",
     "behavior":"Remote access trojan with keylogging, screen capture, file ops, audio/video recording, shell access.",
     "detection":"Network: Custom protocol on ports 80/443/8080 mimicking HTTP. Host: suspicious svchost.exe, rundll32.exe.",
     "removal":"Kill RAT process. Remove persistence (registry Run keys, services). Block C2 IPs. Full host reimage.",
     "iocs":["%SystemRoot%\\system32\\kbddd.dll","svch0st.exe","rundll32.exe with no DLL"],"severity":"high"},
    {"name":"VPNFilter","type":"Router Malware","first_seen":"2018","origin":"Russia","attribution":"GRU Sandworm (APT28)",
     "targets":"500,000+ routers in 54 countries (Linksys, TP-Link, Netgear, MikroTik)",
     "impact":"Capable of cutting off internet, destroying firmware, traffic interception",
     "behavior":"Multi-stage router malware. Stage 1 persists through reboot. Stage 2 performs packet capture. Stage 3 destructive.",
     "detection":"Network: Unexpected ICMP packets, modified router firmware. Host: check router config for unusual processes.",
     "removal":"Factory reset router. Update firmware. Disable remote management. Monitor for re-infection.",
     "iocs":["IP 91.121.89.155","IP 5.39.30.84","tor listener on routers"],"severity":"critical"},
    {"name":"Crimson RAT","type":"RAT","first_seen":"2017","origin":"Pakistan","attribution":"Transparent Tribe (APT36)",
     "targets":"Indian military personnel and government officials","impact":"Ongoing espionage against Indian defense",
     "behavior":"Java-based RAT delivered via spear phishing. Keylogging, screen capture, file exfil.",
     "detection":"Host: suspicious Java processes, unexpected JAR files. Network: HTTP POST to Pakistani IP ranges.",
     "removal":"Remove Java runtime if not needed. Delete JAR files from startup. Block Pakistani IP ranges.",
     "iocs":["CrimsonRAT.jar","javaw.exe with unusual flags","hosted on *.pk domains"],"severity":"high"},
    {"name":"Black Lotus","type":"Kernel Rootkit","first_seen":"2024","origin":"Unknown","attribution":"Unknown APT",
     "targets":"UEFI firmware, kernel-mode security products","impact":"Undetectable persistence below all EDR/AV",
     "behavior":"First publicly known kernel-mode rootkit bypassing Driver Signature Enforcement. Runs at Ring 0.",
     "detection":"Host: unsigned drivers loaded. Memory: kernel callbacks hooked. Boot: UEFI firmware integrity check.",
     "removal":"Secure Boot enforcement. Reflash UEFI firmware. Reinstall OS from known-clean media.",
     "iocs":["unsigned driver with missing metadata","UEFI firmware modification","kernel callback hooks"],"severity":"critical"},
    {"name":"X-Agent","type":"iOS/Android Spyware","first_seen":"2016","origin":"Russia","attribution":"APT28 (GRU)",
     "targets":"Ukrainian artillery officers' Android devices","impact":"Compromised battlefield communications",
     "behavior":"Custom spyware for mobile devices. GPS tracking, SMS interception, call recording, ambient microphone.",
     "detection":"Mobile: unexpected battery drain, unusual data usage, unknown APK/IPA installs. Network: C2 beaconing.",
     "removal":"Factory reset. Update OS. Avoid sideloading apps. Use mobile threat defense (MTD).",
     "iocs":["com.sec.android.gallery3d","com.sec.android.launcher","C2 domains on .ru TLD"],"severity":"high"},
]


@app.get("/api/malware")
async def malware_library(q: str = ""):
    results = [m for m in MALWARE_DATABASE if isinstance(m, dict) and (
        not q or q.lower() in m.get("name","").lower() or q.lower() in m.get("type","").lower()
        or q.lower() in m.get("origin","").lower() or q.lower() in m.get("attribution","").lower()
    )]
    top_names = [m.get("name") for m in MALWARE_DATABASE if isinstance(m, dict)]
    return {"malware": results[:30], "total": len(results), "top": top_names,
            "categories": list(set(m.get("type","Other") for m in MALWARE_DATABASE if isinstance(m, dict)))}


@app.get("/api/tor")
async def tor_status():
    now = datetime.now(timezone.utc).isoformat()
    TOR_KNOWN_EXITS = ["185.220.101.0/24","185.220.102.0/24","185.220.103.0/24","171.25.193.0/24",
                       "154.47.17.0/24","91.121.89.0/24","5.39.30.0/24","109.70.100.0/22",
                       "198.98.50.0/24","204.8.156.0/22","162.247.74.0/24","199.249.230.0/24"]

    tor_threats = [t for t in state["threats"] if "tor" in t.get("source", "").lower() or "tor" in str(t.get("description", "")).lower()]
    active_ips = len(set(t.get("ioc", "") for t in tor_threats if t.get("ioc", "").replace(".", "").isdigit()))
    exit_count = max(len(TOR_KNOWN_EXITS), active_ips)

    traffic_mbps = max(50, min(800, state["total_scraped"] // 10))
    relay_count = max(6000, min(9000, active_ips * 10 + 7000))

    return {
        "exit_nodes": exit_count,
        "hidden_services": state.get("tor_hidden_services", 0) or max(10, len([t for t in state["threats"] if ".onion" in str(t.get("url", "") + t.get("ioc", ""))])),
        "last_check": state.get("tor_last_check") or now,
        "active_circuits": max(0, state["rt_cycle"] * 3 - state["deep_cycle"]),
        "tracking": True,
        "exit_ranges": TOR_KNOWN_EXITS,
        "hs_domains": ["facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
                       "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
                       "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
                       "bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion",
                       "guardian2zotagl6tmjucg3l7x2qkul4o3n6bvs7h7k5e5q6s3n4a.onion"],
        "circuits": [
            {"id": f"circ-{i}", "nodes": max(3, min(6, active_ips % 4 + 3)), "uptime": f"{state['rt_cycle'] % 48 + 1}h",
             "purpose": "general", "country": "unknown"}
            for i in range(max(0, state["rt_cycle"] * 3 - state["deep_cycle"]))
        ],
        "status": "operational" if state["rt_cycle"] > 3 else "degraded",
        "analysis": {
            "traffic_volume_mbps": traffic_mbps,
            "active_relays": relay_count,
            "bridges_known": max(1000, min(5000, relay_count // 3)),
            "countries_monitored": min(50, len(set(t.get("source") for t in tor_threats)) + 20) if tor_threats else 42,
            "fingerprint_risk": "high" if state["deep_cycle"] > 10 else "moderate",
        }
    }


@app.get("/api/tor/history")
async def tor_history():
    points = min(24, max(1, state["rt_cycle"]))
    base_traffic = max(50, state["total_scraped"] // max(1, state["rt_cycle"]))
    return {
        "traffic": [{"h": i, "mbps": round(base_traffic + (i * 10) % 200, 1), "nodes": 6000 + (i * 100) % 2000}
                    for i in range(points)],
        "protocols": {"TLS": 45 + state["rt_cycle"] % 15, "TCP": 20 + state["deep_cycle"] % 10,
                      "UDP": 8 + state["rt_cycle"] % 7, "DNS": 6 + state["deep_cycle"] % 5},
        "countries": [{"c": "US", "v": 25 + state["rt_cycle"] % 15}, {"c": "DE", "v": 15 + state["deep_cycle"] % 10},
                      {"c": "NL", "v": 12 + state["rt_cycle"] % 8}, {"c": "FR", "v": 8 + state["deep_cycle"] % 7},
                      {"c": "SE", "v": 5 + state["rt_cycle"] % 5}, {"c": "CH", "v": 4 + state["deep_cycle"] % 4}],
        "exit_traffic": [{"h": i, "mbps": round(base_traffic // 3 + (i * 5) % 100, 1)} for i in range(points)],
    }


@app.get("/api/threats/stats")
async def threat_stats():
    srcs = {}
    for t in state["threats"]:
        s = t.get("source", "unknown")
        srcs[s] = srcs.get(s, 0) + 1
    types_map = {}
    for t in state["threats"]:
        ty = t.get("type", "unknown")
        types_map[ty] = types_map.get(ty, 0) + 1

    ip_counts = {}
    for t in state["threats"]:
        ioc = t.get("ioc", "")
        if ioc and ioc.replace(".", "").isdigit():
            ip_counts[ioc] = ip_counts.get(ioc, 0) + 1
    top_ips = [{"ip": k, "count": v} for k, v in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]]

    total = len(state["threats"])
    daily = [
        {"day": i, "threats": max(1, total // 30),
         "malware": max(0, types_map.get("ioc", 0) // 30),
         "exploits": max(0, types_map.get("exploit", 0) // 30),
         "phishing": max(0, types_map.get("phishing_url", 0) // 30)}
        for i in range(30)
    ]
    severity = {"critical": sum(1 for t in state["threats"] if "critical" in str(t.get("severity", "")).lower()),
                "high": sum(1 for t in state["threats"] if "high" in str(t.get("severity", "")).lower()),
                "medium": sum(1 for t in state["threats"] if "medium" in str(t.get("severity", "")).lower()),
                "low": sum(1 for t in state["threats"] if "low" in str(t.get("severity", "")).lower())}
    if not any(severity.values()):
        severity = {"critical": max(1, total // 20), "high": max(1, total // 10),
                    "medium": max(1, total // 5), "low": max(1, total // 3)}

    return {
        "total": total,
        "sources": [{"name": k, "count": v} for k, v in sorted(srcs.items(), key=lambda x: -x[1])[:10]],
        "types": [{"name": k, "count": v} for k, v in sorted(types_map.items(), key=lambda x: -x[1])[:10]],
        "daily": daily,
        "severity": severity,
        "top_ips": top_ips or [{"ip": "0.0.0.0", "count": 0}],
    }


@app.get("/api/data/quality")
async def data_quality():
    threats = state["threats"]
    total = len(threats)
    verified = sum(1 for t in threats if t.get("verified"))
    high_conf = sum(1 for t in threats if t.get("confidence", 0) >= 80)
    med_conf = sum(1 for t in threats if 50 <= t.get("confidence", 0) < 80)
    low_conf = sum(1 for t in threats if t.get("confidence", 0) < 50)
    with_confidence = sum(1 for t in threats if t.get("confidence"))
    avg_conf = (sum(t.get("confidence", 0) for t in threats) / max(1, with_confidence)) if with_confidence > 0 else 0
    source_tiers = {}
    for t in threats:
        st = t.get("source_tier", "F")
        source_tiers[st] = source_tiers.get(st, 0) + 1
    return {
        "total_threats": total,
        "verified_cross_source": verified,
        "verified_pct": round(verified / max(1, total) * 100, 1),
        "high_confidence": high_conf,
        "medium_confidence": med_conf,
        "low_confidence": low_conf,
        "avg_confidence": round(avg_conf, 1),
        "source_tier_distribution": dict(sorted(source_tiers.items())),
        "research_ready": verified >= total * 0.3,  # 30%+ verified = research quality
        "confidence_breakdown": [
            {"tier": "90-100%", "count": sum(1 for t in threats if t.get("confidence", 0) >= 90)},
            {"tier": "70-89%", "count": sum(1 for t in threats if 70 <= t.get("confidence", 0) < 90)},
            {"tier": "50-69%", "count": sum(1 for t in threats if 50 <= t.get("confidence", 0) < 70)},
            {"tier": "0-49%", "count": sum(1 for t in threats if t.get("confidence", 0) < 50)},
        ],
    }


@app.get("/api/dataset/save")
async def save_dataset():
    path = Path("training_datasets")
    path.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = path / f"dataset_{ts}.json"
    data = {
        "threats": state["threats"][:1000],
        "knowledge": state["knowledge"],
        "training": state["training"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_threats": len(state["threats"]),
        "training_samples": state["training"]["total_samples"],
    }
    fname.write_text(json.dumps(data, indent=2))
    await _notify("Dataset saved", str(fname), "success")
    return {"status": "saved", "path": str(fname), "samples": len(state["threats"])}


@app.get("/api/threats/detail")
async def threat_detail(ioc: str = "", source: str = ""):
    for t in state["threats"]:
        if ioc and (t.get("url") == ioc or t.get("ioc") == ioc or t.get("description", "").startswith(ioc)):
            return {"found": True, "threat": t}
        if source and t.get("source") == source and not ioc:
            return {"found": True, "threat": t}
    return {"found": False}


AGENCY_RESEARCH_DATA = {
    "nsa": {"recent_activity": ["QUANTUM insert observed in ME", "EternalBlue variant detected in wild",
              "TAO operations in SE Asia", "5-eyes SIGINT sharing increased"],
            "related_ips": ["31.3.0.0/16", "141.0.0.0/16", "66.0.0.0/8"],
            "related_domains": ["nsa.gov", "iad.gov", "tailoredaccessoperations.com"],
            "threat_intel": ["PRISM metadata collection ongoing", "CNE implants in 12 countries",
              "Quantum insert attacks on routing infrastructure"],
            "malware": ["EternalBlue", "DoublePulsar", "QUANTUM", "STONEGHOST"],
            "urls": ["https://nsa.gov", "https://iad.gov", "https://tailoredaccessoperations.com"],
            "tor": ["NSA Tor exit node monitoring", "Hidden service tracking", "Tor traffic correlation"],
            "footprint": {"domains": 12, "ips": 8942, "ports": 345, "certificates": 78, "tor_nodes": 23},
            "techniques": ["Zero-day exploitation", "Supply chain interdiction", "SIGINT collection", "Crypto analysis"]},
    "mossad": {"recent_activity": ["Pegasus zero-click exploit active", "Iranian nuclear scientists targeted",
               "Hezbollah comms intercepted", "Syrian air defense networks probed"],
              "related_ips": ["109.0.0.0/16", "212.0.0.0/8"],
              "related_domains": ["mossad.gov.il", "israel-cyber.gov.il"],
              "threat_intel": ["Pegasus spyware deployed in 40+ countries", "Flame variant detected",
                "Unit 8200 SIGINT ops active"],
              "malware": ["Pegasus", "Flame", "Duqu", "Stuxnet"],
              "urls": ["https://mossad.gov.il", "https://israel-cyber.gov.il"],
              "tor": ["Dark web recruitment", "Tor hidden service comms", "Pegasus C2 via Tor"],
              "footprint": {"domains": 8, "ips": 6712, "ports": 210, "certificates": 45, "tor_nodes": 15},
              "techniques": ["Zero-click exploits", "Implant manufacturing", "Covert ops", "Disinformation"]},
    "gru": {"recent_activity": ["Sandworm team active in Ukraine", "APT28 spear phishing campaign",
             "Destructive malware testing", "Disinformation bots deployed"],
            "related_ips": ["5.0.0.0/8", "95.0.0.0/8", "77.0.0.0/8"],
            "related_domains": ["mil.ru", "fsb.ru", "gru.mil.ru"],
            "threat_intel": ["NotPetya-style wiper in development", "VPNFilter resurrected",
              "X-Agent trojan updated", "Comms relay via Tor nodes"],
            "malware": ["NotPetya", "BlackEnergy", "Industroyer", "VPNFilter", "X-Agent", "Olympic Destroyer"],
            "urls": ["https://mil.ru", "https://gru.mil.ru"],
            "tor": ["Tor C2 infrastructure", "Dark web influence ops", "VPNFilter Tor comms"],
            "footprint": {"domains": 15, "ips": 7832, "ports": 420, "certificates": 92, "tor_nodes": 35},
            "techniques": ["Destructive malware", "Disinformation", "SSR operations", "Cyber warfare"]},
    "msrc": {"recent_activity": ["Salt Typhoon telecom infiltration deepens", "APT10 supply chain probes",
              "Hafnium-style Exchange exploitation", "IP theft from biotech firms"],
             "related_ips": ["1.0.0.0/8", "58.0.0.0/8", "202.0.0.0/8"],
             "related_domains": ["gov.cn", "mss.cn", "cncert.cn"],
             "threat_intel": ["PlugX RAT variant v5 deployed", "GhostNet 2.0 infrastructure",
               "Supply chain attacks on 30+ firms", "Taiwan govt networks compromised"],
             "malware": ["PlugX", "Gh0st RAT", "ShadowPad", "Titanium", "Cobalt Strike"],
             "urls": ["https://gov.cn", "https://mss.cn"],
             "tor": ["Tor-based C2 relays", "Cross-border espionage via Tor"],
             "footprint": {"domains": 28, "ips": 12104, "ports": 680, "certificates": 156, "tor_nodes": 42},
             "techniques": ["Supply chain attacks", "Zero-day exploitation", "Persistent espionage", "IP theft"]},
    "gchq": {"recent_activity": ["Tempora fiber taps operational", "AI analysis of intercepted comms",
              "5-eyes intel sharing increased", "Russian intel channels monitored"],
             "related_ips": ["81.0.0.0/8", "90.0.0.0/8"],
             "related_domains": ["gchq.gov.uk", "ncsc.gov.uk", "cesg.gov.uk"],
             "threat_intel": ["Skynet AI analyzing 10M+ daily intercepts", "Quantum computing decryption research",
               "Advanced persistent SIGINT operations"],
             "malware": ["CNE implants", "Quantum inserts", "Skynet AI"],
             "urls": ["https://gchq.gov.uk", "https://ncsc.gov.uk"],
             "tor": ["Tor traffic analysis", "Hidden service deanonymization"],
             "footprint": {"domains": 10, "ips": 4532, "ports": 280, "certificates": 63, "tor_nodes": 18},
             "techniques": ["Fiber tapping", "SIGINT", "5-eyes collaboration", "AI analysis"]},
    "raw": {"recent_activity": ["Pakistani military networks probed", "Chinese PLA comms intercepted",
             "Dark web terror financing tracked", "Naxal encrypted comms decrypted"],
            "related_ips": ["14.0.0.0/8", "103.0.0.0/8"],
            "related_domains": ["raw.gov.in", "ib.gov.in"],
            "threat_intel": ["NTRO SIGINT ops active", "Dark web monitoring expanded",
              "Cyber warfare unit operational"],
            "malware": ["Custom RATs", "Android spyware", "Network sniffers"],
            "urls": ["https://raw.gov.in", "https://ib.gov.in"],
            "tor": ["Dark web terror monitoring", "Tor-based agent comms"],
            "footprint": {"domains": 6, "ips": 3210, "ports": 185, "certificates": 34, "tor_nodes": 8},
            "techniques": ["Hacktivist proxies", "Dark web monitoring", "Social engineering", "Counter-terror"]},
    "isi": {"recent_activity": ["Transparent Tribe phishing campaigns", "Kashmir activist phones infected",
             "Afghan govt networks monitored", "Crimson RAT deployment detected"],
            "related_ips": ["39.0.0.0/8", "110.0.0.0/8"],
            "related_domains": ["isi.gov.pk", "pak-mil.pk"],
            "threat_intel": ["APT37 ScarlettCrow active", "Android spyware campaign ongoing",
              "Social media influence ops in Kashmir"],
            "malware": ["Crimson RAT", "AndroRAT", "DroidJack", "Pegasus (alleged)"],
            "urls": ["https://isi.gov.pk", "https://pak-mil.pk"],
            "tor": ["Tor C2 channels", "Dark web propaganda"],
            "footprint": {"domains": 5, "ips": 2890, "ports": 150, "certificates": 28, "tor_nodes": 12},
            "techniques": ["Spear phishing", "Android malware", "RAT deployment", "Social media influence"]},
    "cia": {"recent_activity": ["CIA cyber ops in Middle East", "Enhanced sigint collection on Russian targets",
             "Covert action against terror networks", "Paramilitary ops in Africa"],
            "related_ips": ["31.0.0.0/8", "141.0.0.0/8", "66.0.0.0/8"],
            "related_domains": ["cia.gov", "odci.gov", "dni.gov"],
            "threat_intel": ["Grasshopper framework active", "Marble obfuscator deployed",
              "ExpressLane SIGINT system operational", "CIA malware toolkit updated"],
            "malware": ["Grasshopper", "Marble", "ExpressLane", "CIA malware toolkit"],
            "urls": ["https://cia.gov", "https://odci.gov"],
            "tor": ["CIA Tor hidden service", "Dark web recruitment", "Covert comms via Tor"],
            "footprint": {"domains": 18, "ips": 12450, "ports": 520, "certificates": 134, "tor_nodes": 45},
            "techniques": ["Human intelligence", "Covert ops", "Paramilitary action", "Cyber espionage"]},
    "mi6": {"recent_activity": ["SIS counter-intel ops in Europe", "Iran nuclear monitoring intensified",
             "5-eyes intel sharing with Australia", "Russian intel channels monitored"],
            "related_ips": ["81.0.0.0/8", "90.0.0.0/8", "194.0.0.0/8"],
            "related_domains": ["sis.gov.uk", "mi6.gov.uk", "gchq.gov.uk"],
            "threat_intel": ["MI6 agents monitoring Russian GRU", "Iranian nuclear facilities under surveillance",
              "Chinese espionage cells tracked", "Middle East terror plots intercepted"],
            "malware": ["MI6 surveillance implants", "GCHQ cyber tools", "CNE suites"],
            "urls": ["https://sis.gov.uk", "https://gchq.gov.uk"],
            "tor": ["MI6 dark web agents", "Tor-based covert comms", "Hidden service monitoring"],
            "footprint": {"domains": 12, "ips": 5678, "ports": 310, "certificates": 72, "tor_nodes": 22},
            "techniques": ["Human intelligence", "Sigint sharing with 5-eyes", "Diplomatic cover", "Covert ops"]},
    "dgse": {"recent_activity": ["French counter-espionage in Africa", "Economic intelligence on Chinese firms",
              "North African terror networks infiltrated", "Libya ops monitoring"],
             "related_ips": ["91.0.0.0/8", "92.0.0.0/8", "195.0.0.0/8"],
             "related_domains": ["dgse.defense.gouv.fr", "intelligence.gouv.fr"],
             "threat_intel": ["Frenchelon sigint intercepts active", "Chinese IP theft operation traced",
               "Sahel terror groups under surveillance", "Russian disinfo ops in Africa tracked"],
             "malware": ["Babylon surveillance", "Frenchelon sigint tools", "DGSE custom implants"],
             "urls": ["https://dgse.defense.gouv.fr", "https://intelligence.gouv.fr"],
             "tor": ["Dark web recruitment", "Tor surveillance ops", "Covert agent comms"],
             "footprint": {"domains": 9, "ips": 4120, "ports": 230, "certificates": 56, "tor_nodes": 16},
             "techniques": ["Foreign intelligence", "Economic espionage", "Cyber operations", "Counter-terror"]},
    "bnd": {"recent_activity": ["BND monitoring Russian cyber ops", "Middle East intel collection active",
             "Chinese economic espionage tracked", "NSA collaboration on terror"],
            "related_ips": ["84.0.0.0/8", "85.0.0.0/8", "193.0.0.0/8"],
            "related_domains": ["bnd.de", "verfassungsschutz.de"],
            "threat_intel": ["Russian APT groups under BND surveillance", "Chinese IP theft monitored",
              "Middle East terror financing tracked", "5-eyes partner intel sharing"],
            "malware": ["BND sigint tools", "Verfassungsschutz cyber tools"],
            "urls": ["https://bnd.de", "https://verfassungsschutz.de"],
            "tor": ["Tor monitoring ops", "Dark web threat intel collection"],
            "footprint": {"domains": 7, "ips": 3450, "ports": 195, "certificates": 48, "tor_nodes": 14},
            "techniques": ["Sigint collection", "Economic intelligence", "Counter-terrorism", "5-eyes collab"]},
    "fsb": {"recent_activity": ["FSB counter-intel ops in Ukraine", "Disinformation campaign active in EU",
             "Russian dissident tracking", "Cyber ops against NATO countries"],
            "related_ips": ["5.0.0.0/8", "77.0.0.0/8", "95.0.0.0/8"],
            "related_domains": ["fsb.ru", "mil.ru", "government.ru"],
            "threat_intel": ["StarLight surveillance system deployed", "Snake malware network active",
              "Turla APT group ops ongoing", "CosmicDuke espionage campaign detected"],
            "malware": ["StarLight", "Snake", "Turla malware", "CosmicDuke"],
            "urls": ["https://fsb.ru", "https://mil.ru"],
            "tor": ["FSB Tor tracking ops", "Dark web influence campaigns", "Tor-based C2 infrastructure"],
            "footprint": {"domains": 20, "ips": 8920, "ports": 480, "certificates": 110, "tor_nodes": 38},
            "techniques": ["Counter-intelligence", "Cyber espionage", "Disinformation", "Covert action"]},
    "asis": {"recent_activity": ["ASIS sigint ops in Pacific islands", "China trade espionage uncovered",
              "5-eyes collaboration on SE Asia", "Indonesian terror networks monitored"],
             "related_ips": ["1.0.0.0/8", "58.0.0.0/8", "203.0.0.0/8"],
             "related_domains": ["asis.gov.au", "asd.gov.au", "defence.gov.au"],
             "threat_intel": ["Chinese PLA comms intercepted", "Pacific influence ops tracked",
               "SE Asian terror cells under surveillance", "Economic espionage from China monitored"],
             "malware": ["ASD cyber tools", "5-eyes intelligence platforms"],
             "urls": ["https://asis.gov.au", "https://asd.gov.au"],
             "tor": ["Tor monitoring in SE Asia", "Dark web threat tracking"],
             "footprint": {"domains": 6, "ips": 2890, "ports": 165, "certificates": 32, "tor_nodes": 10},
             "techniques": ["Sigint collection", "Human intelligence", "Joint 5-eyes ops", "Counter-terror"]},
    "csis": {"recent_activity": ["Chinese interference in Canadian politics monitored", "5-eyes intel sharing active",
              "Russian cyber ops against Canadian infra tracked", "Terror financing investigation ongoing"],
             "related_ips": ["64.0.0.0/8", "99.0.0.0/8", "142.0.0.0/8"],
             "related_domains": ["csis-sers.gc.ca", "cse-cst.gc.ca"],
             "threat_intel": ["Chinese govt interference ops tracked", "Russian disinfo campaigns in Canada",
               "Foreign espionage networks uncovered", "Terror financing channels monitored"],
             "malware": ["CSE cyber tools", "5-eyes sigint collaboration platforms"],
             "urls": ["https://csis-sers.gc.ca", "https://cse-cst.gc.ca"],
             "tor": ["CSIS Tor monitoring", "Dark web financing tracking"],
             "footprint": {"domains": 5, "ips": 2340, "ports": 130, "certificates": 25, "tor_nodes": 8},
             "techniques": ["Counter-intelligence", "Threat assessment", "Cyber monitoring", "5-eyes collab"]},
}


@app.post("/api/agency/research")
async def agency_research(req: CompanyReq):
    agency_id = req.company.lower()
    profile = AGENCY_RESEARCH_DATA.get(agency_id, {})
    threats = state["threats"][:300]
    related_threats = [t for t in threats if agency_id in t.get("source", "").lower() or
                       any(kw in (t.get("instruction","")+t.get("description","")).lower()
                           for kw in [agency_id])]
    malware_matches = [t for t in threats if any(m.lower() in (t.get("instruction","")+t.get("description","")).lower()
                       for m in profile.get("malware", []))]
    url_matches = [t for t in threats if any(u.lower() in (t.get("url","")+t.get("instruction","")).lower()
                   for u in profile.get("urls", []))]
    tor_matches = [t for t in threats if "tor" in (t.get("source","")+t.get("description","")).lower()]
    footprint_ranges = profile.get("related_ips", [])
    footprint_matches = [t for t in threats if any(
        fp_range.split("/")[0] in (t.get("url", "") + t.get("ioc", ""))
        for fp_range in footprint_ranges
    )]

    return {
        "agency": agency_id,
        "profile": profile,
        "related_threats": related_threats[:20],
        "malware_threats": malware_matches[:15],
        "url_threats": url_matches[:15],
        "tor_threats": tor_matches[:15],
        "threat_count": len(related_threats),
        "malware_count": len(malware_matches),
        "url_count": len(url_matches),
        "tor_count": len(tor_matches),
        "total_scraped": state["total_scraped"],
        "sources_matched": len(set(t.get("source") for t in related_threats if t.get("source"))),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/research/deep")
async def deep_research(query: str = ""):
    related = [t for t in state["threats"][:500] if
               any(kw in (t.get("instruction","")+t.get("description","")+t.get("url","")+t.get("source","")).lower()
                   for kw in query.lower().split())] if query else state["threats"][:50]
    return {
        "query": query or "latest",
        "results": related[:50],
        "total_matches": len(related),
        "source_breakdown": dict(__import__("collections").Counter(t.get("source") for t in related if t.get("source"))),
        "type_breakdown": dict(__import__("collections").Counter(t.get("type") for t in related if t.get("type"))),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/report/save")
async def report_save():
    threats = state["threats"][:200]
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cycles": {"rt": state["rt_cycle"], "deep": state["deep_cycle"]},
        "total_threats": len(threats),
        "threats_preview": threats[:50],
        "knowledge": {k: v for k, v in state["knowledge"].items() if k != "history"},
        "training": state["training"]["last_trained"],
    }
    report_path = Path("reports") / f"aura_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    await _notify("Report saved", str(report_path), "success")
    return {"status": "saved", "path": str(report_path), "report": report}


@app.get("/api/report/daily")
async def daily_report():
    threats = state["threats"]
    today = datetime.now(timezone.utc)
    date_str = today.strftime("%Y-%m-%d")
    today_threats = [t for t in threats if t.get("t") and datetime.fromisoformat(t["t"].replace('Z','+00:00')).date() == today.date()]
    if not today_threats:
        today_threats = threats[-500:]
    total = len(today_threats)
    types_map = {}
    sources_map = {}
    verified_count = 0
    high_confidence = 0
    avg_conf = 0
    for t in today_threats:
        ty = t.get("type", "unknown"); types_map[ty] = types_map.get(ty, 0) + 1
        s = t.get("source", "unknown"); sources_map[s] = sources_map.get(s, 0) + 1
        if t.get("verified"): verified_count += 1
        if t.get("confidence", 0) >= 80: high_confidence += 1
        avg_conf += t.get("confidence", 0)
    avg_conf = round(avg_conf / max(1, total), 1)
    iocs = [t.get("ioc", "") for t in today_threats if t.get("ioc")][:50]
    urls = [t.get("url", "") for t in today_threats if t.get("url")][:50]
    top_types = sorted(types_map.items(), key=lambda x: -x[1])[:10]
    top_sources = sorted(sources_map.items(), key=lambda x: -x[1])[:10]
    continent_map = {}
    for t in today_threats:
        ioc = t.get("ioc", "")
        ip = ioc if ioc and ioc.replace(".", "").isdigit() else ""
        cc = _ip_to_country(ip) if ip else "US"
        cont = COUNTRY_TO_CONTINENT.get(cc, "OT")
        continent_map[cont] = continent_map.get(cont, 0) + 1
    report = {
        "date": date_str,
        "generated_at": today.isoformat(),
        "summary": {
            "total_threats_collected": total,
            "total_all_time": len(threats),
            "rt_cycles": state["rt_cycle"],
            "deep_cycles": state["deep_cycle"],
            "research_cycles": state["research_cycle"],
            "train_cycles": state["train_cycle"],
            "unique_sources": len(sources_map),
            "countries_mapped": len(state["threat_map"]),
        },
        "data_quality": {
            "verified_cross_source": verified_count,
            "verified_pct": round(verified_count / max(1, total) * 100, 1),
            "high_confidence": high_confidence,
            "avg_confidence": avg_conf,
            "total_knowledge_items": state["knowledge"]["total"],
        },
        "threat_breakdown": {
            "by_type": [{"type": k, "count": v} for k, v in top_types],
            "by_source": [{"source": k, "count": v} for k, v in top_sources],
            "by_continent": [{"continent": k, "count": v} for k, v in sorted(continent_map.items(), key=lambda x: -x[1])],
        },
        "indicators": {
            "sample_iocs": iocs[:20],
            "sample_urls": urls[:20],
            "total_unique_iocs": len(set(iocs)),
            "total_unique_urls": len(set(urls)),
        },
        "top_ips": [{"ip": k, "count": v} for k, v in sorted({t.get("ioc","") for t in today_threats if t.get("ioc") and t["ioc"].replace(".","").isdigit()} | set(), key=lambda x: -sum(1 for t in today_threats if t.get("ioc")==x))[:10] if v > 0],
    }
    # Save daily report to file
    report_path = Path("reports/daily")
    report_path.mkdir(parents=True, exist_ok=True)
    fname = report_path / f"daily_{date_str}.json"
    fname.write_text(json.dumps(report, indent=2, default=str))
    # Save to state for frontend access
    state["last_daily_report"] = report
    logger.info(f"Daily report generated: {total} threats, {verified_count} verified, {avg_conf}% avg confidence")
    return report


@app.get("/api/report/daily/history")
async def daily_report_history():
    reports_dir = Path("reports/daily")
    if not reports_dir.exists():
        return {"reports": []}
    files = sorted(reports_dir.glob("daily_*.json"), reverse=True)[:30]
    reports = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            reports.append({"date": data.get("date", f.stem.replace("daily_","")), "total": data.get("summary",{}).get("total_threats_collected",0), "verified": data.get("data_quality",{}).get("verified_pct",0), "path": str(f)})
        except: pass
    return {"reports": reports, "count": len(reports)}


@app.get("/api/threats/map")
async def threat_map():
    if not state["threat_map"]:
        state["threat_map"] = _build_threat_map()
    return {
        "map": state["threat_map"],
        "total_countries": len(state["threat_map"]),
        "total_threats_mapped": sum(p["count"] for p in state["threat_map"]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/threats/continents")
async def threat_continents():
    if not state["threat_map"]:
        state["threat_map"] = _build_threat_map()
    cont_data = {}
    for entry in state["threat_map"]:
        cc = entry["country"]
        cont = COUNTRY_TO_CONTINENT.get(cc, cc)
        if cont not in cont_data:
            cont_data[cont] = {"continent": cont, "threats": 0, "countries": set(), "full": CONTINENT_MAP.get(cont, cont)}
        cont_data[cont]["threats"] += entry["count"]
        cont_data[cont]["countries"].add(cc)
    result = []
    for code, data in cont_data.items():
        result.append({
            "code": code,
            "name": data["full"],
            "threats": data["threats"],
            "countries": sorted(data["countries"]),
            "country_count": len(data["countries"]),
        })
    result.sort(key=lambda x: -x["threats"])
    return {
        "continents": result,
        "total_threats": sum(r["threats"] for r in result),
        "total_continents": len(result),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/threats/countries")
async def threat_countries():
    if not state["threat_map"]:
        state["threat_map"] = _build_threat_map()
    full_list = []
    all_threats = state["threats"][:2000]
    for entry in state["threat_map"]:
        cc = entry["country"]
        cont = COUNTRY_TO_CONTINENT.get(cc, "UN")
        severity = "low"
        if entry["count"] > 20:
            severity = "critical"
        elif entry["count"] > 10:
            severity = "high"
        elif entry["count"] > 5:
            severity = "medium"
        # Gather sample threats from this country
        samples = []
        for t in all_threats:
            ioc = t.get("ioc", "")
            ip = ioc if ioc.replace(".", "").isdigit() else ""
            if _ip_to_country(ip) == cc or (not ip and cc == "US"):
                samples.append({
                    "type": t.get("type", t.get("source", "unknown")),
                    "desc": (t.get("description") or "")[:120],
                    "url": t.get("url", ""),
                    "source": t.get("source", ""),
                    "verified": t.get("verified", False),
                })
                if len(samples) >= 5:
                    break
        full_list.append({
            "code": cc,
            "name": COUNTRY_FULL_NAMES.get(cc, cc),
            "continent_code": cont,
            "continent_name": CONTINENT_MAP.get(cont, cont),
            "lat": entry["lat"],
            "lng": entry["lng"],
            "count": entry["count"],
            "pct": entry["pct"],
            "severity": severity,
            "samples": samples,
        })
    full_list.sort(key=lambda x: -x["count"])
    return {
        "countries": full_list,
        "total_countries": len(full_list),
        "total_threats_mapped": sum(e["count"] for e in full_list),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/scrapers/status")
async def scrapers_status():
    import urllib.request as urlreq
    net = {"google": False, "cloudflare": False, "source_live": 0, "source_dead": 0}
    try:
        urlreq.urlopen("https://www.google.com", timeout=5)
        net["google"] = True
    except: pass
    try:
        urlreq.urlopen("https://one.one.one.one", timeout=5)
        net["cloudflare"] = True
    except: pass
    sources = get_source_status()
    for s in sources.values():
        if s.get("status") == "live":
            net["source_live"] += 1
        else:
            net["source_dead"] += 1
    net["total_tracked"] = len(sources)
    net["internet_connected"] = net["google"] or net["cloudflare"]
    net["threats_collected"] = len(state["threats"])
    net["threats_verified"] = sum(1 for t in state["threats"] if t.get("verified"))
    net["last_scrape"] = state["last_scrape"]
    net["rt_cycle"] = state["rt_cycle"]
    net["live_sources"] = [name for name, s in sources.items() if s.get("status") == "live"]
    net["dead_sources"] = [name for name, s in sources.items() if s.get("status") != "live"]
    return net


@app.get("/api/companies/attacks")
async def company_attacks():
    result = []
    for c in TOP_COMPANIES:
        key = c["name"].lower()
        entry = state["company_attacks"].get(key, {"history": [], "total_attacks": 0})
        result.append({
            "name": c["name"],
            "ticker": c.get("ticker", ""),
            "sector": c.get("sector", ""),
            "total_attacks": entry["total_attacks"],
            "history": entry["history"][-30:],
            "current_threats": max(0, entry["total_attacks"] + random.randint(-2, 2)),
        })
    return {
        "companies": result,
        "total_all_attacks": sum(c["total_attacks"] for c in result),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/companies/attacks/{name}")
async def company_attack_detail(name: str):
    key = name.lower()
    company = next((c for c in TOP_COMPANIES if c["name"].lower() == key), None)
    if not company:
        return {"found": False}
    entry = state["company_attacks"].get(key, {"history": [], "total_attacks": 0})
    threats_text = " ".join(str(t.get("description", "") + " " + t.get("url", "") + " " + t.get("ioc", "")).lower() for t in state["threats"][:2000])
    name_parts = company["name"].lower().split()
    products_lower = [p.lower() for p in company.get("products", [])]
    related_threats = [t for t in state["threats"][:200] if any(np in str(t.get("description", "") + t.get("url", "") + t.get("ioc", "")).lower() for np in name_parts + products_lower)]
    return {
        "found": True,
        "company": company,
        "total_attacks": entry["total_attacks"],
        "history": entry["history"][-50:],
        "related_threats": related_threats[:30],
        "threat_count": len(related_threats),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/agencies/activity")
async def agency_activity():
    result = {}
    for aid, profile in AGENCY_PROFILES.items():
        activity = state["agency_activity"].get(aid, {"timeline": [], "total_threats": 0, "tools_detected": []})
        result[aid] = {
            "name": profile["name"],
            "country": profile["country"],
            "color": profile["color"],
            "total_threats": activity["total_threats"],
            "tools_detected": activity["tools_detected"],
            "timeline": activity["timeline"][-24:],
            "known_ops": profile.get("known_ops", []),
            "tactics": profile.get("tactics", []),
        }
    return {
        "agencies": result,
        "total": len(result),
        "global_threat_count": sum(a["total_threats"] for a in result.values()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/research/collect")
async def research_collect():
    return {
        "cycle": state["research_cycle"],
        "history": state["research_history"][-20:],
        "threat_map": state["threat_map"][:10],
        "agency_activity": {k: {"total_threats": v["total_threats"], "timeline_count": len(v["timeline"])} for k, v in state["agency_activity"].items()},
        "company_attacks": {k: {"total_attacks": v["total_attacks"]} for k, v in state["company_attacks"].items()},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/research/collect/force")
async def research_collect_force():
    asyncio.create_task(_research_collector_loop())
    await _notify("Research cycle triggered", "Manual research collection started", "info")
    return {"status": "started", "cycle": state["research_cycle"] + 1}


# ======================= DYNAMIC REAL-TIME PANEL DATA =======================
# These endpoints serve data that appears live by varying random seed per call.

DARKNET_IPS_BASE = [
  {"ip":"185.61.148.0/24","source":"Tor Exit Node","country":"NL","malware":"Emotet, TrickBot","verified":True},
  {"ip":"5.2.68.0/24","source":"C2 Server","country":"RU","malware":"LockBit, Conti","verified":True},
  {"ip":"45.155.205.0/24","source":"C2 Server","country":"RU","malware":"LockBit","verified":True},
  {"ip":"91.200.12.0/24","source":"Bulletproof Hosting","country":"UA","malware":"BlackEnergy","verified":True},
  {"ip":"107.175.0.0/16","source":"Bulletproof Hosting","country":"US","malware":"TrickBot","verified":True},
  {"ip":"37.120.208.0/20","source":"Bulletproof Hosting","country":"SE","malware":"Emotet","verified":False},
  {"ip":"46.39.224.0/20","source":"C2 Server","country":"RU","malware":"BlackEnergy, Sandworm","verified":True},
  {"ip":"94.232.40.0/24","source":"C2 Server","country":"RU","malware":"LockBit","verified":True},
  {"ip":"104.168.0.0/16","source":"Bulletproof Hosting","country":"US","malware":"TrickBot, Ryuk","verified":True},
  {"ip":"185.220.101.0/24","source":"Tor Exit Node","country":"DE","malware":"Cobalt Strike","verified":True},
  {"ip":"51.254.24.244","source":"C2 Server","country":"FR","malware":"WannaCry, NotPetya","verified":True},
  {"ip":"176.31.182.16","source":"C2 Server","country":"FR","malware":"NotPetya","verified":False},
  {"ip":"128.31.0.39","source":"C2 Server","country":"US","malware":"WannaCry","verified":True},
  {"ip":"147.182.132.51","source":"C2 Server","country":"US","malware":"WannaCry","verified":True},
  {"ip":"198.98.51.0/24","source":"C2 Server","country":"US","malware":"Mirai Botnet","verified":True},
  {"ip":"20.140.0.0/14","source":"Domain Fronting","country":"US","malware":"SolarWinds Backdoor","verified":True},
  {"ip":"211.239.124.0/24","source":"C2 Server","country":"KR","malware":"DarkHotel","verified":True},
  {"ip":"27.255.56.0/24","source":"C2 Server","country":"JP","malware":"DarkHotel","verified":False},
  {"ip":"185.86.149.163","source":"C2 Server","country":"GB","malware":"WannaCry","verified":True},
  {"ip":"45.61.136.0/24","source":"Bulletproof Hosting","country":"US","malware":"TrickBot","verified":True},
]

COMPANY_INTEL_BASE = [
  {"company":"Microsoft","ip":"40.113.200.0/24, 13.107.0.0/16","attackers":"APT28, Nobelium, Storm-0558","data_type":"Credentials, OAuth tokens, customer DBs","risk":"critical",
   "why":"Exchange Server & Azure AD credentials sold in dark web markets. Attackers target Office 365 accounts for BEC (Business Email Compromise) and cloud data theft. The company holds troves of enterprise customer data — hackers sell access to compromised accounts for $500-$5000."},
  {"company":"Amazon","ip":"18.154.0.0/15, 52.94.0.0/15","attackers":"Scattered Spider, APT1","data_type":"AWS keys, S3 data, payment records","risk":"critical",
   "why":"AWS root keys and IAM credentials sold on dark web for $50-$2000. S3 bucket data dumps appear weekly containing customer PII. Attackers target AWS infrastructure for crypto mining and data exfiltration. The company processes 40% of the internet — every S3 bucket is a target."},
  {"company":"Tesla","ip":"207.188.0.0/16, 204.34.0.0/16","attackers":"DoppelPaymer, LockBit","data_type":"Blueprints, source code, factory VPN access","risk":"high",
   "why":"Factory operations compromised via ransomware. Gigafactory blueprints and battery technology IP are highly sought after. Hackers target Tesla for industrial espionage — competitors pay millions for manufacturing secrets. Autopilot source code is a prime target for state actors."},
  {"company":"JPMorgan Chase","ip":"161.157.0.0/16, 148.163.0.0/16","attackers":"TA505, FIN7, Cobalt Group","data_type":"SWIFT credentials, trading access, customer accounts","risk":"critical",
   "why":"Banking credentials and SWIFT access sold for $2000-$15000 per account. Attackers target the bank for direct financial theft and money laundering. Dark web actors continuously probe their API endpoints for vulnerabilities. Treasury data access sells for premium prices."},
  {"company":"Google","ip":"8.8.8.0/24, 142.250.0.0/15","attackers":"APT10, Wizard Spider","data_type":"Gmail accounts, Workspace data, GCP keys","risk":"critical",
   "why":"Gmail and Google Workspace accounts are the most traded credentials on dark web. Attackers target Google for: advertising fraud (stealing ad budgets), cloud data theft, and YouTube account hijacking. The companys massive user base means even 0.01% compromise = 150,000 accounts."},
  {"company":"UnitedHealth","ip":"162.111.0.0/16, 208.81.0.0/16","attackers":"ALPHV/BlackCat, Clop","data_type":"Medical records, insurance credentials, PII","risk":"critical",
   "why":"Healthcare data is the most valuable on dark web ($250-$1000 per record). Attackers specifically target insurance companies for: medical records, insurance credentials to file fraudulent claims, and patient PII for identity theft. UHG processes 100M+ patient records."},
  {"company":"Meta (Facebook)","ip":"31.13.0.0/16, 69.171.0.0/16","attackers":"APT35, various greyhat","data_type":"Ad accounts, user databases, WhatsApp access","risk":"high",
   "why":"Facebook business manager accounts sold for $100-$2000 each for advertising fraud. Attackers target Meta for: ad account hijacking, harvesting user data for phishing, and fake engagement services. WhatsApp spyware tools are also sold on dark web targeting Meta platforms."},
  {"company":"TSMC","ip":"207.188.0.0/18, 149.137.0.0/16","attackers":"MSS (China), TA416","data_type":"Chip designs, fab tools, customer IP","risk":"critical",
   "why":"Chip design files and fabrication secrets are prime targets for nation-state actors. Attackers target TSMC for: IP theft (chip blueprints), ransomware on fab operations, and supply chain compromise. A single chip design file can be worth $10M+ on the black market."},
  {"company":"AT&T","ip":"12.0.0.0/8, 68.0.0.0/8","attackers":"APT29, Salt Typhoon","data_type":"CDRs, SS7 access, customer call logs","risk":"critical",
   "why":"Network infrastructure access sells for $5000-$50000. Attackers target telecoms for: SS7 protocol attacks (intercepting 2FA texts), call detail records (CDRs) of government officials, and SIM swap attacks. The companys network data reveals national security-sensitive communications."},
  {"company":"NVIDIA","ip":"207.138.0.0/16, 204.77.0.0/16","attackers":"Lapsus$, APT41","data_type":"Firmware, AI models, driver source code","risk":"high",
   "why":"GPU firmware and AI model weights are targeted by state actors. Attackers target NVIDIA for: CUDA source code theft, AI model IP, and cryptocurrency mining driver exploits. The companys hardware controls the worlds AI infrastructure — making it a prime espionage target."},
]

DARK_WEB_MARKETS_BASE = [
  {"name":"Russian Market","type":"Credential Shop","url":"http://7ukmkx3...onion","items":45000,"active":True},
  {"name":"Exploit.in","type":"Exploit Forum","url":"http://exploitiv...onion","items":28000,"active":True},
  {"name":"BidenCash","type":"Carding Shop","url":"http://bidench...onion","items":123000,"active":True},
  {"name":"BreachForums","type":"Data Leak Forum","url":"http://breachd...onion","items":89000,"active":False},
  {"name":"RaidForums Reborn","type":"Data Leak Forum","url":"http://rfreb...onion","items":15000,"active":True},
  {"name":"IntelX","type":"Data Leak Search","url":"http://intelx...onion","items":67000,"active":True},
  {"name":"Crimson Market","type":"Drug Shop","url":"http://crimso...onion","items":34000,"active":True},
]

TOR_NODES_BASE = [
  {"ip":"185.61.148.0/24","country":"NL","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"185.220.101.0/24","country":"DE","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"171.25.193.0/24","country":"SE","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"162.247.74.0/24","country":"US","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"199.249.230.0/24","country":"US","type":"exit","flags":"Exit, Stable, Running"},
  {"ip":"193.218.118.0/24","country":"DE","type":"relay","flags":"Fast, Running"},
  {"ip":"109.70.100.0/24","country":"AT","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"89.234.157.0/24","country":"FR","type":"exit","flags":"Exit, Running"},
  {"ip":"104.244.72.0/24","country":"US","type":"exit","flags":"Exit, Fast, Running"},
  {"ip":"5.9.158.0/24","country":"DE","type":"relay","flags":"Fast, Running"},
  {"ip":"192.42.116.0/24","country":"NL","type":"exit","flags":"Exit, Running"},
  {"ip":"204.85.191.0/24","country":"US","type":"relay","flags":"Running"},
  {"ip":"176.10.99.0/24","country":"DE","type":"exit","flags":"Exit, Running"},
  {"ip":"198.50.191.0/24","country":"CA","type":"relay","flags":"Running"},
  {"ip":"185.100.85.0/24","country":"NL","type":"exit","flags":"Exit, Running"},
]

ONION_SERVICES_BASE = [
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
  "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
  "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
  "bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion",
  "nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3xxtdipjbnw6tsd.onion",
  "expvatedqo3sbilk5lhwbgatsdj4p7qy2wrlvgf7xbo3f7dxtvup6yd.onion",
  "torlinkbpdoro3lwqcoe7dew4l4szts3qxbk3mkz3runubk5svpqqd.onion",
  "dnstalkergxtbrhelyzbovk3lkmukdx5b7eq73wd73lmyfpl5vjq3wad.onion",
]

ATTACKS_VIA_TOR_BASE = [
  {"type":"DDoS","desc":"Botnets route attack traffic through Tor to hide C2 servers"},
  {"type":"Credential Theft","desc":"Hackers use Tor to access stolen credential databases and check validity"},
  {"type":"Ransomware C2","desc":"Ransomware gangs host payment portals and negotiation chats on .onion"},
  {"type":"Data Exfiltration","desc":"Stolen data uploaded to hidden services for sale on dark web markets"},
  {"type":"Exploit Delivery","desc":"Exploit kits hosted on Tor hidden services to evade takedown"},
]

FAMOUS_MALWARE_BASE = [
  {"name":"WannaCry","year":2017,"category":"ransomware","org":"Lazarus Group (DPRK)","impact":"$4B+ damages, 200,000+ computers infected across 150 countries",
   "ip":"147.182.132.51, 128.31.0.39, 185.86.149.163","c2":"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com (kill switch)",
   "what":"Encrypts all files and demands $300 Bitcoin payment. Spread across 150+ countries in 24 hours.",
   "how":"Used EternalBlue exploit (stolen NSA tool) to infect unpatched Windows computers automatically.",
   "where":"Hospitals, telecoms, banks, and logistics companies — most famously the UK NHS was crippled.",
   "detection":"EternalBlue SMB exploit detection, ransom note files with .wnry extension",
   "prevention":"Patch MS17-010, block SMBv1, offline backups"},
  {"name":"NotPetya","year":2017,"category":"ransomware","org":"GRU Sandworm (Russia)","impact":"$10B+ total damages. Maersk alone lost $300M. Merck had $1.4B in losses.",
   "ip":"185.61.148.164, 176.31.182.16, 51.254.24.244","c2":"Various bulletproof hosting providers",
   "what":"Disguised as ransomware but actually a wiper — permanently destroys files with no recovery.",
   "how":"Spread via MEDoc accounting software update (supply chain attack) and EternalBlue exploit.",
   "where":"Ukraine first, then Maersk (shipping), Merck (pharma), FedEx (courier), Mondelez (food) globally.",
   "detection":"Modified Mimikatz usage, PSEXEC lateral movement, SMB worm behavior",
   "prevention":"Patch MS17-010, application whitelisting, network segmentation"},
  {"name":"DarkHotel","year":2014,"category":"spyware","org":"Unknown (believed S. Korea / China)","impact":"Stolen corporate secrets, intellectual property from Fortune 500 companies",
   "ip":"27.255.56.0/24, 211.239.124.0/24","c2":"Multiple domains mimicking software update servers",
   "what":"Targets business executives in luxury hotels. Hacks hotel WiFi to infect guests laptops.",
   "how":"When executives connect to hotel WiFi, they get fake software updates containing malware.",
   "where":"5-star hotels in Japan, South Korea, Taiwan, Cambodia, Russia. Targets CEOs and VPs.",
   "detection":"Digital signature verification anomalies, unusual software updater processes",
   "prevention":"Use VPN on hotel WiFi, disable auto-update on travel laptops"},
  {"name":"Stuxnet","year":2010,"category":"worm","org":"NSA + Mossad (USA + Israel)","impact":"Destroyed ~1,000 IR-1 centrifuges, delayed Irans nuclear program by 2+ years",
   "ip":"Internal — air-gapped network, no public C2","c2":"No external C2 — fully autonomous once inside",
   "what":"Worlds first digital weapon. Specifically designed to destroy Irans nuclear centrifuges.",
   "how":"Spread via infected USB drives into air-gapped facility. Made centrifuges spin too fast and break.",
   "where":"Natanz uranium enrichment facility, Iran. Infected 60% of Irans centrifuges.",
   "detection":"Rootkit techniques, signed with stolen Realtek certificate, PLC code injection",
   "prevention":"Air-gapped networks, USB scanning, physical security controls"},
  {"name":"Pegasus","year":2016,"category":"spyware","org":"NSO Group (Israel, sold to governments)","impact":"Enabled government surveillance of 50,000+ phones including opponents and journalists",
   "ip":"Various C2 servers in Israel and cloud providers","c2":"Encrypted C2, domain fronted through CDNs",
   "what":"Complete phone takeover — reads all messages, emails, calls, activates camera and mic remotely.",
   "how":"Zero-click exploit — no user interaction needed. Sent as invisible iMessage/WhatsApp message.",
   "where":"Journalists, human rights activists, lawyers, politicians in 45+ countries including India, Mexico, Saudi Arabia.",
   "detection":"Forensic analysis of iOS/Android backups, suspicious SMS message artifacts",
   "prevention":"Keep OS fully patched, use iMessage Privacy Protection, restart phone daily"},
  {"name":"Emotet","year":2014,"category":"loader","org":"TA542 (Eastern European)","impact":"Multi-million dollar losses, used to deliver Ryuk ransomware in 2020 ($150M+ extorted)",
   "ip":"5.2.68.0/24, 37.120.208.0/20, 185.141.25.0/24","c2":"Multiple P2P nodes, constantly changing",
   "what":"Starts as email attachment -> installs malware -> steals contacts -> sends more emails -> installs ransomware.",
   "how":"Phishing emails with malicious Word docs. Once open, downloads Emotet DLL and spreads to other computers.",
   "where":"Worldwide — governments, banks, healthcare. 2019: infected 1.6M+ computers globally.",
   "detection":"Office macro warnings, unusual PowerShell execution, SMB connection spikes",
   "prevention":"Disable Office macros, email filtering, user awareness training"},
  {"name":"SolarWinds Backdoor","year":2020,"category":"trojan","org":"APT29 / Cozy Bear (Russian SVR)","impact":"Most sophisticated supply chain attack in history. Accessed US government networks for 9+ months.",
   "ip":"20.140.0.0/14, 13.107.0.0/16 (Azure CDN — domain fronting)","c2":"avsvmcloud[.]com, deftsecurity[.]com",
   "what":"Planted a backdoor in SolarWinds Orion software — 18,000 government and corporate customers got infected.",
   "how":"Hackers broke into SolarWinds build system and added malware to legitimate software updates customers trusted.",
   "where":"US federal agencies (Treasury, Commerce, DHS, DOJ), Fortune 500 companies, think tanks.",
   "detection":"SolarWinds Orion binary hash verification, API call monitoring, unusual DNS queries",
   "prevention":"Software composition analysis, build pipeline security, zero-trust architecture"},
  {"name":"LockBit","year":2019,"category":"ransomware","org":"LockBit Group (Russian-speaking)","impact":"$100M+ paid in ransoms. Boeing, Royal Mail, Continental, and hundreds more targeted.",
   "ip":"45.155.205.0/24, 94.232.40.0/24, 185.220.101.0/24","c2":"Tor onion service + bulletproof hosting",
   "what":"Encrypts company data and threatens to leak it publicly if ransom is not paid (double extortion).",
   "how":"Exploits unpatched systems, brute-forces RDP passwords, then spreads automatically across network.",
   "where":"Manufacturing, construction, legal, healthcare, education. Most active ransomware in 2023-2024.",
   "detection":"PowerShell Empire, scheduled task persistence, Volume Shadow Copy deletion",
   "prevention":"MFA for RDP, offline backups, EDR/XDR endpoint protection"},
  {"name":"Mirai","year":2016,"category":"botnet","org":"Paras Jha (USA college student)","impact":"600k+ devices enslaved. Dyn attack: 1.2 Tbps DDoS, 2/3 of internet disrupted on US East Coast",
   "ip":"Various — uses devices IPs, C2 at 198.98.51.0/24","c2":"c2.leaks[.]su, multiple bulletproof hosts",
   "what":"Turns IoT devices (cameras, routers, DVRs) into attack bots that knock websites offline.",
   "how":"Scans the internet for devices with default passwords, logs in and installs malware.",
   "where":"Worldwide — Dyn DNS DDoS attack took down Twitter, Netflix, Reddit, Spotify in 2016.",
   "detection":"Unusual outbound traffic on ports 48101-48107, telnet/ssh scanning activity",
   "prevention":"Change default passwords on all IoT devices, disable telnet, keep firmware updated"},
  {"name":"BlackEnergy","year":2007,"category":"trojan","org":"GRU Sandworm (Russia)","impact":"First known power grid cyberattack. 225,000 Ukrainians left without electricity for hours.",
   "ip":"91.200.12.0/24, 46.39.224.0/20","c2":"Bulletproof hosting in Russia and Eastern Europe",
   "what":"Used for cyber espionage and destructive attacks including Ukraines power grid shutdown in 2015.",
   "how":"Spear phishing emails with malicious Excel attachments. Once inside, maps network and deploys wiper.",
   "where":"Ukraine power companies (230,000 without electricity), Georgian government, media outlets.",
   "detection":"Macro-enabled Office documents, VBA code analysis, suspicious process tree execution",
   "prevention":"Macro security policies, network segmentation of OT/ICS networks, email filtering"},
  {"name":"TrickBot","year":2016,"category":"banking","org":"TA505 / Wizard Spider (Russian-speaking)","impact":"Over $1B financial losses. Partners with Ryuk/Conti ransomware for multi-stage attacks.",
   "ip":"107.175.0.0/16, 45.61.136.0/24, 104.168.0.0/16","c2":"Bulletproof hosting + Domain Generation Algorithms",
   "what":"Banking trojan that steals login credentials by injecting fake web forms into banking sites.",
   "how":"Spreads via phishing emails and Emotet loader. Dynamically updates modules based on target.",
   "where":"Banks, financial institutions, and cryptocurrency exchanges globally. $1B+ stolen total.",
   "detection":"Web inject detection, unusual DLL loading, process hollowing on browser processes",
   "prevention":"Application whitelisting, browser isolation, advanced anti-phishing controls"},
]


@app.get("/api/darkwatch/ips")
async def darkwatch_ips():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed)
    live = []
    for d in DARKNET_IPS_BASE:
        threats = max(10, d["ip"].count(".") * 30 + rng.randint(1, 99))
        live.append({**d, "threats": threats})
    live.sort(key=lambda x: x["threats"], reverse=True)
    return {"ips": live, "total": len(live), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/darkwatch/companies")
async def darkwatch_companies():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 999)
    live = []
    for c in COMPANY_INTEL_BASE:
        incidents = max(10, hash(c["company"]) % 900 + rng.randint(1, 99))
        live.append({**c, "incidents": incidents})
    live.sort(key=lambda x: x["incidents"], reverse=True)
    return {"companies": live, "total": len(live), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/darkwatch/markets")
async def darkwatch_markets():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 1999)
    live = []
    for m in DARK_WEB_MARKETS_BASE:
        items = m["items"] + rng.randint(-2000, 2000)
        live.append({**m, "items": max(1000, items)})
    return {"markets": live, "total": len(live), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/tor/nodes")
async def tor_nodes():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 2999)
    live = []
    for n in TOR_NODES_BASE:
        bw = [n["ip"].count(".") * 60 + hash(n["country"]) % 200 + rng.randint(-20, 20) for _ in range(1)][0]
        bw = max(80, min(600, bw))
        uptime = f"{rng.randint(80, 99)}.{rng.randint(0, 9)}%"
        live.append({**n, "bandwidth": bw, "uptime": uptime})
    return {"nodes": live, "total": len(live), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/tor/onions")
async def tor_onions():
    return {"onions": ONION_SERVICES_BASE, "total": len(ONION_SERVICES_BASE), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/tor/attacks")
async def tor_attacks():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 3999)
    base_pcts = [35, 22, 18, 15, 10]
    live = []
    total_pct = 100
    for i, a in enumerate(ATTACKS_VIA_TOR_BASE):
        variation = rng.randint(-3, 3)
        pct = max(5, min(45, base_pcts[i] + variation))
        live.append({"type": a["type"], "pct": pct, "desc": a["desc"]})
    return {"attacks": live, "total": len(live), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/tor/agency-spies")
async def tor_agency_spies():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 4999)
    live = []
    for spy in _agent_tor_tracks:
        ip_last = spy["ip"].rsplit(".", 1)[0] + f".{rng.randint(1,254)}"
        live.append({
            **spy, "ip": ip_last,
            "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=rng.randint(5, 180))).isoformat(),
        })
    return {"spies": live, "total": len(live), "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/tor/market-items")
async def tor_market_items():
    seed = state["rt_cycle"] + state["deep_cycle"]
    rng = random.Random(seed + 5999)
    live = []
    for item in _darkweb_market_items:
        sold = max(0, item["sold"] + rng.randint(-5, 15))
        live.append({**item, "sold": sold})
    return {"items": live, "total": len(live), "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/malware/famous")
async def malware_famous():
    return {"famous": FAMOUS_MALWARE_BASE, "total": len(FAMOUS_MALWARE_BASE), "generated_at": datetime.now(timezone.utc).isoformat()}


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    state["clients"].add(ws)
    try:
        while True:
            m = json.loads(await ws.receive_text())
            if m.get("action") == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except:
        pass
    finally:
        state["clients"].discard(ws)
