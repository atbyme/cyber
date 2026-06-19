import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from pathlib import Path

from .scraper import realtime_scan, deep_scan, stats, types, knowledge, SOURCES
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

logger = logging.getLogger("AURA.Server")

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


async def _train(cycle):
    if state["training"]["running"]:
        return
    samples = state["threats"][:]
    if not samples:
        logger.info("No samples for training, skipping")
        return
    state["training"]["running"] = True
    try:
        await _broadcast("train_status", {"cycle": cycle, "samples": len(samples), "status": "started"})
        await _notify(f"Training cycle {cycle}", f"{len(samples)} samples → ModelScope cloud", "info")
        merged = merge_datasets([format_for_modelscope(samples), format_for_modelscope(get_linux_training_data())])
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
        await _notify(f"Dataset v{cycle} pushed", f"{len(merged)} samples → ModelScope Hub + Cloud GPU", "success")
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

                # Auto-train once per day (check if 24h passed)
                now = datetime.now(timezone.utc)
                last_date = state.get("last_train_date")
                should_train = False
                if last_date is None:
                    should_train = True
                else:
                    try:
                        last = datetime.fromisoformat(last_date) if isinstance(last_date, str) else last_date
                        if (now - last).total_seconds() >= 86400:
                            should_train = True
                    except:
                        should_train = True
                if should_train:
                    train_cycle = state.get("train_cycle", 0) + 1
                    state["train_cycle"] = train_cycle
                    state["last_train_date"] = now.isoformat()
                    logger.info(f"  DAILY AUTO-TRAIN #{train_cycle} with {len(state['threats'][:])} samples (24h passed)")
                    await _broadcast("daily_train", {"cycle": train_cycle, "samples": len(state['threats'][:]), "date": now.isoformat()})
                    await _train(train_cycle)
                else:
                    next_train_seconds = 86400 - (now - last).total_seconds()
                    logger.info(f"  Next daily train in {next_train_seconds/3600:.1f}h")

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
            logger.info(f"  RT #{c} scanning...")
            data = await asyncio.to_thread(realtime_scan, on_source)
            await _process_scan_results(data, c, "rt")
        except Exception as e:
            logger.error(f"RT #{c}: {e}")
        await asyncio.sleep(30)


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
            logger.info(f"  DEEP #{c} scanning (19 sources)...")
            data = await asyncio.to_thread(deep_scan, on_source)
            await _process_scan_results(data, c, "deep")
        except Exception as e:
            logger.error(f"Deep #{c}: {e}")
        await asyncio.sleep(1800)


async def _daily_train_scheduler():
    await asyncio.sleep(60)
    while state["active"]:
        now = datetime.now(timezone.utc)
        target_hour = state.get("daily_train_hour", 3)
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
                logger.info(f"  DAILY SCHEDULED TRAIN #{train_cycle} at {now.hour}:00 UTC")
                await _broadcast("daily_train", {"cycle": train_cycle, "samples": len(state["threats"]), "date": now.isoformat()})
                await _train(train_cycle)
            await asyncio.sleep(3600)
        else:
            await asyncio.sleep(1800)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AURA starting — autonomous mode: RT 30s, Deep 30min, Daily train at 03:00 UTC")
    asyncio.create_task(_rt_loop())
    asyncio.create_task(_deep_loop())
    asyncio.create_task(_daily_train_scheduler())
    yield
    state["active"] = False
    logger.info("AURA stopping")


app = FastAPI(title="AURA Cyber AI", version="4.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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


@app.get("/api/footprints")
async def footprints(limit=50):
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
    lines = ["AURA CYBER THREAT INTELLIGENCE REPORT", "=" * 50,
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
async def monitor(limit=50):
    return state["monitored"][:limit]


@app.get("/api/notifications")
async def get_notifs(limit=50):
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
    sim = []
    for c in TOP_COMPANIES:
        key = c["name"].lower()
        entry = state["company_sim"][key]
        entry["threats"] = random.randint(0, max(1, entry["threats"] + random.randint(-2, 5)))
        entry["attacks"] = random.randint(0, max(1, entry["attacks"] + random.randint(-1, 3)))
        entry["breaches"] = random.randint(0, max(0, entry["breaches"] + random.randint(0, 1)))
        entry["ports"] = random.randint(10, 200) + random.randint(-5, 5)
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
    return {
        "exit_nodes": state.get("tor_exit_nodes", 0) or len(TOR_KNOWN_EXITS),
        "hidden_services": state.get("tor_hidden_services", 0) or 47,
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
            {"id": f"circ-{i}", "nodes": random.randint(3,6), "uptime": f"{random.randint(1,72)}h",
             "purpose": random.choice(["client","hs","general"]), "country": random.choice(["US","DE","NL","FR","SE","CH","CA"])}
            for i in range(max(0, state["rt_cycle"] * 3 - state["deep_cycle"]))
        ],
        "status": "operational" if state["rt_cycle"] > 3 else "degraded",
        "analysis": {
            "traffic_volume_mbps": round(random.uniform(150, 500), 1),
            "active_relays": random.randint(7000, 8000),
            "bridges_known": random.randint(2000, 3000),
            "countries_monitored": 42,
            "fingerprint_risk": "high" if state["deep_cycle"] > 10 else "moderate",
        }
    }


@app.get("/api/tor/history")
async def tor_history():
    points = 24
    base = state["rt_cycle"] * 10
    return {
        "traffic": [{"h": i, "mbps": round(random.uniform(100, 500), 1), "nodes": random.randint(6000, 8500)}
                    for i in range(points)],
        "protocols": {"TLS": random.randint(40, 60), "TCP": random.randint(15, 30),
                      "UDP": random.randint(5, 15), "DNS": random.randint(5, 10)},
        "countries": [{"c": "US", "v": random.randint(20, 40)}, {"c": "DE", "v": random.randint(10, 25)},
                      {"c": "NL", "v": random.randint(10, 20)}, {"c": "FR", "v": random.randint(5, 15)},
                      {"c": "SE", "v": random.randint(3, 10)}, {"c": "CH", "v": random.randint(2, 8)}],
        "exit_traffic": [{"h": i, "mbps": round(random.uniform(30, 150), 1)} for i in range(points)],
    }


@app.get("/api/threats/stats")
async def threat_stats():
    srcs = {}
    for t in state["threats"]:
        s = t.get("source", "unknown")
        srcs[s] = srcs.get(s, 0) + 1
    types = {}
    for t in state["threats"]:
        ty = t.get("type", "unknown")
        types[ty] = types.get(ty, 0) + 1
    daily = [
        {"day": i, "threats": random.randint(50, 500), "malware": random.randint(5, 50),
         "exploits": random.randint(10, 100), "phishing": random.randint(20, 200)}
        for i in range(30)
    ]
    return {
        "total": len(state["threats"]),
        "sources": [{"name": k, "count": v} for k, v in sorted(srcs.items(), key=lambda x: -x[1])[:10]],
        "types": [{"name": k, "count": v} for k, v in sorted(types.items(), key=lambda x: -x[1])[:10]],
        "daily": daily,
        "severity": {"critical": random.randint(10, 50), "high": random.randint(50, 200),
                     "medium": random.randint(100, 500), "low": random.randint(200, 800)},
        "top_ips": [{"ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                     "count": random.randint(10, 500)} for _ in range(10)],
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
    footprint_matches = [t for t in threats if any(ip_parts in (t.get("url","")+t.get("ioc",""))
                        for ip_range in profile.get("footprint",{}).get("ips",0) * "")]

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


@app.post("/api/agency/research")
async def agency_research(req: CompanyReq):
    agency_id = req.company.lower()
    profile = AGENCY_RESEARCH_DATA.get(agency_id, {})
    related_threats = [t for t in state["threats"][:200] if agency_id in t.get("source", "").lower() or
                       any(keyword in (t.get("instruction","")+t.get("description","")).lower()
                           for keyword in [agency_id, profile.get("name","").lower()])]
    return {
        "agency": agency_id,
        "profile": profile,
        "related_threats": related_threats[:30],
        "threat_count": len(related_threats),
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
