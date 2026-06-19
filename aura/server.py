import asyncio
import json
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from .scraper import realtime_scan, deep_research_scan, get_source_stats, get_type_breakdown, extract_knowledge, THREAT_SOURCES
from .cleaner import filter_and_clean, format_for_training
from .analyzer import digital_footprint, scan_ports
from .linux_knowledge import get_linux_training_data
from .modelscope_trainer import (
    prepare_dataset, generate_swift_config, save_swift_yaml,
    format_for_modelscope, merge_datasets, get_training_command,
)
from .config import load_config

logger = logging.getLogger("AURA.Server")

app_state = {
    "cycle_count": 0,
    "research_count": 0,
    "scrape_stats": {"total_scraped": 0, "last_scrape": None, "running": False},
    "research_stats": {"total_researched": 0, "last_research": None, "running": False},
    "train_stats": {
        "total_samples": 0, "last_trained": None, "running": False,
        "datasets": [], "model_versions": [],
    },
    "knowledge": {"unique_cves": 0, "unique_iocs": 0, "unique_malware": 0, "unique_urls": 0, "total_samples": 0, "history": []},
    "recent_threats": [], "threat_history": [],
    "notifications": [], "analysis_history": [],
    "connected_clients": set(),
    "research_activity": [],
    "learning": True,
}

SOURCES_META = [{"id": k, "name": v} for k, v in THREAT_SOURCES.items()]


class AnalyzeReq(BaseModel):
    target: str
    scan_ports: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AURA starting — passive internet research + 2h deep cycle")
    asyncio.create_task(_passive_research_loop())
    asyncio.create_task(_deep_research_loop())
    yield
    logger.info("AURA stopping")


app = FastAPI(title="AURA Cyber AI", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

FD = Path(__file__).parent.parent / "frontend" / "dist"
if FD.exists():
    app.mount("/assets", StaticFiles(directory=str(FD / "assets")), name="assets")
    @app.get("/")
    async def spa(): return FileResponse(str(FD / "index.html"))
    @app.exception_handler(404)
    async def spa404(req, exc): return FileResponse(str(FD / "index.html"))


async def _broadcast(event: str, data: dict):
    msg = json.dumps({"event": event, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
    dead = set()
    for ws in app_state["connected_clients"]:
        try: await ws.send_text(msg)
        except: dead.add(ws)
    app_state["connected_clients"] -= dead


async def _notify(title: str, message: str, level: str = "info"):
    n = {"id": len(app_state["notifications"]) + 1, "title": title, "message": message, "level": level, "timestamp": datetime.now(timezone.utc).isoformat()}
    app_state["notifications"].insert(0, n)
    app_state["notifications"] = app_state["notifications"][:300]
    await _broadcast("notification", n)


def _update_knowledge(data: list):
    k = extract_knowledge(data)
    for key in ["unique_cves", "unique_iocs", "unique_malware", "unique_urls", "total_samples"]:
        app_state["knowledge"][key] += k.get(key, 0)
    app_state["knowledge"]["history"].append({
        "cycle": app_state["cycle_count"],
        "time": datetime.now(timezone.utc).isoformat(),
        **k,
    })
    app_state["knowledge"]["history"] = app_state["knowledge"]["history"][-200:]


async def _passive_research_loop():
    await asyncio.sleep(8)
    while app_state["learning"]:
        app_state["research_count"] += 1
        c = app_state["research_count"]
        logger.info(f"[RESEARCH #{c}] Passive real-time scan")
        try:
            data = await asyncio.to_thread(realtime_scan)
            if data:
                app_state["research_stats"]["total_researched"] += len(data)
                app_state["research_stats"]["last_research"] = datetime.now(timezone.utc).isoformat()
                cleaned = filter_and_clean(data)
                formatted = format_for_training(cleaned)
                app_state["recent_threats"] = formatted + app_state["recent_threats"]
                app_state["recent_threats"] = app_state["recent_threats"][:300]
                _update_knowledge(data)
                srcs = get_source_stats(data)
                types = get_type_breakdown(data)
                activity = {"cycle": c, "type": "realtime", "count": len(data), "sources": srcs, "types": types, "time": datetime.now(timezone.utc).isoformat()}
                app_state["research_activity"].insert(0, activity)
                app_state["research_activity"] = app_state["research_activity"][:100]
                app_state["scrape_stats"]["total_scraped"] += len(data)
                await _broadcast("research_update", {
                    "cycle": c, "count": len(data), "sources": srcs, "types": types,
                    "knowledge": app_state["knowledge"],
                })
                await _notify(f"Research #{c}: {len(data)} threats", f"Sources: {', '.join(f'{k}({v})' for k,v in srcs.items())}", "info")
                asyncio.create_task(_train(formatted, c))
        except Exception as e:
            logger.error(f"Research #{c} failed: {e}")
        await _broadcast("research_cycle", {"cycle": c, "next_seconds": 180})
        await asyncio.sleep(180)


async def _deep_research_loop():
    await asyncio.sleep(30)
    while app_state["learning"]:
        app_state["cycle_count"] += 1
        c = app_state["cycle_count"]
        logger.info(f"[DEEP #{c}] Full internet research scan")
        try:
            data = await asyncio.to_thread(deep_research_scan)
            if data:
                app_state["scrape_stats"]["total_scraped"] += len(data)
                app_state["scrape_stats"]["last_scrape"] = datetime.now(timezone.utc).isoformat()
                cleaned = filter_and_clean(data)
                formatted = format_for_training(cleaned)
                app_state["recent_threats"] = formatted + app_state["recent_threats"]
                app_state["recent_threats"] = app_state["recent_threats"][:500]
                _update_knowledge(data)
                srcs = get_source_stats(data)
                app_state["threat_history"].append({"cycle": c, "count": len(data), "sources": len(srcs), "time": datetime.now(timezone.utc).isoformat()})
                app_state["threat_history"] = app_state["threat_history"][-100:]
                await _broadcast("deep_research_update", {
                    "cycle": c, "count": len(data), "sources": srcs,
                    "knowledge": app_state["knowledge"],
                })
                await _notify(f"Deep Research #{c}: {len(data)} threats", f"Full scan across all {len(srcs)} sources", "success")
                if len(formatted) >= 5:
                    asyncio.create_task(_train(formatted, c))
            else:
                logger.warning(f"Deep #{c}: no data returned")
        except Exception as e:
            logger.error(f"Deep #{c} failed: {e}")
        await asyncio.sleep(7200)


async def _train(samples: list, cycle: int):
    if app_state["train_stats"]["running"]:
        return
    app_state["train_stats"]["running"] = True
    try:
        await _broadcast("train_status", {"cycle": cycle, "status": "started", "samples": len(samples)})
        merged = merge_datasets([format_for_modelscope(samples), format_for_modelscope(get_linux_training_data())])
        cfg = load_config()
        model = cfg.get("modelscope", {}).get("model_name", "Qwen/Qwen2.5-7B-Instruct")
        dp = await asyncio.to_thread(prepare_dataset, merged, f"aura_c{cycle}")
        config = generate_swift_config(dp, model_name=model)
        cf = dp / "swift_config.yaml"
        await asyncio.to_thread(save_swift_yaml, config, cf)
        ver = {"cycle": cycle, "hub_id": config["output"]["hub_model_id"], "version": f"v{cycle}", "samples": len(merged), "timestamp": datetime.now(timezone.utc).isoformat(), "dataset_path": str(dp)}
        app_state["train_stats"]["model_versions"].append(ver)
        app_state["train_stats"]["last_trained"] = datetime.now(timezone.utc).isoformat()
        app_state["train_stats"]["total_samples"] = len(merged)
        app_state["train_stats"]["datasets"].append(str(dp))
        cmd = get_training_command(str(cf), cloud=True)
        await _broadcast("train_complete", {"cycle": cycle, "samples": len(merged), "model": model, "hub_model_id": config["output"]["hub_model_id"], "version": f"v{cycle}", "command": cmd})
        await _notify(f"Dataset v{cycle} ready", f"{len(merged)} samples pushed to ModelScope cloud", "success")
    except Exception as e:
        logger.error(f"Train fail: {e}")
        await _broadcast("train_error", {"cycle": cycle, "error": str(e)})
    finally:
        app_state["train_stats"]["running"] = False


@app.get("/api/status")
async def status():
    return {
        "cycle": app_state["cycle_count"], "research_cycle": app_state["research_count"], "learning": app_state["learning"],
        "scraper": app_state["scrape_stats"],
        "research": app_state["research_stats"],
        "knowledge": {k: v for k, v in app_state["knowledge"].items() if k != "history"},
        "training": {k: v for k, v in app_state["train_stats"].items() if k not in ("datasets", "model_versions")},
        "recent_count": len(app_state["recent_threats"]),
        "notifications_count": len(app_state["notifications"]),
        "analysis_count": len(app_state["analysis_history"]),
    }


@app.get("/api/sources")
async def sources():
    return {s["id"]: s["name"] for s in SOURCES_META}


@app.get("/api/knowledge")
async def knowledge():
    return app_state["knowledge"]


@app.get("/api/research/activity")
async def research_activity(limit: int = 50):
    return app_state["research_activity"][:limit]


@app.get("/api/threats")
async def threats(limit: int = 200):
    return app_state["recent_threats"][:limit]


@app.get("/api/threats/history")
async def threat_history():
    return app_state["threat_history"][-50:]


@app.get("/api/models")
async def models():
    return {"versions": app_state["train_stats"]["model_versions"], "current_cycle": app_state["cycle_count"]}


@app.get("/api/notifications")
async def get_notifications(limit: int = 50):
    return app_state["notifications"][:limit]


@app.post("/api/notifications/clear")
async def clear_notifs():
    app_state["notifications"] = []
    await _broadcast("notifications_cleared", {})
    return {"status": "cleared"}


@app.post("/api/analyze")
async def analyze(req: AnalyzeReq):
    result = digital_footprint(req.target)
    if req.scan_ports and req.target.replace(".", "").isdigit():
        result["port_scan"] = scan_ports(req.target)
    app_state["analysis_history"].append({"target": req.target, "timestamp": datetime.now(timezone.utc).isoformat(), "result": result})
    await _notify("Footprint Analyzed", f"Target: {req.target}", "info")
    return result


@app.get("/api/train/status")
async def train_status():
    return {
        "running": app_state["train_stats"]["running"],
        "total_samples": app_state["train_stats"]["total_samples"],
        "last_trained": app_state["train_stats"]["last_trained"],
        "versions": len(app_state["train_stats"]["model_versions"]),
    }


@app.get("/api/train/history")
async def train_history():
    return {"model_versions": app_state["train_stats"]["model_versions"][-50:], "datasets": app_state["train_stats"]["datasets"][-50:]}


@app.post("/api/train/start")
async def start_train():
    if app_state["train_stats"]["running"]:
        return {"status": "busy", "message": "Training already running"}
    samples = app_state.get("recent_threats", [])[:100]
    if not samples:
        data = await asyncio.to_thread(deep_research_scan)
        samples = format_for_training(filter_and_clean(data))
    asyncio.create_task(_train(samples, app_state["cycle_count"] + 1))
    return {"status": "started", "samples": len(samples)}


@app.get("/api/analysis/history")
async def analysis_hist(limit: int = 20):
    return app_state["analysis_history"][-limit:]


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    app_state["connected_clients"].add(ws)
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("action") == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except:
        pass
    finally:
        app_state["connected_clients"].discard(ws)
