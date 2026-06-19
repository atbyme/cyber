import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .scraper import scrape_all, get_source_stats
from .cleaner import filter_and_clean, format_for_training
from .analyzer import digital_footprint, scan_ports
from .linux_knowledge import get_linux_training_data
from .modelscope_trainer import (
    prepare_dataset, generate_swift_config, save_swift_yaml,
    format_for_modelscope, merge_datasets, get_training_command, push_dataset_to_hub,
)
from .config import load_config
from pathlib import Path

logger = logging.getLogger("AURA.Server")

app_state = {
    "cycle_count": 0,
    "scrape_stats": {"total_scraped": 0, "last_scrape": None, "running": False},
    "train_stats": {
        "total_samples": 0, "last_trained": None, "running": False,
        "datasets": [], "model_versions": [],
    },
    "recent_threats": [], "threat_history": [],
    "notifications": [], "analysis_history": [],
    "connected_clients": set(),
    "learning": True,
}


class AnalyzeReq(BaseModel):
    target: str
    scan_ports: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AURA starting — continuous internet monitoring active")
    asyncio.create_task(_engine())
    yield
    logger.info("AURA stopping")


app = FastAPI(title="AURA Cyber AI", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/")
    async def serve_spa():
        return FileResponse(str(FRONTEND_DIST / "index.html"))

    @app.exception_handler(404)
    async def spa_fallback(req, exc):
        return FileResponse(str(FRONTEND_DIST / "index.html"))


async def _broadcast(event: str, data: dict):
    msg = json.dumps({"event": event, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
    dead = set()
    for ws in app_state["connected_clients"]:
        try:
            await ws.send_text(msg)
        except:
            dead.add(ws)
    app_state["connected_clients"] -= dead


async def _notify(title: str, message: str, level: str = "info"):
    n = {"id": len(app_state["notifications"]) + 1, "title": title, "message": message, "level": level, "timestamp": datetime.now(timezone.utc).isoformat()}
    app_state["notifications"].insert(0, n)
    app_state["notifications"] = app_state["notifications"][:200]
    await _broadcast("notification", n)
    logger.info(f"[{level.upper()}] {title}")


async def _engine():
    await asyncio.sleep(5)
    while app_state["learning"]:
        app_state["cycle_count"] += 1
        c = app_state["cycle_count"]
        logger.info(f"=== Cycle #{c} ===")

        try:
            data = await asyncio.to_thread(scrape_all)
            app_state["scrape_stats"]["total_scraped"] += len(data)
            app_state["scrape_stats"]["last_scrape"] = datetime.now(timezone.utc).isoformat()
            cleaned = filter_and_clean(data)
            formatted = format_for_training(cleaned)
            app_state["recent_threats"] = formatted[:200]

            if c % 12 == 0:
                app_state["threat_history"].append({"cycle": c, "count": len(data), "time": datetime.now(timezone.utc).isoformat()})
                app_state["threat_history"] = app_state["threat_history"][-100:]

            srcs = get_source_stats(data)
            await _broadcast("scrape_update", {
                "cycle": c, "count": len(data), "cleaned": len(cleaned),
                "total": app_state["scrape_stats"]["total_scraped"],
                "sources": srcs, "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            if len(data) > 5:
                await _notify(f"Cycle #{c}: {len(data)} threats", f"Sources: {', '.join(f'{k}={v}' for k,v in srcs.items())}", "info")

            if len(formatted) >= 3:
                asyncio.create_task(_train(formatted, c))

        except Exception as e:
            logger.error(f"Cycle #{c} error: {e}")

        await _broadcast("cycle_complete", {"cycle": c, "next_seconds": 60})
        await asyncio.sleep(60)


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
        await _notify(f"Dataset v{cycle} ready", f"{len(merged)} samples → cloud training on ModelScope", "success")
    except Exception as e:
        logger.error(f"Train fail: {e}")
        await _broadcast("train_error", {"cycle": cycle, "error": str(e)})
    finally:
        app_state["train_stats"]["running"] = False


@app.get("/api/status")
async def status():
    return {
        "cycle": app_state["cycle_count"], "learning": app_state["learning"],
        "scraper": app_state["scrape_stats"],
        "training": {k: v for k, v in app_state["train_stats"].items() if k != "datasets"},
        "recent_count": len(app_state["recent_threats"]),
        "notifications_count": len(app_state["notifications"]),
        "analysis_count": len(app_state["analysis_history"]),
    }


@app.get("/api/scrape")
async def trigger_scrape():
    if app_state["scrape_stats"]["running"]:
        return {"status": "busy", "count": 0, "message": "Already running"}
    app_state["scrape_stats"]["running"] = True
    try:
        data = await asyncio.to_thread(scrape_all)
        cleaned = filter_and_clean(data)
        app_state["scrape_stats"]["total_scraped"] += len(data)
        app_state["scrape_stats"]["last_scrape"] = datetime.now(timezone.utc).isoformat()
        app_state["recent_threats"] = format_for_training(cleaned)[:200]
        return {"status": "ok", "count": len(data), "message": f"Scraped {len(data)} threats from {len(get_source_stats(data))} sources"}
    finally:
        app_state["scrape_stats"]["running"] = False


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
    samples = app_state.get("recent_threats", [])
    if not samples:
        data = await asyncio.to_thread(scrape_all)
        samples = format_for_training(filter_and_clean(data))
    asyncio.create_task(_train(samples, app_state["cycle_count"] + 1))
    return {"status": "started", "samples": len(samples)}


@app.get("/api/analysis/history")
async def analysis_hist(limit: int = 20):
    return app_state["analysis_history"][-limit:]


@app.get("/api/sources")
async def sources():
    from .scraper import THREAT_SOURCES
    return THREAT_SOURCES


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
