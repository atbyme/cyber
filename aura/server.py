import asyncio
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .scraper import scrape_cyber_threats
from .cleaner import filter_and_clean, format_for_training
from .analyzer import digital_footprint, scan_ports
from .linux_knowledge import get_linux_training_data
from .modelscope_trainer import (
    prepare_dataset,
    generate_swift_config,
    save_swift_yaml,
    format_for_modelscope,
    merge_datasets,
    get_training_command,
)
from .config import DATA_DIR, DATASETS_DIR, load_config

logger = logging.getLogger("AURA.Server")

app_state: Dict = {
    "cycle_count": 0,
    "scrape_stats": {"total_scraped": 0, "last_scrape": None, "running": False},
    "train_stats": {
        "total_samples": 0,
        "last_trained": None,
        "running": False,
        "datasets": [],
        "model_versions": [],
    },
    "recent_threats": [],
    "analysis_history": [],
    "connected_clients": set(),
}


class AnalyzeRequest(BaseModel):
    target: str
    scan_ports: bool = False


class ScrapeResponse(BaseModel):
    status: str
    count: int
    message: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AURA Server starting - auto train cycle every 1 hour")
    asyncio.create_task(_auto_learn_cycle())
    yield
    logger.info("AURA Server shutting down...")


app = FastAPI(title="AURA Cyber AI Dashboard", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _broadcast(event: str, data: dict):
    msg = json.dumps({"event": event, "data": data, "timestamp": datetime.utcnow().isoformat()})
    dead = set()
    for ws in app_state["connected_clients"]:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    app_state["connected_clients"] -= dead


async def _auto_learn_cycle():
    await asyncio.sleep(10)
    while True:
        app_state["cycle_count"] += 1
        cycle = app_state["cycle_count"]
        logger.info(f"=== Auto-learn cycle #{cycle} starting ===")

        try:
            data = await asyncio.to_thread(scrape_cyber_threats)
            logger.info(f"Cycle #{cycle}: scraped {len(data)} raw threats")
        except Exception as e:
            logger.error(f"Cycle #{cycle}: scrape failed: {e}")
            await asyncio.sleep(3600)
            continue

        cleaned = filter_and_clean(data)
        formatted = format_for_training(cleaned)

        app_state["scrape_stats"]["total_scraped"] += len(data)
        app_state["scrape_stats"]["last_scrape"] = datetime.utcnow().isoformat()
        app_state["recent_threats"] = formatted[:100]

        await _broadcast("scrape_update", {
            "cycle": cycle,
            "count": len(data),
            "cleaned": len(cleaned),
            "total": app_state["scrape_stats"]["total_scraped"],
            "timestamp": app_state["scrape_stats"]["last_scrape"],
        })

        logger.info(f"Cycle #{cycle}: starting cloud training with {len(formatted)} samples")
        await _auto_train(formatted, cycle)

        logger.info(f"Cycle #{cycle}: complete. Next cycle in 1 hour.")
        await _broadcast("cycle_complete", {"cycle": cycle, "next_in": 3600})
        await asyncio.sleep(3600)


async def _auto_train(samples: list, cycle: int):
    app_state["train_stats"]["running"] = True
    try:
        await _broadcast("train_status", {
            "cycle": cycle,
            "status": "started",
            "samples": len(samples),
        })

        linux_data = format_for_modelscope(get_linux_training_data())
        threat_data = format_for_modelscope(samples)
        merged = merge_datasets([threat_data, linux_data])

        cfg = load_config()
        model = cfg.get("modelscope", {}).get("model_name", "Qwen/Qwen2.5-7B-Instruct")
        dataset_name = f"aura_cycle_{cycle}"

        dataset_path = await asyncio.to_thread(prepare_dataset, merged, dataset_name)
        config = generate_swift_config(dataset_path, model_name=model)
        config_file = dataset_path / "swift_config.yaml"
        await asyncio.to_thread(save_swift_yaml, config, config_file)

        hub_model_id = config["output"]["hub_model_id"]
        version_tag = f"v{cycle}"

        model_version = {
            "cycle": cycle,
            "hub_id": hub_model_id,
            "version": version_tag,
            "samples": len(merged),
            "timestamp": datetime.utcnow().isoformat(),
            "dataset_path": str(dataset_path),
        }
        app_state["train_stats"]["model_versions"].append(model_version)
        app_state["train_stats"]["last_trained"] = datetime.utcnow().isoformat()
        app_state["train_stats"]["total_samples"] = len(merged)
        app_state["train_stats"]["datasets"].append(str(dataset_path))

        cmd = get_training_command(str(config_file), cloud=True)

        await _broadcast("train_complete", {
            "cycle": cycle,
            "samples": len(merged),
            "model": model,
            "hub_model_id": hub_model_id,
            "version": version_tag,
            "dataset_path": str(dataset_path),
            "command": cmd,
        })

        logger.info(
            f"Cycle #{cycle} dataset ready: {len(merged)} samples | "
            f"Model: {hub_model_id}:{version_tag} | "
            f"Run on ModelScope cloud: swift train --config {config_file}"
        )

    except Exception as e:
        logger.error(f"Cycle #{cycle} training failed: {e}")
        await _broadcast("train_error", {"cycle": cycle, "error": str(e)})
    finally:
        app_state["train_stats"]["running"] = False


@app.get("/api/status")
async def get_status():
    return {
        "cycle": app_state["cycle_count"],
        "scraper": app_state["scrape_stats"],
        "training": {
            "running": app_state["train_stats"]["running"],
            "total_samples": app_state["train_stats"]["total_samples"],
            "last_trained": app_state["train_stats"]["last_trained"],
            "versions": len(app_state["train_stats"]["model_versions"]),
        },
        "recent_count": len(app_state["recent_threats"]),
        "analysis_count": len(app_state["analysis_history"]),
    }


@app.get("/api/scrape")
async def trigger_scrape():
    if app_state["scrape_stats"]["running"]:
        return ScrapeResponse(status="busy", count=0, message="Scrape already running")
    app_state["scrape_stats"]["running"] = True
    try:
        data = await asyncio.to_thread(scrape_cyber_threats)
        cleaned = filter_and_clean(data)
        formatted = format_for_training(cleaned)
        app_state["scrape_stats"]["total_scraped"] += len(data)
        app_state["scrape_stats"]["last_scrape"] = datetime.utcnow().isoformat()
        app_state["recent_threats"] = formatted[:100]
        app_state["train_stats"]["total_samples"] = len(formatted)
        return ScrapeResponse(status="ok", count=len(data), message=f"Scraped {len(data)} threats")
    finally:
        app_state["scrape_stats"]["running"] = False


@app.get("/api/threats")
async def get_threats(limit: int = 100):
    return app_state["recent_threats"][:limit]


@app.get("/api/models")
async def get_model_versions():
    return {
        "versions": app_state["train_stats"]["model_versions"],
        "current_cycle": app_state["cycle_count"],
    }


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    result = digital_footprint(req.target)
    if req.scan_ports and req.target.replace(".", "").isdigit():
        ports = scan_ports(req.target)
        result["port_scan"] = ports
    app_state["analysis_history"].append({
        "target": req.target,
        "timestamp": datetime.utcnow().isoformat(),
        "result": result,
    })
    return result


@app.get("/api/train/status")
async def train_status():
    return {
        "running": app_state["train_stats"]["running"],
        "total_samples": app_state["train_stats"]["total_samples"],
        "last_trained": app_state["train_stats"]["last_trained"],
        "versions": len(app_state["train_stats"]["model_versions"]),
        "datasets": len(app_state["train_stats"]["datasets"]),
    }


@app.get("/api/train/history")
async def train_history():
    return {
        "model_versions": app_state["train_stats"]["model_versions"][-20:],
        "datasets": app_state["train_stats"]["datasets"][-20:],
    }


@app.post("/api/train/start")
async def start_training():
    if app_state["train_stats"]["running"]:
        return {"status": "busy", "message": "Training already in progress"}
    samples = app_state.get("recent_threats", [])
    if not samples:
        data = await asyncio.to_thread(scrape_cyber_threats)
        cleaned = filter_and_clean(data)
        samples = format_for_training(cleaned)
    asyncio.create_task(_auto_train(samples, app_state["cycle_count"] + 1))
    return {"status": "started", "samples": len(samples)}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    app_state["connected_clients"].add(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        app_state["connected_clients"].discard(ws)
