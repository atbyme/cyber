import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

from .config import DATASETS_DIR, get, set_key

logger = logging.getLogger("sys.trainer")

MODELSCOPE_API = "https://api.modelscope.cn/v1"
MODELSCOPE_HUB_API = "https://www.modelscope.cn/api/v1"
DATASET_OWNER = "aura-cyber"
DATASET_NAME = "aura-threat-intel"
SUPPORTED_MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-14B-Instruct",
    "Qwen/QwQ-32B",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
    "ZhipuAI/glm-4-9b-chat",
    "Shanghai_AI_Laboratory/internlm2_5-7b-chat",
]


def _api_key() -> str:
    return get("modelscope.api_key", "")


def _headers() -> dict:
    ak = _api_key()
    h = {"Content-Type": "application/json"}
    if ak:
        h["Authorization"] = f"Bearer {ak}"
    return h


def prepare_dataset(data: List[Dict], name: str = "aura_auto") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_dir = DATASETS_DIR / f"{name}_{timestamp}"
    dataset_dir.mkdir(parents=True, exist_ok=True)

    split = max(1, int(len(data) * 0.9))
    train_file = dataset_dir / "train.jsonl"
    valid_file = dataset_dir / "valid.jsonl"

    for f, subset in [(train_file, data[:split]), (valid_file, data[split:])]:
        with open(f, "w", encoding="utf-8") as fh:
            for item in subset:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")

    config = {
        "dataset_name": name, "created_at": timestamp,
        "total_samples": len(data), "train_samples": split, "valid_samples": len(data) - split,
    }
    with open(dataset_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    logger.info(f"Dataset prepared: {dataset_dir} ({len(data)} samples)")
    return str(dataset_dir)


def generate_swift_config(dataset_path: str, model: str = "Qwen/Qwen2.5-7B-Instruct", hyperparams: dict = None) -> dict:
    cfg = {
        "model": model,
        "dataset": f"{dataset_path}/train.jsonl",
        "valid_dataset": f"{dataset_path}/valid.jsonl",
        "hyperparameters": {
            "epochs": hyperparams.get("epochs", 3) if hyperparams else 3,
            "batch_size": hyperparams.get("batch_size", 4) if hyperparams else 4,
            "learning_rate": hyperparams.get("learning_rate", 2e-5) if hyperparams else 2e-5,
            "max_seq_length": 2048,
            "lora_rank": 8, "lora_alpha": 32, "lora_dropout": 0.05,
        },
        "output": {"push_to_hub": True, "hub_model_id": f"{DATASET_OWNER}/{model.split('/')[-1]}-ft"},
    }
    return cfg


def save_swift_yaml(config: dict, output_path: str) -> str:
    path = Path(output_path)
    try:
        import yaml
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
    return str(path)


def format_for_modelscope(data: List[Dict]) -> List[Dict]:
    return [{"instruction": d["instruction"], "output": d["response"]} for d in data if d.get("instruction") and d.get("response")]


def merge_datasets(datasets: List[List[Dict]]) -> List[Dict]:
    seen = set()
    merged = []
    for ds in datasets:
        for item in ds:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged


def push_dataset_to_hub(dataset_path: str, version: str) -> dict:
    ak = _api_key()
    if not ak:
        logger.warning("No ModelScope API key, saving dataset locally only")
        return {"status": "saved_locally", "path": dataset_path, "version": version}

    full_name = f"{DATASET_OWNER}/{DATASET_NAME}"
    url = f"{MODELSCOPE_HUB_API}/datasets/{full_name}/versions"

    dataset_dir = Path(dataset_path)
    train_path = dataset_dir / "train.jsonl"
    valid_path = dataset_dir / "valid.jsonl"
    config_path = dataset_dir / "config.json"

    if not train_path.exists():
        return {"status": "error", "message": "train.jsonl not found"}

    payload = {
        "version": version,
        "description": f"cyber threat intelligence dataset v{version} - {datetime.now(timezone.utc).isoformat()}",
        "files": [],
    }

    try:
        resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
        dataset_id = None
        if resp.status_code in (200, 201):
            dataset_id = resp.json().get("id")
            logger.info(f"Dataset version {version} created on ModelScope Hub: {resp.status_code}")

        upload_url = f"{MODELSCOPE_HUB_API}/datasets/{full_name}/versions/{version}/files"

        for fpath in [train_path, valid_path, config_path]:
            if fpath.exists():
                with open(fpath, "rb") as fh:
                    files = {"file": (fpath.name, fh, "application/octet-stream")}
                    ur = requests.post(upload_url, files=files, headers={"Authorization": f"Bearer {ak}"}, timeout=60)
                    logger.info(f"Upload {fpath.name}: {ur.status_code}")

        logger.info(f"Dataset {full_name} v{version} pushed to ModelScope Hub")
        return {"status": "pushed", "dataset": full_name, "version": version, "id": dataset_id}
    except Exception as e:
        logger.error(f"Hub push failed: {e}")
        return {"status": "saved_locally", "path": dataset_path, "version": version}


def list_hub_datasets() -> list:
    datasets = []
    for d in DATASETS_DIR.iterdir():
        if d.is_dir() and (d / "config.json").exists():
            try:
                cfg = json.load(open(d / "config.json"))
                datasets.append({"name": d.name, "path": str(d), "samples": cfg.get("total_samples", 0), "created": cfg.get("created_at", "")})
            except:
                pass
    return sorted(datasets, key=lambda x: x.get("created", ""), reverse=True)


def trigger_cloud_training(dataset_path: str, model: str = "Qwen/Qwen2.5-7B-Instruct") -> dict:
    ak = _api_key()
    if not ak:
        logger.info(f"Local-only mode: dataset saved at {dataset_path}")
        return {"status": "local_ready", "path": dataset_path, "model": model, "message": "Dataset saved locally. Set modelscope.api_key for cloud training."}

    url = f"{MODELSCOPE_API}/train/fine-tune"
    payload = {
        "model": model,
        "train_dataset_path": f"{dataset_path}/train.jsonl",
        "valid_dataset_path": f"{dataset_path}/valid.jsonl",
        "hyperparameters": {
            "epochs": 3, "batch_size": 4, "learning_rate": 2e-5, "max_seq_length": 2048,
            "lora_rank": 8, "lora_alpha": 32,
        },
        "push_to_hub": True,
        "hub_model_id": f"{DATASET_OWNER}/{model.split('/')[-1]}-ft",
    }
    try:
        resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
        if resp.status_code == 200:
            result = resp.json()
            logger.info(f"Cloud training started: {result}")
            return {"status": "started", "job_id": result.get("job_id"), "response": result}
        else:
            logger.warning(f"Cloud training API error: {resp.status_code} {resp.text[:200]}")
            return {"status": "saved_locally", "path": dataset_path, "model": model, "message": "Dataset saved. Cloud training failed, try again later."}
    except Exception as e:
        logger.error(f"Cloud training request failed: {e}")
        return {"status": "saved_locally", "path": dataset_path, "model": model, "message": f"Dataset saved locally. Cloud unavailable: {e}"}


def check_training_status(job_id: str) -> dict:
    ak = _api_key()
    if not ak:
        return {"status": "local_only"}
    try:
        resp = requests.get(f"{MODELSCOPE_API}/train/jobs/{job_id}", headers=_headers(), timeout=15)
        return resp.json() if resp.status_code == 200 else {"status": "error", "code": resp.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def list_trained_models() -> list:
    return [{"name": m.split("/")[-1], "path": m, "source": "local"} for m in SUPPORTED_MODELS]


def get_training_command(config_path: str, cloud: bool = True) -> str:
    if cloud:
        return f"pip install ms-swift -U\nswift train --config {config_path}"
    return f"swift train --config {config_path}"
