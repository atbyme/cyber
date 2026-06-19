import os
import json
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".aura"
CONFIG_FILE = CONFIG_DIR / "config.json"
DATA_DIR = CONFIG_DIR / "data"
DATASETS_DIR = CONFIG_DIR / "datasets"


DEFAULT_CONFIG = {
    "modelscope": {
        "api_key": "",
        "model_name": "Qwen/Qwen2.5-7B-Instruct",
        "cloud_workspace": "aura-cyber",
    },
    "scraper": {
        "nvd_api_key": "",
        "otx_api_key": "",
        "threatfox_enabled": True,
        "cache_ttl_hours": 6,
    },
    "training": {
        "epochs": 3,
        "batch_size": 4,
        "learning_rate": 2e-5,
        "max_seq_length": 2048,
    },
}


def ensure_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    ensure_dirs()
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    save_config(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict):
    ensure_dirs()
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def get(key: str, default=None):
    cfg = load_config()
    parts = key.split(".")
    for p in parts:
        if isinstance(cfg, dict):
            cfg = cfg.get(p)
        else:
            return default
    return cfg if cfg is not None else default


def set_key(key: str, value):
    cfg = load_config()
    parts = key.split(".")
    target = cfg
    for p in parts[:-1]:
        target = target.setdefault(p, {})
    target[parts[-1]] = value
    save_config(cfg)
