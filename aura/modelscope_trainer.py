import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .config import DATASETS_DIR, get, set_key

logger = logging.getLogger("AURA.ModelScopeTrainer")

MODELSCOPE_API_BASE = "https://api.modelscope.cn/v1"

SUPPORTED_MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-14B-Instruct",
    "Qwen/QwQ-32B",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B",
    "ZhipuAI/glm-4-9b-chat",
    "Shanghai_AI_Laboratory/internlm2_5-7b-chat",
]

TRAINING_TEMPLATE = {
    "model": "",
    "dataset": [],
    "hyperparameters": {
        "epochs": 3,
        "batch_size": 4,
        "learning_rate": 2e-5,
        "max_seq_length": 2048,
        "warmup_ratio": 0.1,
        "lora_rank": 8,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
    },
    "output": {
        "push_to_hub": True,
        "hub_model_id": "",
    },
}


def prepare_dataset(data: List[Dict], name: str = "cyber_threat") -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_dir = DATASETS_DIR / f"{name}_{timestamp}"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    train_file = dataset_dir / "train.jsonl"
    valid_file = dataset_dir / "valid.jsonl"

    split = int(len(data) * 0.9)
    for f, subset in [(train_file, data[:split]), (valid_file, data[split:])]:
        with open(f, "w", encoding="utf-8") as fh:
            for item in subset:
                json.dump(item, fh, ensure_ascii=False)
                fh.write("\n")

    config = {
        "dataset_name": name,
        "created_at": timestamp,
        "total_samples": len(data),
        "train_samples": split,
        "valid_samples": len(data) - split,
        "format": "instruction-response",
    }
    with open(dataset_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    logger.info(f"Dataset prepared: {dataset_dir} ({len(data)} samples)")
    return dataset_dir


def generate_swift_config(
    dataset_path: Path,
    model_name: str = "Qwen/Qwen2.5-7B-Instruct",
    hyperparams: Optional[Dict] = None,
) -> dict:
    cfg = dict(TRAINING_TEMPLATE)
    cfg["model"] = model_name
    cfg["dataset"] = [
        str(dataset_path / "train.jsonl"),
        str(dataset_path / "valid.jsonl"),
    ]
    if hyperparams:
        cfg["hyperparameters"].update(hyperparams)
    hub_id = f"aura-cyber/{model_name.split('/')[-1]}-finetuned"
    cfg["output"]["hub_model_id"] = hub_id
    return cfg


def save_swift_yaml(config: dict, output_path: Path) -> Path:
    try:
        import yaml
        with open(output_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        logger.info(f"MS-SWIFT config saved: {output_path}")
        return output_path
    except ImportError:
        with open(output_path, "w") as f:
            json.dump(config, f, indent=2)
        logger.warning("PyYAML not installed, saved as JSON instead")
        return output_path


def format_for_modelscope(data: List[Dict]) -> List[Dict]:
    formatted = []
    for item in data:
        instruction = item.get("instruction", "")
        response = item.get("response", "")
        if instruction and response:
            fmt_item = {
                "instruction": instruction,
                "output": response,
            }
            formatted.append(fmt_item)
    return formatted


def merge_datasets(datasets: List[List[Dict]]) -> List[Dict]:
    merged = []
    seen = set()
    for ds in datasets:
        for item in ds:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                merged.append(item)
    logger.info(f"Merged {sum(len(d) for d in datasets)} -> {len(merged)} unique samples")
    return merged


def get_training_command(config_path: str, cloud: bool = True) -> str:
    if cloud:
        return (
            f"pip install ms-swift -U\n"
            f"swift train --config {config_path}"
        )
    return f"swift train --config {config_path}"


def generate_colab_notebook(dataset_name: str, model_name: str) -> str:
    return f'''# AURA Cloud Training - ModelScope MS-SWIFT
# Dataset: {dataset_name} | Model: {model_name}

!pip install ms-swift -U
!pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

import json
from google.colab import files
import yaml

uploaded = files.upload()
# Upload the dataset zip and config.yaml

import zipfile
import os
for fn in uploaded.keys():
    if fn.endswith('.zip'):
        with zipfile.ZipFile(fn, 'r') as zf:
            zf.extractall('dataset')

# Start training
!swift train --config config.yaml

# Push to ModelScope Hub
!swift export --ckpt_dir output --push_to_hub true --hub_model_id aura-cyber/{model_name.split('/')[-1]}-finetuned
'''
