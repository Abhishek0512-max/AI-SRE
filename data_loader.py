"""Data loader for incident investigation dataset."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


def load_json(path: str) -> Any:
    with open(path, 'r') as f:
        return json.load(f)


def load_jsonl(path: str) -> List[Dict]:
    with open(path, 'r') as f:
        return [json.loads(line) for line in f if line.strip()]


def parse_ts(ts: str) -> datetime:
    """Parse ISO8601 timestamp to datetime."""
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    return datetime.fromisoformat(ts)


def load_all(data_dir: str) -> Dict[str, Any]:
    """Load all dataset files."""
    p = Path(data_dir)
    return {
        'alerts': load_json(p / 'alerts.json'),
        'metrics': load_json(p / 'metrics.json'),
        'changes': load_json(p / 'changes.json'),
        'service_map': load_json(p / 'service_map.json'),
        'logs': load_jsonl(p / 'logs.jsonl'),
    }
