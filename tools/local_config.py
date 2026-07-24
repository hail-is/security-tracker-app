"""
Local, non-committed settings (e.g. remembered defaults for interactive prompts).

Stored at .local_config.json in the project root, which is gitignored.
"""
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / ".local_config.json"


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def set_config_value(key: str, value: str) -> None:
    config = load_config()
    config[key] = value
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
