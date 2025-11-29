from dataclasses import dataclass
from typing import List
import pathlib, yaml

@dataclass
class Pipeline:
    steps: List[str]
    concurrency: int = 4
    continue_on_error: bool = True

def load_pipeline(home: pathlib.Path) -> Pipeline:
    cfg = home / "config" / "pipeline.yaml"
    if not cfg.exists():
        # дефолт, если файла нет
        return Pipeline(steps=["httpx", "nmap"], concurrency=4, continue_on_error=True)
    data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    steps = data.get("steps") or []
    if not isinstance(steps, list) or not all(isinstance(x, str) for x in steps):
        raise ValueError("pipeline.steps must be a list of strings")
    return Pipeline(
        steps=steps,
        concurrency=int(data.get("concurrency", 4)),
        continue_on_error=bool(data.get("continue_on_error", True)),
    )
