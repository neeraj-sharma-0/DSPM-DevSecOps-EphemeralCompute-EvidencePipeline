from __future__ import annotations
import json
import time
from dataclasses import dataclass
from typing import Any, Dict

def receipt(kind: str, inputs: Dict[str, Any], outputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "kind": kind,
        "ts_epoch": int(time.time()),
        "inputs": inputs,
        "outputs": outputs,
    }

def write_receipt(path, payload: Dict[str, Any]) -> None:
    import pathlib
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
