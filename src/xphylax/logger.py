import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class JsonlLogger:
    def __init__(self, output_path: str, console: bool = True) -> None:
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.console = console
        self.lock = threading.Lock()

    def timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def emit(self, event: dict) -> None:
        event["timestamp"] = event.get("timestamp", self.timestamp())
        record = json.dumps(event, ensure_ascii=False)
        with self.lock:
            with open(self.output_path, "a", encoding="utf-8") as handle:
                handle.write(record + "\n")
        if self.console:
            print(record)
