import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import DEFAULT_CONFIG
from .logger import JsonlLogger
from .monitor import tail_log_file
from .notifier import TelegramNotifier
from .responder import UfwResponder

IP_REGEX = re.compile(r"(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)")


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    regex: re.Pattern
    severity: str
    block_on_match: bool
    tags: List[str]
    source: str
    reference: Optional[str] = None

    def match(self, line: str) -> bool:
        return bool(self.regex.search(line))


def parse_config(config_path: Optional[str]) -> Dict[str, Any]:
    if config_path:
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            raise SystemExit(f"Unable to load config {config_path}: {exc}")

    return DEFAULT_CONFIG


def build_rules(config: Dict[str, Any]) -> List[DetectionRule]:
    rules: List[DetectionRule] = []
    for entry in config.get("detectors", []):
        rules.append(
            DetectionRule(
                id=entry["id"],
                name=entry["name"],
                description=entry.get("description", ""),
                regex=re.compile(entry["pattern"], re.IGNORECASE),
                severity=entry.get("severity", "medium"),
                block_on_match=entry.get("block_on_match", False),
                tags=entry.get("tags", []),
                source=entry.get("source", "custom"),
                reference=entry.get("reference"),
            )
        )
    return rules


def extract_ip(line: str) -> Optional[str]:
    match = IP_REGEX.search(line)
    if match:
        ip = match.group("ip")
        parts = [int(part) for part in ip.split('.')]
        if all(0 <= part <= 255 for part in parts):
            return ip
    return None


async def monitor_source(
    name: str,
    path: str,
    rules: List[DetectionRule],
    logger: JsonlLogger,
    notifier: TelegramNotifier,
    responder: UfwResponder,
    dry_run: bool,
    cache: Dict[str, float],
    rate_limit_seconds: int,
) -> None:
    async for line in tail_log_file(path):
        text = line.rstrip("\n")
        for rule in rules:
            if rule.match(text):
                event = {
                    "timestamp": logger.timestamp(),
                    "source": name,
                    "path": path,
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "rule_source": rule.source,
                    "rule_reference": rule.reference,
                    "severity": rule.severity,
                    "tags": rule.tags,
                    "message": text,
                }
                ip = extract_ip(text)
                if ip:
                    event["ip"] = ip

                if rule.block_on_match and responder.enabled and ip:
                    now = asyncio.get_event_loop().time()
                    previous = cache.get(ip, 0)
                    if now - previous >= rate_limit_seconds:
                        cache[ip] = now
                        try:
                            block_result = responder.block_ip(ip, rule.name, dry_run=dry_run)
                        except Exception as exc:
                            block_result = {"action": "failed", "ip": ip, "error": str(exc)}
                        if block_result:
                            event["block_action"] = block_result.get("action")
                            event["block_reason"] = block_result.get("reason")
                            event["block_tier"] = block_result.get("tier")
                            event["block_duration"] = block_result.get("duration")
                            event["block_type"] = block_result.get("block_type")
                            event["block_error"] = block_result.get("error")
                    else:
                        event["block_action"] = "rate_limited"

                logger.emit(event)
                notifier.notify(event)
                break


async def run(config_path: Optional[str], dry_run: bool, verbose: bool) -> None:
    config = parse_config(config_path)
    rules = build_rules(config)
    logger = JsonlLogger(config["logging"]["output_path"], console=config["logging"].get("console", True))
    responder = UfwResponder(
        enabled=config["response"].get("enabled", True),
        dry_run=dry_run,
        whitelist_ips=config["response"].get("whitelist_ips", []),
        escalation_seconds=config["response"].get("escalation_seconds", [3600, 86400, 0]),
    )
    notifier = TelegramNotifier.from_config(config, dry_run=dry_run)
    cache: dict[str, float] = {}
    rate_limit_seconds = config["response"].get("rate_limit_seconds", 600)

    tasks = []
    for source in config["log_sources"]:
        tasks.append(
            asyncio.create_task(
                monitor_source(
                    source["name"],
                    source["path"],
                    rules,
                    logger,
                    notifier,
                    responder,
                    dry_run,
                    cache,
                    rate_limit_seconds,
                )
            )
        )

    if verbose:
        logger.emit({
            "timestamp": logger.timestamp(),
            "source": "xphylax",
            "path": "config",
            "rule_id": "startup",
            "rule_name": "startup",
            "severity": "info",
            "tags": ["startup"],
            "message": f"xPhylax started monitoring {len(tasks)} sources",
        })

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        if verbose:
            print("xPhylax shutting down cleanly.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="xphylax", description="xPhylax real-time Linux log monitoring and active response")
    parser.add_argument("--config", help="Custom JSON config file path")
    parser.add_argument("--dry-run", action="store_true", help="Do not apply firewall changes")
    parser.add_argument("--verbose", action="store_true", help="Emit startup and status events")
    args = parser.parse_args()

    if os.name != "posix":
        raise SystemExit("xPhylax is designed for Linux and requires a POSIX runtime.")

    try:
        asyncio.run(run(args.config, args.dry_run, args.verbose))
    except KeyboardInterrupt:
        print("Terminated by user.")
        sys.exit(0)
