import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TELEGRAM_CONFIG_PATH = "/etc/xphylax.conf"


def escape_markdown(text: str) -> str:
    special_chars = r"_ * [ ] ( ) ~ ` > # + - = | { } . !"
    for char in special_chars.split():
        text = text.replace(char, f"\\{char}")
    return text


def load_key_value_file(path: str = DEFAULT_TELEGRAM_CONFIG_PATH) -> Dict[str, str]:
    values: Dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return values

    with file_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key:
                values[key] = value

    return values


def load_telegram_credentials(path: str = DEFAULT_TELEGRAM_CONFIG_PATH) -> Dict[str, str]:
    file_values = load_key_value_file(path)
    return {
        "bot_token": file_values.get("BOT_TOKEN") or os.getenv("BOT_TOKEN", ""),
        "chat_id": file_values.get("CHAT_ID") or os.getenv("CHAT_ID", ""),
    }


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        enabled: bool = False,
        dry_run: bool = False,
        parse_mode: str = "MarkdownV2",
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled and bool(bot_token and chat_id)
        self.dry_run = dry_run
        self.parse_mode = parse_mode
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    @classmethod
    def from_config(
        cls,
        config: Dict[str, Any],
        dry_run: bool = False,
    ) -> "TelegramNotifier":
        notifier_config = config.get("notifications", {}).get("telegram", {})
        credentials_path = notifier_config.get("credentials_path", DEFAULT_TELEGRAM_CONFIG_PATH)
        credentials = load_telegram_credentials(credentials_path)
        return cls(
            bot_token=credentials["bot_token"],
            chat_id=credentials["chat_id"],
            enabled=notifier_config.get("enabled", True),
            dry_run=dry_run,
            parse_mode=notifier_config.get("parse_mode", "MarkdownV2"),
        )

    def _format_message(self, event: Dict[str, Any]) -> str:
        parts = ["*xPhylax Alert*"]
        parts.append(f"*Rule:* `{escape_markdown(str(event.get('rule_name', 'unknown')))}`")
        parts.append(f"*Rule ID:* `{escape_markdown(str(event.get('rule_id', 'unknown')))}`")
        parts.append(f"*Source:* `{escape_markdown(str(event.get('rule_source', 'unknown')))}`")
        if event.get("rule_reference"):
            parts.append(f"*Reference:* `{escape_markdown(str(event['rule_reference']))}`")
        parts.append(f"*Severity:* `{escape_markdown(str(event.get('severity', 'unknown')))}`")
        if event.get("tags"):
            tags = ", ".join(str(tag) for tag in event["tags"])
            parts.append(f"*Tags:* `{escape_markdown(tags)}`")
        parts.append(f"*Log:* `{escape_markdown(str(event.get('source', 'unknown')))}`")
        parts.append(f"*Path:* `{escape_markdown(str(event.get('path', 'unknown')))}`")

        if event.get("ip"):
            parts.append(f"*IP:* `{escape_markdown(str(event['ip']))}`")

        if event.get("block_action"):
            parts.append(f"*Action:* `{escape_markdown(str(event['block_action']))}`")

        if event.get("block_reason"):
            parts.append(f"*Action reason:* `{escape_markdown(str(event['block_reason']))}`")

        if event.get("block_tier") is not None:
            parts.append(f"*Block tier:* `{event['block_tier']}`")

        if event.get("block_duration") is not None:
            duration = event['block_duration']
            duration_label = "permanent" if duration == 0 else f"{duration}s"
            parts.append(f"*Duration:* `{escape_markdown(duration_label)}`")

        if event.get("block_error"):
            parts.append(f"*Action error:* `{escape_markdown(str(event['block_error']))}`")

        parts.append(f"*Message:* `{escape_markdown(str(event.get('message', '')) )}`")
        parts.append(f"*Timestamp:* `{escape_markdown(str(event.get('timestamp', '')) )}`")
        return "\n".join(parts)

    def notify(self, event: Dict[str, Any]) -> None:
        if not self.enabled:
            return

        message = self._format_message(event)
        payload = json.dumps(
            {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": self.parse_mode,
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")

        if self.dry_run:
            print(f"[DRY-RUN] Telegram alert to {self.chat_id}: {message}")
            return

        request = urllib.request.Request(self.api_url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
        except Exception as exc:
            print(f"Failed to send Telegram alert: {exc}")
