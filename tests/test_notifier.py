from xphylax.notifier import TelegramNotifier, load_telegram_credentials


def test_load_telegram_credentials_from_xphylax_conf(tmp_path, monkeypatch):
    config_path = tmp_path / "xphylax.conf"
    config_path.write_text(
        """
# comments are ignored
BOT_TOKEN="token-value"
CHAT_ID='chat-value'
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("BOT_TOKEN", raising=False)
    monkeypatch.delenv("CHAT_ID", raising=False)

    credentials = load_telegram_credentials(str(config_path))

    assert credentials == {"bot_token": "token-value", "chat_id": "chat-value"}


def test_telegram_notifier_formats_alert_with_response_details():
    notifier = TelegramNotifier("token", "chat", enabled=True, dry_run=True)

    message = notifier._format_message(
        {
            "timestamp": "2026-05-12T10:00:00Z",
            "source": "auth",
            "path": "/var/log/auth.log",
            "rule_id": "ssh-auth-failure",
            "rule_name": "SSH authentication failure",
            "rule_source": "MITRE ATT&CK",
            "rule_reference": "T1110: Brute Force",
            "severity": "high",
            "tags": ["ssh", "auth"],
            "ip": "203.0.113.10",
            "block_action": "dry_run_block",
            "block_tier": 1,
            "block_duration": 3600,
            "message": "Failed password for invalid user admin from 203.0.113.10",
        }
    )

    assert "*xPhylax Alert*" in message
    assert "*Rule ID:* `ssh\\-auth\\-failure`" in message
    assert "*IP:* `203\\.0\\.113\\.10`" in message
    assert "*Action:* `dry\\_run\\_block`" in message
    assert "*Duration:* `3600s`" in message
