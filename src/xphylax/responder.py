import asyncio
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Set


class UfwResponder:
    def __init__(
        self,
        enabled: bool = True,
        dry_run: bool = False,
        whitelist_ips: Optional[List[str]] = None,
        escalation_seconds: Optional[List[int]] = None,
    ) -> None:
        self.enabled = enabled
        self.dry_run = dry_run
        self.ufw_path = shutil.which("ufw")
        self.whitelist_ips: Set[str] = set(whitelist_ips or [])
        self.escalation_seconds = escalation_seconds or [3600, 86400, 0]
        self.blocked_ips: Set[str] = set()
        self.block_counts: Dict[str, int] = {}
        self.unblock_handles: Dict[str, asyncio.TimerHandle] = {}

    def _get_escalation_duration(self, ip: str) -> int:
        count = self.block_counts.get(ip, 0)
        index = max(0, min(count - 1, len(self.escalation_seconds) - 1))
        return self.escalation_seconds[index]

    def _schedule_unblock(self, ip: str, duration: int) -> None:
        if ip in self.unblock_handles:
            self.unblock_handles[ip].cancel()

        if duration <= 0:
            return

        loop = asyncio.get_event_loop()
        handle = loop.call_later(duration, self._unblock_ip, ip)
        self.unblock_handles[ip] = handle

    def _unblock_ip(self, ip: str) -> None:
        if ip not in self.blocked_ips:
            return

        command = [self.ufw_path or "ufw", "delete", "deny", "from", ip, "to", "any"]
        if self.dry_run:
            print(f"[DRY-RUN] Would remove UFW block for IP: {ip}")
        else:
            if self.ufw_path is None:
                print("Unable to remove UFW block because ufw is not installed.")
            else:
                try:
                    subprocess.run(command, check=True, capture_output=True, text=True)
                    print(f"Removed UFW block for IP {ip}")
                except subprocess.CalledProcessError as exc:
                    print(f"Failed to remove UFW block for IP {ip}: {exc.stderr.strip()}")

        self.blocked_ips.discard(ip)
        self.unblock_handles.pop(ip, None)

    def block_ip(self, ip: str, reason: str, dry_run: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        if dry_run is None:
            dry_run = self.dry_run

        if ip in self.whitelist_ips:
            print(f"Skipping whitelist IP {ip}.")
            return {"action": "skipped", "reason": "whitelisted", "ip": ip}

        count = self.block_counts.get(ip, 0) + 1
        self.block_counts[ip] = count
        duration = self._get_escalation_duration(ip)
        block_type = "permanent" if duration == 0 else f"{duration}s"

        if ip in self.blocked_ips and duration == 0:
            print(f"IP {ip} is already blocked permanently.")
            return {
                "action": "skipped",
                "reason": "already_permanent",
                "ip": ip,
                "tier": count,
                "duration": duration,
                "block_type": block_type,
            }

        if self.ufw_path is None and not dry_run:
            raise RuntimeError("ufw utility is not available on this system.")

        command = [self.ufw_path or "ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", f"xPhylax:{reason}:{count}"]
        if dry_run:
            print(f"[DRY-RUN] Would block IP: {ip} for {block_type} (tier {count}) reason: {reason}")
            self.blocked_ips.add(ip)
            if duration > 0:
                self._schedule_unblock(ip, duration)
            return {
                "action": "dry_run_block",
                "ip": ip,
                "tier": count,
                "duration": duration,
                "block_type": block_type,
            }

        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.blocked_ips.add(ip)
            print(f"Blocked IP {ip} via UFW for {block_type} (tier {count}) reason: {reason}")
            self._schedule_unblock(ip, duration)
            return {
                "action": "blocked",
                "ip": ip,
                "tier": count,
                "duration": duration,
                "block_type": block_type,
            }
        except subprocess.CalledProcessError as exc:
            print(f"Failed to block IP {ip}: {exc.stderr.strip()}")
            return {"action": "failed", "ip": ip, "error": exc.stderr.strip()}
