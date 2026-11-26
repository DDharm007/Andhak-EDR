"""In-process asyncio pub/sub fan-out bus for live WebSocket streams."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Any

VALID_CHANNELS = ("telemetry", "alerts", "responses")


@dataclass(eq=False)
class Subscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    endpoint_id: str | None = None
    origin: str | None = None


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[str, set[Subscriber]] = {ch: set() for ch in VALID_CHANNELS}

    def subscribe(
        self,
        channel: str,
        loop: asyncio.AbstractEventLoop,
        endpoint_id: str | None = None,
        origin: str | None = None,
    ) -> Subscriber:
        sub = Subscriber(
            queue=asyncio.Queue(maxsize=256),
            loop=loop,
            endpoint_id=endpoint_id,
            origin=origin,
        )
        with self._lock:
            self._subs.setdefault(channel, set()).add(sub)
        return sub

    def unsubscribe(self, channel: str, sub: Subscriber) -> None:
        with self._lock:
            self._subs.get(channel, set()).discard(sub)

    def publish_sync(self, channel: str, frame: dict[str, Any]) -> int:
        with self._lock:
            targets = list(self._subs.get(channel, set()))
        delivered = 0
        ep_val = frame.get("endpoint_id") or frame.get("data", {}).get("endpoint_id")
        origin_val = frame.get("origin") or frame.get("data", {}).get("telemetry_origin")
        for sub in targets:
            if sub.endpoint_id and ep_val and sub.endpoint_id != ep_val:
                continue
            if sub.origin and origin_val and sub.origin != origin_val:
                continue
            if sub.loop.is_closed():
                continue

            def _deliver(target_q: asyncio.Queue[dict[str, Any]] = sub.queue) -> None:
                if target_q.full():
                    try:
                        target_q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                try:
                    target_q.put_nowait(frame)
                except asyncio.QueueFull:
                    pass

            try:
                sub.loop.call_soon_threadsafe(_deliver)
                delivered += 1
            except RuntimeError:
                pass
        return delivered

    def subscriber_counts(self) -> dict[str, int]:
        with self._lock:
            return {ch: len(s) for ch, s in self._subs.items()}


event_bus = EventBus()
