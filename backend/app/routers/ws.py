"""WebSocket endpoints for live telemetry, alerts/incidents, and response actions."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.db import utc_now_iso
from app.realtime.bus import event_bus

router = APIRouter(tags=["websockets"])


async def _stream_channel(
    websocket: WebSocket,
    channel: str,
    endpoint_id: str | None = None,
    origin: str | None = None,
) -> None:
    await websocket.accept()
    loop = asyncio.get_running_loop()
    sub = event_bus.subscribe(channel, loop, endpoint_id=endpoint_id, origin=origin)
    await websocket.send_json(
        {
            "type": "ws.connected",
            "channel": channel,
            "timestamp": utc_now_iso(),
            "filters": {"endpoint_id": endpoint_id, "origin": origin},
        }
    )

    async def _reader() -> None:
        while True:
            msg = await websocket.receive_text()
            if msg.strip().lower() in {"ping", '{"type":"ping"}'}:
                await websocket.send_json({"type": "pong", "timestamp": utc_now_iso()})

    reader_task = asyncio.create_task(_reader())
    try:
        while True:
            try:
                frame: dict[str, Any] = await asyncio.wait_for(sub.queue.get(), timeout=20.0)
                await websocket.send_json(frame)
            except TimeoutError:
                await websocket.send_json(
                    {"type": "ws.keepalive", "channel": channel, "timestamp": utc_now_iso()}
                )
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        reader_task.cancel()
        event_bus.unsubscribe(channel, sub)


@router.websocket("/ws/telemetry")
async def ws_telemetry(
    websocket: WebSocket,
    endpoint_id: str | None = None,
    origin: str | None = None,
) -> None:
    await _stream_channel(websocket, "telemetry", endpoint_id=endpoint_id, origin=origin)


@router.websocket("/ws/alerts")
async def ws_alerts(
    websocket: WebSocket,
    endpoint_id: str | None = None,
    origin: str | None = None,
) -> None:
    await _stream_channel(websocket, "alerts", endpoint_id=endpoint_id, origin=origin)


@router.websocket("/ws/responses")
async def ws_responses(
    websocket: WebSocket,
    endpoint_id: str | None = None,
    origin: str | None = None,
) -> None:
    await _stream_channel(websocket, "responses", endpoint_id=endpoint_id, origin=origin)
