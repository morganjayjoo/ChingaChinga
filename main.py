"""
ChingaChinga — companion app for CoinCollectSSS
================================================

This is a single-file FastAPI service that can run on Windows without any manual
configuration. It provides:

- An "AI coin engine" that issues signed drop claims compatible with CoinCollectSSS.
- A small SQLite-backed profile & season cache (safe defaults, no external DB).
- A websocket stream for live drops and leaderboard ticks.
- A static file server for the 50C web UI (served from ../50C by default).

It is designed to be:
- Mainnet-safe (no custody, no secret exposure in responses).
- Operator-friendly (auto-generates an ECDSA signer key on first run and stores locally).

Quick start:
    python -m venv .venv
    .venv\\Scripts\\pip install -r requirements.txt
    .venv\\Scripts\\python app.py

Then open:
    http://127.0.0.1:8787/
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import string
import sys
import time
import traceback
import typing as t
from pathlib import Path

import requests
from eth_account import Account
from eth_utils import to_checksum_address
from fastapi import (
    BackgroundTasks,
    Body,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


# ============================================================
#                         CONFIG
# ============================================================


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "chinga.sqlite3"
SIGNER_PATH = DATA_DIR / "signer.json"
CONFIG_PATH = DATA_DIR / "config.json"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _unix_now() -> int:
    return int(time.time())


def _rand_handle() -> str:
    alphabet = string.ascii_letters + string.digits
    return "cc_" + "".join(secrets.choice(alphabet) for _ in range(18))


def _hash_handle(handle: str) -> str:
    return "0x" + hashlib.sha256(handle.encode("utf-8")).hexdigest()


def _json_dumps(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _clamp_int(v: int, lo: int, hi: int) -> int:
    return lo if v < lo else hi if v > hi else v


def _require(condition: bool, message: str, code: int = 400) -> None:
    if not condition:
        raise HTTPException(status_code=code, detail=message)


@dataclasses.dataclass(frozen=True)
class AppSettings:
    host: str = "127.0.0.1"
    port: int = 8787
    web_dir: Path = WORKSPACE_ROOT / "50C"
    cors_allow_all: bool = True
    # CoinCollectSSS EIP-712 domain pieces
    contract_name: str = "CoinCollectSSS"
    contract_version: str = "1.0.0"
    # Demo defaults (can be updated at runtime via API)
    chain_id: int = 1
    verifying_contract: str = "0x0000000000000000000000000000000000000000"


def load_settings() -> AppSettings:
    if CONFIG_PATH.exists():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            raw = {}
    else:
        raw = {}

    base = AppSettings()
    verifying_contract = raw.get("verifying_contract", base.verifying_contract)
    try:
        verifying_contract = to_checksum_address(verifying_contract)
    except Exception:
        verifying_contract = base.verifying_contract

    chain_id = raw.get("chain_id", base.chain_id)
    try:
        chain_id = int(chain_id)
    except Exception:
        chain_id = base.chain_id

    port = raw.get("port", base.port)
    try:
        port = int(port)
    except Exception:
        port = base.port

    return dataclasses.replace(
        base,
        port=port,
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )


SETTINGS = load_settings()


def save_settings(new_settings: AppSettings) -> None:
    payload = {
        "port": int(new_settings.port),
        "chain_id": int(new_settings.chain_id),
        "verifying_contract": str(new_settings.verifying_contract),
    }
    CONFIG_PATH.write_text(_json_dumps(payload), encoding="utf-8")


# ============================================================
#                         DB LAYER
# ============================================================

