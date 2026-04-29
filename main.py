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


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


DB = db_connect()


def db_init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS players (
            address TEXT PRIMARY KEY,
            handle TEXT NOT NULL,
            handle_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS seasons (
            season_id INTEGER PRIMARY KEY,
            start_at INTEGER NOT NULL,
            end_at INTEGER NOT NULL,
            entry_fee_wei TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS drops (
            drop_id TEXT PRIMARY KEY,
            season_id INTEGER NOT NULL,
            address TEXT NOT NULL,
            coin_type INTEGER NOT NULL,
            amount TEXT NOT NULL,
            deadline INTEGER NOT NULL,
            nonce TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS counters (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        """
    )
    conn.commit()


db_init(DB)


def db_get_counter(key: str) -> int:
    row = DB.execute("SELECT value FROM counters WHERE key = ?", (key,)).fetchone()
    if not row:
        DB.execute("INSERT OR REPLACE INTO counters(key, value) VALUES(?, ?)", (key, 0))
        DB.commit()
        return 0
    return int(row["value"])


def db_inc_counter(key: str, by: int = 1) -> int:
    cur = db_get_counter(key)
    nxt = cur + by
    DB.execute("INSERT OR REPLACE INTO counters(key, value) VALUES(?, ?)", (key, nxt))
    DB.commit()
    return nxt


def db_upsert_player(address: str, handle: str) -> dict:
    handle_hash = _hash_handle(handle)
    now = _unix_now()
    DB.execute(
        "INSERT OR REPLACE INTO players(address, handle, handle_hash, created_at) VALUES(?, ?, ?, COALESCE((SELECT created_at FROM players WHERE address=?), ?))",
        (address, handle, handle_hash, address, now),
    )
    DB.commit()
    return {"address": address, "handle": handle, "handle_hash": handle_hash, "created_at": now}


def db_get_player(address: str) -> dict | None:
    row = DB.execute("SELECT * FROM players WHERE address = ?", (address,)).fetchone()
    if not row:
        return None
    return dict(row)


def db_list_players(limit: int = 200) -> list[dict]:
    limit = _clamp_int(limit, 1, 2000)
    rows = DB.execute("SELECT * FROM players ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def db_set_season(season_id: int, start_at: int, end_at: int, entry_fee_wei: int) -> dict:
    now = _unix_now()
    DB.execute(
        "INSERT OR REPLACE INTO seasons(season_id, start_at, end_at, entry_fee_wei, created_at) VALUES(?, ?, ?, ?, ?)",
        (season_id, start_at, end_at, str(entry_fee_wei), now),
    )
    DB.commit()
    return {
        "season_id": int(season_id),
        "start_at": int(start_at),
        "end_at": int(end_at),
        "entry_fee_wei": str(entry_fee_wei),
        "created_at": now,
    }


def db_get_season(season_id: int) -> dict | None:
    row = DB.execute("SELECT * FROM seasons WHERE season_id = ?", (season_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["season_id"] = int(d["season_id"])
    d["start_at"] = int(d["start_at"])
    d["end_at"] = int(d["end_at"])
    return d


def db_latest_season() -> dict | None:
    row = DB.execute("SELECT * FROM seasons ORDER BY season_id DESC LIMIT 1").fetchone()
    if not row:
        return None
    d = dict(row)
    d["season_id"] = int(d["season_id"])
    d["start_at"] = int(d["start_at"])
    d["end_at"] = int(d["end_at"])
    return d


def db_add_drop(
    drop_id: str,
    season_id: int,
    address: str,
    coin_type: int,
    amount: int,
    deadline: int,
    nonce: int,
) -> dict:
    now = _unix_now()
    DB.execute(
        "INSERT OR REPLACE INTO drops(drop_id, season_id, address, coin_type, amount, deadline, nonce, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        (drop_id, int(season_id), address, int(coin_type), str(amount), int(deadline), str(nonce), now),
    )
    DB.commit()
    return {
        "drop_id": drop_id,
        "season_id": int(season_id),
        "address": address,
        "coin_type": int(coin_type),
        "amount": str(amount),
        "deadline": int(deadline),
        "nonce": str(nonce),
        "created_at": now,
    }


def db_list_drops(address: str | None = None, limit: int = 200) -> list[dict]:
    limit = _clamp_int(limit, 1, 5000)
    if address:
        rows = DB.execute(
            "SELECT * FROM drops WHERE address = ? ORDER BY created_at DESC LIMIT ?",
            (address, limit),
        ).fetchall()
    else:
        rows = DB.execute("SELECT * FROM drops ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ============================================================
#                      SIGNER / KEY MGMT
# ============================================================


class SignerState(t.TypedDict):
    address: str
    private_key: str
    created_at: int
    note: str


def _new_signer_state() -> SignerState:
    acct = Account.create(secrets.token_hex(32))
    return {
        "address": to_checksum_address(acct.address),
        "private_key": acct.key.hex(),
        "created_at": _unix_now(),
        "note": "Local operator signer for CoinCollectSSS EIP-712 drops.",
    }


def load_or_create_signer() -> SignerState:
    if SIGNER_PATH.exists():
        try:
            raw = json.loads(SIGNER_PATH.read_text(encoding="utf-8"))
            address = to_checksum_address(raw["address"])
            pk = raw["private_key"]
            if not pk.startswith("0x"):
                pk = "0x" + pk
            _ = Account.from_key(pk)
            raw["address"] = address
            raw["private_key"] = pk
            return t.cast(SignerState, raw)
        except Exception:
            # fall through to recreate (keep the old file for forensics)
            backup = SIGNER_PATH.with_suffix(".broken.json")
            try:
                SIGNER_PATH.replace(backup)
            except Exception:
                pass

    st = _new_signer_state()
    SIGNER_PATH.write_text(_json_dumps(st), encoding="utf-8")
    return st


SIGNER = load_or_create_signer()
SIGNER_ACCOUNT = Account.from_key(SIGNER["private_key"])


# ============================================================
#                 EIP-712 DROP COMPAT HELPERS
# ============================================================


DOMAIN_SALT_HEX = "0xc8e2b8b7b2a8bb1f6e9a2f1ed94b0e3cfae01a31c4b2c6f0a2f36c88f3cc7a19"


def _keccak(data: bytes) -> bytes:
    # For EIP-712 compatibility we require Keccak-256 (not NIST sha3_256).
    import eth_hash.auto

    return eth_hash.auto.keccak(data)


def _to_bytes32_hex(b: bytes) -> str:
    return "0x" + b.hex().rjust(64, "0")


def _abi_encode_uint(value: int) -> bytes:
    return int(value).to_bytes(32, byteorder="big", signed=False)


def _abi_encode_address(addr: str) -> bytes:
    a = bytes.fromhex(addr[2:])
    return b"\x00" * 12 + a


def _abi_encode_bytes32(hex32: str) -> bytes:
    if not hex32.startswith("0x") or len(hex32) != 66:
        raise ValueError("bytes32 must be 0x + 64 hex chars")
    return bytes.fromhex(hex32[2:])


def _hash_string(s: str) -> bytes:
    return _keccak(s.encode("utf-8"))


EIP712_DOMAIN_TYPEHASH = _keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
)
DROP_TYPEHASH = _keccak(
    b"Drop(address player,uint32 seasonId,uint16 coinType,uint96 amount,uint64 deadline,bytes32 dropId,uint256 nonce)"
)


def domain_separator(chain_id: int, verifying_contract: str) -> bytes:
    verifying_contract = to_checksum_address(verifying_contract)
    parts = (
        EIP712_DOMAIN_TYPEHASH,
        _hash_string(SETTINGS.contract_name),
        _hash_string(SETTINGS.contract_version),
        _abi_encode_uint(chain_id),
        _abi_encode_address(verifying_contract),
        _abi_encode_bytes32(DOMAIN_SALT_HEX),
    )
    return _keccak(b"".join(parts))


def hash_drop_struct(
    player: str,
    season_id: int,
    coin_type: int,
    amount: int,
    deadline: int,
    drop_id_hex32: str,
    nonce: int,
) -> bytes:
    player = to_checksum_address(player)
    if not (drop_id_hex32.startswith("0x") and len(drop_id_hex32) == 66):
        raise ValueError("dropId must be bytes32 hex")
    parts = (
        DROP_TYPEHASH,
        _abi_encode_address(player),
        _abi_encode_uint(season_id),
        _abi_encode_uint(coin_type),
        _abi_encode_uint(amount),
        _abi_encode_uint(deadline),
        _abi_encode_bytes32(drop_id_hex32),
        _abi_encode_uint(nonce),
    )
    return _keccak(b"".join(parts))


def eip712_digest(chain_id: int, verifying_contract: str, struct_hash: bytes) -> bytes:
    ds = domain_separator(chain_id, verifying_contract)
    return _keccak(b"\x19\x01" + ds + struct_hash)


def sign_digest(digest: bytes) -> str:
    # IMPORTANT: CoinCollectSSS expects ECDSA over the raw EIP-712 digest (no personal_sign prefix).
    # eth-account exposes this via LocalAccount._sign_hash (stable in practice across versions).
    sig = SIGNER_ACCOUNT._sign_hash(digest)  # pyright: ignore[reportPrivateUsage]
    return sig.signature.hex()


def random_drop_id(season_id: int, address: str, nonce: int) -> str:
    # produce bytes32 id; include some extra entropy and stable components
    seed = _json_dumps(
        {
            "season_id": int(season_id),
            "address": to_checksum_address(address),
            "nonce": str(nonce),
            "t": _unix_now(),
            "salt": secrets.token_hex(16),
        }
    ).encode("utf-8")
    return _to_bytes32_hex(_keccak(seed))


# ============================================================
#                     WEBSOCKET BROADCAST
# ============================================================


class WsHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def add(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: WebSocket) -> None:
        async with self._lock:
