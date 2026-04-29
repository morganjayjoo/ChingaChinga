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
