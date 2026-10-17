"""Framework-neutral request and response, so every adapter shares one gate."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


@dataclass
class Request:
    method: str
    path: str
    headers: Mapping[str, str]  # lowercased names
    query: str = ""
    scheme: str = "http"
    host: str = ""
    ip: str = ""


@dataclass
class Response:
    status: int
    headers: list = field(default_factory=list)  # [(name, value)]
    body: bytes = b""


@dataclass
class Decision:
    """response set: answer it and stop. Otherwise serve the page and add `headers`."""
    response: Response | None = None
    headers: list = field(default_factory=list)


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""
