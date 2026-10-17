"""Keccak-256 (the Ethereum variant, pad 0x01) for the MPP nonce binding.

Uses pycryptodome when installed; otherwise a small pure-Python fallback.
"""
from __future__ import annotations

try:  # pragma: no cover - exercised by whichever backend is installed
    from Crypto.Hash import keccak as _keccak
except Exception:  # pragma: no cover
    _keccak = None

_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_RATE = 136


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _f(st: list[int]) -> None:
    for rnd in range(24):
        bc = [st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20] for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rol(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
        t = st[1]
        for i in range(24):
            j = _PILN[i]
            bc0 = st[j]
            st[j] = _rol(t, _ROTC[i])
            t = bc0
        for j in range(0, 25, 5):
            row = st[j:j + 5]
            for i in range(5):
                st[j + i] = row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5]) & _MASK
        st[0] ^= _RC[rnd]


def _keccak256_pure(data: bytes) -> bytes:
    st = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), _RATE):
        block = padded[off:off + _RATE]
        for i in range(_RATE // 8):
            st[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def keccak256(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    if _keccak is not None:
        return _keccak.new(digest_bits=256, data=data).digest()
    return _keccak256_pure(data)


def keccak256_hex(data: bytes | str) -> str:
    return "0x" + keccak256(data).hex()
