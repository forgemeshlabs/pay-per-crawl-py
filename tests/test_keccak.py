import pytest

from forgemesh_pay_per_crawl.core import keccak
from forgemesh_pay_per_crawl.core.keccak import _keccak256_pure, keccak256_hex

VECTORS = [
    (b"", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"a" * 135, "0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),  # pad edge
    (b"a" * 136, "0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),  # exactly one block
    (b"a" * 137, "0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"),
    (b"xyz" * 100, "0xcc0b928a8fb33dca301e35d6070e6cccfda8a90b0ce76912018dd71168c42ad2"),  # multi-block
]


@pytest.mark.parametrize("data,expected", VECTORS)
def test_vectors_default_backend(data, expected):
    assert keccak256_hex(data) == expected


@pytest.mark.parametrize("data,expected", VECTORS)
def test_vectors_pure_fallback(data, expected):
    assert "0x" + _keccak256_pure(data).hex() == expected


def test_str_input_and_backend_flag():
    assert keccak256_hex("abc") == VECTORS[1][1]
    assert keccak._keccak is not None  # pycryptodome is a declared dependency
