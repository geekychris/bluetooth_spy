"""Brute-force common-checksum detection over captured packets.

Given N payloads of the same length L, try every (range, position, algorithm) tuple:
  - range: bytes [s..e) used as input to the checksum
  - position: which byte (or two bytes) holds the result
  - algorithm: sum, xor, CRC-8, CRC-16-CCITT, CRC-16-XMODEM, CRC-16-MODBUS

Report any (s, e, pos, algo) where every payload satisfies algo(payload[s:e]) == payload[pos].

This is a "needle in haystack" but for typical BLE payloads (8-30 bytes), the search
space is small enough to brute force in milliseconds. Once a candidate emerges, you
have a high-confidence hypothesis you can immediately verify by mutating + replaying.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable


@dataclass
class ChecksumHypothesis:
    algo: str          # 'sum8', 'xor8', 'crc8', 'crc16_ccitt', 'crc16_xmodem', 'crc16_modbus'
    input_start: int   # byte offset (inclusive)
    input_end: int     # byte offset (exclusive)
    output_offset: int # byte offset where the checksum byte(s) live
    output_size: int   # 1 or 2 bytes
    sample_count: int  # number of payloads that satisfied this hypothesis (all of them)


# --- algorithms ---

def sum8(b: bytes) -> int:
    return sum(b) & 0xFF


def xor8(b: bytes) -> int:
    x = 0
    for c in b:
        x ^= c
    return x


def _crc8(b: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    """Standard CRC-8 (poly 0x07, init 0x00) — used in some 1-Wire variants and BLE devices."""
    crc = init
    for byte in b:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _crc16(b: bytes, poly: int, init: int) -> int:
    crc = init
    for byte in b:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc16_ccitt_false(b: bytes) -> int:
    return _crc16(b, poly=0x1021, init=0xFFFF)


def crc16_xmodem(b: bytes) -> int:
    return _crc16(b, poly=0x1021, init=0x0000)


def crc16_modbus(b: bytes) -> int:
    """CRC-16-MODBUS — poly 0xA001 with reflected input. Most common in smart home gear."""
    crc = 0xFFFF
    for byte in b:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


ALGOS_8BIT: list[tuple[str, Callable[[bytes], int]]] = [
    ("sum8", sum8),
    ("xor8", xor8),
    ("crc8", _crc8),
]

ALGOS_16BIT: list[tuple[str, Callable[[bytes], int]]] = [
    ("crc16_ccitt_false", crc16_ccitt_false),
    ("crc16_xmodem", crc16_xmodem),
    ("crc16_modbus", crc16_modbus),
]


# --- search ---


def find_checksums(payloads: list[bytes], *, max_results: int = 8) -> list[ChecksumHypothesis]:
    """Find every (range, position, algorithm) tuple that holds across all payloads.

    Constraints:
      - All payloads must share the same length (we pre-filter to the most common length).
      - We only try ranges/positions where input and output don't overlap.

    Returns at most `max_results` hypotheses sorted by input range size (longer ranges win
    because they're harder to satisfy by chance).
    """
    if not payloads:
        return []
    # Restrict to the most common payload length — mixing sizes is meaningless here.
    from collections import Counter
    lengths = Counter(len(p) for p in payloads)
    target_len, _ = lengths.most_common(1)[0]
    payloads = [p for p in payloads if len(p) == target_len]
    if len(payloads) < 2 or target_len < 2:
        return []

    hypotheses: list[ChecksumHypothesis] = []

    # 1-byte checksum
    for algo_name, algo in ALGOS_8BIT:
        for s in range(0, target_len - 1):
            for e in range(s + 1, target_len):
                for pos in range(target_len):
                    if s <= pos < e:
                        continue  # output can't be inside input
                    if all(algo(p[s:e]) == p[pos] for p in payloads):
                        hypotheses.append(ChecksumHypothesis(
                            algo=algo_name, input_start=s, input_end=e,
                            output_offset=pos, output_size=1, sample_count=len(payloads),
                        ))

    # 2-byte checksum (little-endian; most BLE protocols use LE)
    if target_len >= 3:
        for algo_name, algo in ALGOS_16BIT:
            for s in range(0, target_len - 1):
                for e in range(s + 1, target_len):
                    for pos in range(target_len - 1):
                        if s <= pos < e or s <= pos + 1 < e:
                            continue
                        if all(
                            struct.unpack("<H", p[pos:pos+2])[0] == algo(p[s:e])
                            for p in payloads
                        ):
                            hypotheses.append(ChecksumHypothesis(
                                algo=algo_name + "_le", input_start=s, input_end=e,
                                output_offset=pos, output_size=2, sample_count=len(payloads),
                            ))

    # Sort by input range size descending (bigger ranges = stronger hypothesis)
    hypotheses.sort(key=lambda h: (-(h.input_end - h.input_start), h.input_start))
    return hypotheses[:max_results]
