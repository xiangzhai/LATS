#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024-2026 LATS Project Authors
#
# SPDX-License-Identifier: GPL-2.0-only

"""Validate canonical TU payloads and member-page references in an AOT cache."""

from __future__ import annotations

import argparse
from collections import Counter
import struct
from pathlib import Path


PAGE_MAGIC = 0x66666666
MERGED_MAGIC = 0x77777777
TB_MAGIC = 0xFEFEFEFE
TU_REF_MAGIC = 0xFDFDFDFD
PAGE_PREFIX_SIZE = 16 + 4096
AOT_TU_MAX_PAGES = 8
AOT_TAIL_SIZE = 2072  # format37: includes REP INS/OUTS helpers
AOT_REL_SIZE = 32
SPLIT_SEARCH_BIT = 37
PUSHPOP_BIT = 47
TU_HEAD = struct.Struct("<IIIIQQII")
TU_REF = struct.Struct("<IIQqII")
AOT_BLOCK_SIZE = 176
MASK64 = (1 << 64) - 1
XXH_PRIME64_1 = 0x9E3779B185EBCA87
XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4F
XXH_PRIME64_3 = 0x165667B19E3779F9
XXH_PRIME64_4 = 0x85EBCA77C2B2AE63


def rol64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def xxh64_round(accumulator: int, value: int) -> int:
    return (rol64((accumulator + value * XXH_PRIME64_2) & MASK64, 31) *
            XXH_PRIME64_1) & MASK64


def xxh64_merge(accumulator: int, value: int) -> int:
    return ((accumulator ^ xxh64_round(0, value)) * XXH_PRIME64_1 +
            XXH_PRIME64_4) & MASK64


def page_fingerprint(guest_code: bytes | bytearray | memoryview) -> int:
    words = struct.unpack_from("<512Q", guest_code)
    values = [
        (1 + XXH_PRIME64_1 + XXH_PRIME64_2) & MASK64,
        (1 + XXH_PRIME64_2) & MASK64,
        1,
        (1 - XXH_PRIME64_1) & MASK64,
    ]
    for index in range(0, len(words), 4):
        for lane in range(4):
            values[lane] = xxh64_round(values[lane], words[index + lane])
    result = (rol64(values[0], 1) + rol64(values[1], 7) +
              rol64(values[2], 12) + rol64(values[3], 18)) & MASK64
    for value in values:
        result = xxh64_merge(result, value)
    result = (result + 4096) & MASK64
    result ^= result >> 33
    result = (result * XXH_PRIME64_2) & MASK64
    result ^= result >> 29
    result = (result * XXH_PRIME64_3) & MASK64
    return (result ^ (result >> 32)) & MASK64


def parse_cache_bytes(
    data: bytes | bytearray,
) -> tuple[int, int, int, int, int]:
    if len(data) < AOT_TAIL_SIZE:
        raise ValueError("truncated AOT tail")
    option_flags = struct.unpack_from("<Q", data, len(data) - AOT_TAIL_SIZE)[0]
    offset = 0
    page_count = 0
    tb_count = 0
    cross_page_count = 0
    max_tu_pages = 0
    cross_page_payloads: dict[int, tuple[tuple[int, int], ...]] = {}
    payload_count = 0
    references: list[tuple[int, int, int]] = []

    while offset + 16 <= len(data):
        magic, _page_hash, page_records, page_size = struct.unpack_from(
            "<IIIi", data, offset
        )
        if magic not in (PAGE_MAGIC, MERGED_MAGIC):
            break
        if page_size < PAGE_PREFIX_SIZE or offset + page_size > len(data):
            raise ValueError(f"invalid page record at {offset:#x}")

        record = offset + PAGE_PREFIX_SIZE
        page_end = offset + page_size
        container_fingerprint = None
        for _ in range(page_records):
            if record + 4 > page_end:
                raise ValueError(f"truncated TU record at {record:#x}")
            record_magic = struct.unpack_from("<I", data, record)[0]
            if record_magic == TU_REF_MAGIC:
                if record + TU_REF.size > page_end:
                    raise ValueError(f"truncated TU reference at {record:#x}")
                (_magic, ref_size, tu_id, anchor_delta,
                 reserved0, reserved1) = TU_REF.unpack_from(data, record)
                if (ref_size != TU_REF.size or not tu_id or
                        anchor_delta == -(1 << 63) or anchor_delta & 0xFFF or
                        reserved0 or reserved1):
                    raise ValueError(f"invalid TU reference at {record:#x}")
                if container_fingerprint is None:
                    container_fingerprint = page_fingerprint(memoryview(data)[
                        offset + 16:offset + PAGE_PREFIX_SIZE
                    ])
                references.append((tu_id, anchor_delta,
                                   container_fingerprint))
                record += TU_REF.size
                continue

            if record_magic != TB_MAGIC or record + TU_HEAD.size > page_end:
                raise ValueError(f"invalid TU payload at {record:#x}")
            (tb_magic, tu_size, tu_tbs, rel_count, first_pc, tu_id,
             tu_pages, reserved) = TU_HEAD.unpack_from(data, record)
            if (tb_magic != TB_MAGIC or not tu_id or not tu_tbs or
                    not 1 <= tu_pages <= AOT_TU_MAX_PAGES or reserved or
                    record + tu_size > page_end):
                raise ValueError(f"invalid TU header at {record:#x}")

            pages = record + TU_HEAD.size
            if pages + tu_pages * 16 > record + tu_size:
                raise ValueError(f"truncated TU pages at {record:#x}")
            dependencies = []
            previous_delta = None
            for page_id in range(tu_pages):
                delta, fingerprint = struct.unpack_from(
                    "<qQ", data, pages + page_id * 16
                )
                if (delta == -(1 << 63) or delta & 0xFFF or
                        previous_delta is not None and delta <= previous_delta):
                    raise ValueError(f"invalid TU dependency at {record:#x}")
                dependencies.append((delta, fingerprint))
                previous_delta = delta
            if not any(delta == 0 for delta, _ in dependencies):
                raise ValueError(f"TU anchor page missing at {record:#x}")

            blocks = pages + tu_pages * 16
            if blocks + tu_tbs * AOT_BLOCK_SIZE > record + tu_size:
                raise ValueError(f"truncated TU blocks at {record:#x}")
            dependency_deltas = {delta for delta, _ in dependencies}
            code_size = struct.unpack_from("<i", data, blocks + 136)[0]
            if code_size < 0:
                raise ValueError(f"negative TU code size at {record:#x}")
            expected_size = (TU_HEAD.size + tu_pages * 16 +
                             tu_tbs * AOT_BLOCK_SIZE + code_size +
                             rel_count * AOT_REL_SIZE)
            for block_id in range(tu_tbs):
                block = blocks + block_id * AOT_BLOCK_SIZE
                block_pc, _page0, page1 = struct.unpack_from(
                    "<QQQ", data, block)
                search_size = struct.unpack_from("<Q", data, block + 56)[0]
                icount = struct.unpack_from("<H", data, block + 158)[0]
                expected_size += (icount * 4 if option_flags &
                                  (1 << SPLIT_SEARCH_BIT) else search_size)
                if option_flags & (1 << PUSHPOP_BIT):
                    expected_size += icount * 4
                if block_id == 0 and block_pc != first_pc:
                    raise ValueError(f"TU entry mismatch at {record:#x}")
                page_delta = ((block_pc & ~0xFFF) -
                              (first_pc & ~0xFFF)) & ((1 << 64) - 1)
                if page_delta & (1 << 63):
                    page_delta -= 1 << 64
                if page_delta not in dependency_deltas:
                    raise ValueError(
                        f"TU block dependency missing at {record:#x}"
                    )
                if (page1 != (1 << 64) - 1 and
                        page_delta + 4096 not in dependency_deltas):
                    raise ValueError(
                        "TU block second-page dependency missing "
                        f"at {record:#x}"
                    )
            if expected_size != tu_size:
                raise ValueError(
                    f"TU payload size mismatch at {record:#x}: "
                    f"expected {expected_size}, got {tu_size}"
                )
            if tu_pages > 1:
                if tu_id in cross_page_payloads:
                    raise ValueError(
                        f"cross-page TU payload {tu_id:#x} is duplicated"
                    )
                cross_page_payloads[tu_id] = tuple(dependencies)
            payload_count += 1
            tb_count += tu_tbs
            cross_page_count += tu_pages > 1
            max_tu_pages = max(max_tu_pages, tu_pages)
            record += tu_size

        if record != page_end:
            raise ValueError(f"page payload mismatch at {offset:#x}")
        page_count += 1
        offset = page_end

    references_by_tu: dict[int, Counter[int]] = {}
    for (tu_id, anchor_delta, fingerprint), count in (
        Counter(references).items()
    ):
        references_by_tu.setdefault(tu_id, Counter())[
            (anchor_delta, fingerprint)
        ] = count

    for tu_id, dependencies in cross_page_payloads.items():
        expected = Counter(
            (-delta, fingerprint) for delta, fingerprint in dependencies
            if delta
        )
        actual = references_by_tu.pop(tu_id, Counter())
        if actual != expected:
            raise ValueError(
                f"TU {tu_id:#x} member references mismatch: "
                f"expected {dict(expected)}, got {dict(actual)}"
            )
    if references_by_tu:
        raise ValueError(
            f"dangling TU references: {sorted(references_by_tu)}"
        )

    return (page_count, payload_count, tb_count, cross_page_count,
            max_tu_pages)


def parse_cache(path: Path) -> tuple[int, int, int, int, int]:
    return parse_cache_bytes(path.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cache", type=Path)
    parser.add_argument("--require-cross-page", action="store_true")
    args = parser.parse_args()

    pages, tus, tbs, cross_page, max_tu_pages = parse_cache(args.cache)
    if args.require_cross_page and not cross_page:
        raise SystemExit("FAIL: cache contains no cross-page TU")
    print(
        f"PASS: {pages} pages, {tus} canonical TUs, {tbs} TBs, "
        f"{cross_page} cross-page TUs, max {max_tu_pages} pages/TU"
    )


if __name__ == "__main__":
    main()
