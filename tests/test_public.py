"""Public tests for the authenticated time synchronization module."""

import hashlib
import hmac
import struct

from ntpauth import (
    check_key_id,
    check_offset,
    packet_batch,
    parse_packet,
    verify_auth,
)

SECRET = b"public-test-secret"
MAGIC = b"NTP4"
NONCE = b"nonce001"
UTC_0400 = "2026-11-19T04:00:00Z"
UTC_0500 = "2026-11-19T05:00:00Z"
UTC_0400_EPOCH = 1795060800.0


def _stamp_bytes(value: str) -> bytes:
    return value.encode("ascii").ljust(24, b"\x00")


def _make_packet(
    *,
    key_id: int = 7,
    stamp: str = UTC_0400,
    sequence: int = 1,
    nonce: bytes = NONCE,
) -> bytes:
    signed = (
        MAGIC
        + bytes([4, 3, 0, 0])
        + struct.pack(">I", key_id)
        + _stamp_bytes(stamp)
        + struct.pack(">I", sequence)
        + nonce
    )
    assert len(signed) == 48
    auth = hmac.new(SECRET, signed, hashlib.sha256).digest()[:16]
    return signed + auth


def _state(**overrides: object) -> dict:
    state = {
        "last_timestamp": 0.0,
        "seen": set(),
        "offset": 0.0,
        "last_applied": None,
        "policy": {"max_abs": 5.0},
    }
    state.update(overrides)
    return state


def test_parse_packet_extracts_fields_and_utc_timestamp() -> None:
    raw = _make_packet()
    packet = parse_packet(raw)

    assert packet["key_id"] == 7
    assert packet["timestamp"] == UTC_0400_EPOCH
    assert packet["nonce"] == NONCE
    assert packet["auth"] == raw[48:64]


def test_check_key_id_rejects_untrusted_key() -> None:
    assert check_key_id(9, {1, 2}) is False
    assert check_key_id(2, {1, 2}) is True


def test_verify_auth_rejects_tampered_packet() -> None:
    tampered = bytearray(_make_packet())
    tampered[40] ^= 0x01
    packet = parse_packet(bytes(tampered))

    assert verify_auth(packet, SECRET) is False


def test_check_offset_enforces_policy_limit() -> None:
    policy = {"max_abs": 5.0}

    assert check_offset(1.5, policy) is True
    assert check_offset(120.0, policy) is False


def test_packet_batch_keeps_two_packets_independent() -> None:
    first = parse_packet(_make_packet(stamp=UTC_0400, sequence=1))
    first["offset"] = 0.5
    second = parse_packet(_make_packet(stamp=UTC_0500, sequence=2))
    second["offset"] = 2.5

    result = packet_batch([first, second], {7: SECRET}, _state())

    assert result["accepted"] == [first["timestamp"], second["timestamp"]]
    assert result["rejected"] == []
    assert result["state"]["offset"] == 2.5
    assert result["state"]["last_timestamp"] == second["timestamp"]