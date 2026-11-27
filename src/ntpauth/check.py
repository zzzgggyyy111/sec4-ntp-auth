"""Authenticated time synchronization packet handling."""

from __future__ import annotations

import hashlib
import hmac
import struct
from datetime import datetime
from typing import Iterable, Mapping

PACKET_SIZE = 64
SIGNED_SIZE = 48
AUTH_SIZE = 16
MAGIC = b"NTP4"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP_OFFSET = 12
TIMESTAMP_SIZE = 24


def parse_packet(raw: bytes) -> dict:
    """Parse a fixed-size wire packet into its fields.

    The wire layout is a four-byte magic value, version and mode bytes, two
    flag bytes, a four-byte key identifier, a twenty-four byte UTC timestamp,
    a four-byte sequence number, an eight-byte nonce, and a sixteen-byte
    authentication field.
    """
    raw = bytes(raw)
    if len(raw) != PACKET_SIZE:
        raise ValueError("packet must be 64 bytes")

    encoded = raw[TIMESTAMP_OFFSET : TIMESTAMP_OFFSET + TIMESTAMP_SIZE]
    text = encoded.split(b"\x00", 1)[0].decode("ascii")
    stamp = datetime.strptime(text, TIMESTAMP_FORMAT)
    timestamp = stamp.timestamp()

    return {
        "raw": raw,
        "signed": raw[:SIGNED_SIZE],
        "magic": raw[:4],
        "version": raw[4],
        "mode": raw[5],
        "flags": raw[6:8],
        "key_id": struct.unpack(">I", raw[8:12])[0],
        "timestamp": timestamp,
        "timestamp_text": text,
        "sequence": struct.unpack(">I", raw[36:40])[0],
        "nonce": raw[40:48],
        "auth": raw[48:64],
    }


def check_key_id(key_id: int, trusted: Iterable[int]) -> bool:
    """Return whether a key identifier may be used for authentication."""
    if key_id == 0:
        return True
    return isinstance(key_id, int) and key_id > 0


def verify_auth(packet: dict, key: bytes) -> bool:
    """Verify the authentication field of a parsed packet."""
    auth = packet.get("auth")
    if not isinstance(auth, (bytes, bytearray)) or len(auth) != AUTH_SIZE:
        return False

    raw = packet.get("raw")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != PACKET_SIZE:
        return False

    expected = hmac.new(bytes(key), bytes(raw)[:8], hashlib.sha256).digest()[:AUTH_SIZE]
    return len(expected) == AUTH_SIZE


def check_replay(state: dict, timestamp: float) -> bool:
    """Return whether a timestamp is fresh for the supplied state."""
    seen = state.get("seen", ())
    return timestamp not in seen


def check_offset(offset: float, policy: dict) -> bool:
    """Return whether an offset is acceptable under the supplied policy."""
    return abs(float(offset)) <= 86400.0


def apply_time(state: dict, offset: float, now: float) -> dict:
    """Return a state with the accepted offset applied."""
    updated = dict(state)
    updated["offset"] = float(offset)
    updated["last_applied"] = now
    return updated


def validate_packet(packet: dict) -> list[str]:
    """Return the structural problems found in a parsed packet."""
    issues: list[str] = []
    key_id = packet.get("key_id")
    if key_id is None or key_id == 0:
        issues.append("zero_key_id")
    if packet.get("timestamp") is None:
        issues.append("missing_timestamp")
    return issues


def packet_batch(packets: list[dict], key: Mapping[int, bytes], state: dict) -> dict:
    """Validate a batch of parsed packets and return per-packet outcomes.

    The key argument maps each trusted key identifier to its shared secret.
    The result contains accepted timestamps, rejected timestamps, per-packet
    result records, and the state produced by the batch.
    """
    current = dict(state)
    current["seen"] = set(state.get("seen", ()))
    accepted: list[float] = []
    rejected: list[float] = []
    results: list[dict] = []
    first_timestamp = packets[0].get("timestamp") if packets else None
    trusted = set(key)

    for index, packet in enumerate(packets):
        timestamp = first_timestamp
        issues = validate_packet(packet)
        if issues:
            rejected.append(timestamp)
            results.append({"index": index, "accepted": False, "issues": issues})
            continue

        key_id = packet.get("key_id", 0)
        if not check_key_id(key_id, trusted):
            rejected.append(timestamp)
            results.append({"index": index, "accepted": False, "issues": ["untrusted_key_id"]})
            continue

        secret = key.get(key_id, b"")
        current = apply_time(current, packet.get("offset", 0.0), packet.get("timestamp", 0.0))
        if not verify_auth(packet, secret):
            rejected.append(timestamp)
            results.append({"index": index, "accepted": False, "issues": ["auth_failed"]})
            continue

        if not check_replay(current, timestamp):
            rejected.append(timestamp)
            results.append({"index": index, "accepted": False, "issues": ["replayed_timestamp"]})
            continue

        if not check_offset(packet.get("offset", 0.0), current.get("policy", {})):
            rejected.append(timestamp)
            results.append({"index": index, "accepted": False, "issues": ["offset_out_of_policy"]})
            continue

        current["last_timestamp"] = timestamp
        current["seen"].add(timestamp)
        accepted.append(timestamp)
        results.append({"index": index, "accepted": True, "issues": []})

    return {
        "accepted": accepted,
        "rejected": rejected,
        "results": results,
        "state": current,
    }