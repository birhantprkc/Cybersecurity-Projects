"""
©AngelaMos | 2026
store.py
"""

import json
from pathlib import Path
from typing import Protocol

from rveng.engine import patch
from rveng.engine.challenge import (
    Challenge,
    FoundValue,
    IdentifiedSymbol,
    PatchedBytes,
)

MANIFEST = "challenge.json"
TARGET = "target"
SOURCE = "source.c"

CAT_FOUND_VALUE = "found_value"
CAT_IDENTIFIED_SYMBOL = "identified_symbol"
CAT_PATCHED_BYTES = "patched_bytes"


class ChallengeError(ValueError):
    """
    Raised when a challenge asset directory is malformed
    """


def _build_answer(spec: dict, binary: bytes):
    category = spec.get("category")
    if category == CAT_FOUND_VALUE:
        return FoundValue(spec["expected"])
    if category == CAT_IDENTIFIED_SYMBOL:
        return IdentifiedSymbol(spec["name"])
    if category == CAT_PATCHED_BYTES:
        offset = spec["offset"]
        replacement = bytes.fromhex(spec["patch"])
        known_good = patch.apply(binary, offset, replacement)
        return PatchedBytes(offset=offset, known_good=known_good)
    raise ChallengeError(f"unknown answer category: {category}")


def load_challenge(directory: Path) -> Challenge:
    """
    Load one challenge from its asset directory
    """
    manifest_path = directory / MANIFEST
    if not manifest_path.is_file():
        raise ChallengeError(f"no manifest in {directory}")
    manifest = json.loads(manifest_path.read_text())
    binary = (directory / TARGET).read_bytes()
    source = (directory / SOURCE).read_text()
    return Challenge(
        id=manifest["id"],
        module=manifest["module"],
        title=manifest["title"],
        mission=manifest["mission"],
        binary=binary,
        source=source,
        answer=_build_answer(manifest["answer"], binary),
    )


class ChallengeStore:
    """
    An in-memory registry of loaded challenges keyed by id
    """

    def __init__(self, challenges: list[Challenge]):
        self._by_id = {c.id: c for c in challenges}

    def list(self) -> list[Challenge]:
        return sorted(self._by_id.values(), key=lambda c: c.id)

    def get(self, challenge_id: str) -> Challenge | None:
        return self._by_id.get(challenge_id)


def load_store(root: Path) -> ChallengeStore:
    """
    Load every challenge directory under root into a store
    """
    challenges = []
    for directory in sorted(root.iterdir()):
        if (directory / MANIFEST).is_file():
            challenges.append(load_challenge(directory))
    return ChallengeStore(challenges)


class ProgressStore(Protocol):
    """
    Persistence boundary for solved-challenge tracking
    """

    def mark_solved(self, session: str, challenge_id: str) -> None:
        ...

    def solved(self, session: str) -> set[str]:
        ...


class InMemoryProgress:
    """
    A process-local progress store, swapped for SQLite in M4
    """

    def __init__(self):
        self._solved: dict[str, set[str]] = {}

    def mark_solved(self, session: str, challenge_id: str) -> None:
        self._solved.setdefault(session, set()).add(challenge_id)

    def solved(self, session: str) -> set[str]:
        return set(self._solved.get(session, set()))
