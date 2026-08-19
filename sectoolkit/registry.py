"""A registry of file 'checks' that can be run automatically against a file.

Each module (hashing, entropy, file-type detection, etc.) registers one or
more checks here. The CLI's auto-analyze mode ('sectoolkit <file>') runs
every check whose `applies_to(filepath)` returns True, and reports what ran.

This design means adding a new analysis module later does NOT require
touching the CLI dispatch code — it just registers itself here.
"""
from dataclasses import dataclass
from typing import Callable, Any

_CHECKS: list["Check"] = []


@dataclass
class Check:
    name: str
    description: str
    applies_to: Callable[[str], bool]
    run: Callable[[str], Any]


def register_check(name: str, description: str, applies_to: Callable[[str], bool], run: Callable[[str], Any]) -> None:
    _CHECKS.append(Check(name=name, description=description, applies_to=applies_to, run=run))


def applicable_checks(filepath: str) -> list[Check]:
    return [c for c in _CHECKS if c.applies_to(filepath)]


def all_checks() -> list[Check]:
    return list(_CHECKS)


def clear_registry() -> None:
    """Test-only helper to reset the registry between test cases."""
    _CHECKS.clear()
