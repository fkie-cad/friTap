"""Matching spawned mobile processes against the packages friTap gates.

On Android/iOS a spawn's identifier is a package name, optionally followed by
``:<process>`` for a secondary process (e.g. ``com.example.app:service``).
"""

from typing import Iterable, Optional

PROCESS_NAME_SEPARATOR = ":"


def spawn_matches_packages(identifier: Optional[str], packages: Optional[Iterable[str]]) -> bool:
    """True iff *identifier* is one of *packages* or a ``<pkg>:<process>`` of one.

    A plain prefix does not match: ``com.foo.barbaz`` is not ``com.foo.bar``.
    """
    if not identifier:
        return False
    return any(
        identifier == pkg or identifier.startswith(pkg + PROCESS_NAME_SEPARATOR)
        for pkg in (packages or ())
        if pkg
    )
