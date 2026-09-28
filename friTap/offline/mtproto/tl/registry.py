"""Loads the vendored TL schemas (``friTap/offline/mtproto/schema/``) per domain.

Two domains exist, each a precedence-ordered stack of ``.tl`` files (the first
file defining an id wins):

* ``"mtproto"`` - cloud traffic: ``mtproto_api.tl`` > ``mtproto_core.tl`` >
  ``telegram_api.tl`` > ``aliases.tl``;
* ``"secret"``  - Secret-Chat (end-to-end) payloads: ``secret_api.tl`` >
  ``telegram_api.tl`` > ``aliases.tl``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

from .schema import TlSchema, parse_tl

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"

DOMAIN_FILES: Dict[str, Tuple[str, ...]] = {
    "mtproto": ("mtproto_api.tl", "mtproto_core.tl", "telegram_api.tl", "aliases.tl"),
    "secret": ("secret_api.tl", "telegram_api.tl", "aliases.tl"),
}


@lru_cache(maxsize=None)
def _parse_file(filename: str) -> TlSchema:
    return parse_tl((SCHEMA_DIR / filename).read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def load_schema(domain: str = "mtproto") -> TlSchema:
    """The merged schema of *domain* (``"mtproto"`` or ``"secret"``).

    Raises ``ValueError`` for an unknown domain.
    """
    try:
        files = DOMAIN_FILES[domain]
    except KeyError:
        raise ValueError(f"unknown TL domain {domain!r}") from None
    merged = TlSchema()
    for filename in files:
        merged.merge(_parse_file(filename))
    return merged


def name_for_id(ctor_id: int, domain: str = "mtproto") -> Optional[str]:
    """Schema name of constructor/function *ctor_id* in *domain*, else ``None``."""
    return load_schema(domain).name_for_id(ctor_id)
