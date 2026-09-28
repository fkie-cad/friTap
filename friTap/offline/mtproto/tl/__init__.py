"""Schema-driven TL (Type Language) decoding for MTProto / Secret-Chat payloads.

The vendored TDLib schema lives in ``friTap/offline/mtproto/schema/``; see its
``SOURCE.txt`` for provenance and licence.
"""

from .decoder import TlLimits, decode_tl, decode_tl_cached
from .nodes import (
    TlField,
    TlNode,
    TlRaw,
    TlVector,
    iter_nodes,
    iter_raws,
    stopped_early,
    to_jsonable,
)
from .registry import load_schema, name_for_id
from .schema import TlCombinator, TlParam, TlSchema, parse_tl
from .users import extract_users, link_secret_chat_peer, merge_user_directory

__all__ = [
    "TlCombinator",
    "TlField",
    "TlLimits",
    "TlNode",
    "TlParam",
    "TlRaw",
    "TlSchema",
    "TlVector",
    "decode_tl",
    "decode_tl_cached",
    "extract_users",
    "iter_nodes",
    "iter_raws",
    "link_secret_chat_peer",
    "load_schema",
    "merge_user_directory",
    "name_for_id",
    "parse_tl",
    "stopped_early",
    "to_jsonable",
]
