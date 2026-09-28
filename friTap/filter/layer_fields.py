"""Per-protocol display-filter fields, declared as a spec table.

Each :class:`LayerFieldSpec` maps a filter field name (``mtproto.dc_id``,
``telegram.msg``, ``tls.sni`` ...) to a path inside the JSON-native layer dicts
produced by :meth:`friTap.flow.layers.ProtocolLayer.to_dict`. Because the same
dict shape is stored verbatim in a tap file's ``meta["layers"]``, one pure
function (:func:`extract_filter_attrs`) serves both live flows
(``[l.to_dict() for l in flow.layers]``) and replayed tap summaries.

Adding a protocol field means adding a row to :data:`LAYER_FIELD_SPECS`; no
evaluator code changes (open/closed).

Path syntax (see :func:`_walk`): dotted keys descend into mappings
(``envelope.session_id``) and a ``[]`` suffix fans out over a list
(``messages[].method``). Missing keys simply yield nothing.

A *union* spec (``telegram.method`` ...) stores nothing itself: it names the
base fields it unites, and :func:`lookup_attr` resolves it at query time.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field as _dc_field
from typing import Any, Optional

from friTap.filter.protocols import canonical_protocols

# Memory bounds: a flow can carry thousands of parsed messages, and bodies can
# be arbitrarily long. Values beyond these caps are dropped / truncated.
MAX_VALUES_PER_FIELD = 2000
MAX_STR_LEN = 4096

# The key under which a layer dict carries its protocol name, both in
# ``ProtocolLayer.to_dict()`` and in a tap file's ``meta["layers"]`` entries.
LAYER_NAME_KEY = "name"


@dataclass(frozen=True)
class LayerFieldSpec:
    """One filterable per-protocol field.

    Attributes:
        field: Lowercase filter name, ``<proto>.<field>``.
        layers: Layer names whose dicts are searched.
        path: Path inside each layer dict (``a.b``, ``x[].y``).
        value_type: ``"str"`` | ``"int"`` | ``"float"`` | ``"bool"``.
        description: One-line text for the generated filter help.
        zero_is_missing: Treat a numeric ``0`` as "absent" (for ids whose
            default ``0`` means unknown, e.g. ``dc_id`` / ``peer_id``).
        union_of: Base fields this field unites (``telegram.*``); a union
            spec is never extracted, only resolved by :func:`lookup_attr`.
        segments: *path* pre-split into ``(key, fan_out)`` steps.
    """

    field: str
    layers: tuple[str, ...]
    path: str
    value_type: str
    description: str = ""
    zero_is_missing: bool = False
    union_of: tuple[str, ...] = ()
    segments: tuple[tuple[str, bool], ...] = _dc_field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "segments", _split_path(self.path))


def _split_path(path: str) -> tuple[tuple[str, bool], ...]:
    """``"messages[].method"`` -> ``(("messages", True), ("method", False))``."""
    if not path:
        return ()
    return tuple((token[:-2], True) if token.endswith("[]") else (token, False)
                 for token in path.split("."))


def _spec(field: str, layers, path: str, value_type: str = "str",
          description: str = "", zero_is_missing: bool = False) -> LayerFieldSpec:
    """Compact constructor for the table below (``layers`` may be a single name)."""
    if isinstance(layers, str):
        layers = (layers,)
    return LayerFieldSpec(field, tuple(layers), path, value_type,
                          description, zero_is_missing)


def _union(field: str, members: tuple[str, ...], value_type: str = "str",
           description: str = "") -> LayerFieldSpec:
    """A field whose values are the union of the *members* base fields."""
    return LayerFieldSpec(field, (), "", value_type, description, union_of=members)


def _telegram_union(suffix: str) -> tuple[str, ...]:
    """The cloud (MTProto) and Secret-Chat base fields for ``telegram.<suffix>``."""
    return (f"mtproto.{suffix}", f"telegram_e2e.{suffix}")

LAYER_FIELD_SPECS: tuple[LayerFieldSpec, ...] = (
    # --- MTProto (Telegram cloud transport) --------------------------------
    _spec("mtproto.dc_id", "mtproto", "dc_id", "int", "Telegram data-center id", True),
    _spec("mtproto.auth_key_id", "mtproto", "auth_key_id", "str", "auth_key_id (hex) that decrypted the flow"),
    _spec("mtproto.transport", "mtproto", "transport", "str", "Transport framing (abridged, intermediate, ...)"),
    _spec("mtproto.obfuscated", "mtproto", "obfuscated", "bool", "Obfuscated2 transport in use"),
    _spec("mtproto.message_count", "mtproto", "message_count", "int", "Number of parsed messages"),
    _spec("mtproto.session_id", "mtproto", "envelope.session_id", "str", "Envelope session_id (hex)"),
    _spec("mtproto.msg_id", "mtproto", "envelope.msg_id", "str", "Envelope msg_id (hex)"),
    _spec("mtproto.seq_no", "mtproto", "envelope.seq_no", "int", "Envelope seq_no"),
    _spec("mtproto.salt", "mtproto", "envelope.salt", "str", "Envelope server salt (hex)"),
    _spec("mtproto.method", "mtproto", "messages[].method", "str", "TL method/constructor of a message"),
    _spec("mtproto.msg", "mtproto", "messages[].body", "str", "Decoded message body text"),
    _spec("mtproto.kind", "mtproto", "messages[].kind", "str", "Message kind (text, service, ...)"),
    _spec("mtproto.user_id", "mtproto", "messages[].user_id", "int", "User id of a message", True),
    _spec("mtproto.peer_id", "mtproto", "messages[].peer_id", "int", "Peer id of a message", True),
    _spec("mtproto.sender", "mtproto", "messages[].sender_id", "int", "Sender user id of a message", True),
    # --- Telegram (union of cloud MTProto + Secret Chats) ------------------
    _union("telegram.method", _telegram_union("method"), "str", "TL method (cloud or secret chat)"),
    _union("telegram.msg", _telegram_union("msg"), "str", "Message body (cloud or secret chat)"),
    _union("telegram.kind", _telegram_union("kind"), "str", "Message kind (cloud or secret chat)"),
    _union("telegram.peer_id", _telegram_union("peer_id"), "int", "Peer id (cloud or secret chat)"),
    _union("telegram.user_id", _telegram_union("user_id"), "int", "User id (cloud or secret chat)"),
    _union("telegram.sender", _telegram_union("sender"), "int", "Sender user id (cloud or secret chat)"),
    _union("telegram.chat_id", ("telegram_e2e.chat_id",), "int", "Secret-chat id"),
    _union("telegram.key_fingerprint", ("telegram_e2e.key_fingerprint",), "str",
           "Secret-chat key fingerprint (hex)"),
    # --- Telegram Secret Chats (end-to-end) --------------------------------
    _spec("telegram_e2e.chat_id", "telegram_e2e", "chat_id", "int", "Secret-chat id", True),
    _spec("telegram_e2e.key_fingerprint", "telegram_e2e", "key_fingerprint", "str", "Key fingerprint (hex)"),
    _spec("telegram_e2e.layer_version", "telegram_e2e", "layer_version", "int", "Secret-chat TL layer", True),
    _spec("telegram_e2e.origin", "telegram_e2e", "origin", "str", "decrypted / plaintext_hook"),
    _spec("telegram_e2e.method", "telegram_e2e", "messages[].method", "str", "TL method of a secret-chat message"),
    _spec("telegram_e2e.msg", "telegram_e2e", "messages[].body", "str", "Secret-chat message body"),
    _spec("telegram_e2e.kind", "telegram_e2e", "messages[].kind", "str", "Secret-chat message kind"),
    _spec("telegram_e2e.peer_id", "telegram_e2e", "messages[].peer_id", "int", "Peer id of a secret-chat message", True),
    _spec("telegram_e2e.user_id", "telegram_e2e", "messages[].user_id", "int", "User id of a secret-chat message", True),
    _spec("telegram_e2e.sender", "telegram_e2e", "messages[].sender_id", "int", "Sender user id of a secret-chat message", True),
    # --- Signal ------------------------------------------------------------
    _spec("signal.chat_type", "signal", "chat_type", "str", "one_to_one / group"),
    _spec("signal.identifier", "signal", "identifier", "str", "eph_pub (1:1) or auth_tag (group), hex"),
    _spec("signal.message_count", "signal", "message_count", "int", "Number of parsed messages"),
    _spec("signal.msg", "signal", "messages[].body", "str", "Decoded message body text"),
    _spec("signal.kind", "signal", "messages[].kind", "str", "Message kind"),
    _spec("signal.sender", "signal", "messages[].sender", "str", "Message sender"),
    _spec("signal.direction", "signal", "messages[].direction", "str", "Message direction"),
    # --- TLS / QUIC / SSH / IPsec / RC4 ------------------------------------
    _spec("tls.library", "tls", "library", "str", "TLS library that was hooked"),
    _spec("tls.version", "tls", "version", "str", "TLS version"),
    _spec("tls.sni", "tls", "sni", "str", "Server Name Indication"),
    _spec("tls.alpn", "tls", "alpn", "str", "Negotiated ALPN"),
    _spec("tls.cipher", "tls", "cipher", "str", "Cipher suite"),
    _spec("quic.version", "quic", "version", "str", "QUIC version"),
    _spec("quic.sni", "quic", "sni", "str", "Server Name Indication"),
    _spec("quic.alpn", "quic", "alpn", "str", "Negotiated ALPN"),
    _spec("quic.cipher", "quic", "cipher", "str", "Cipher suite"),
    _spec("quic.scid", "quic", "scid", "str", "Source connection id"),
    _spec("quic.dcid", "quic", "dcid", "str", "Destination connection id"),
    _spec("ssh.client_version", "ssh", "client_version", "str", "Client identification string"),
    _spec("ssh.server_version", "ssh", "server_version", "str", "Server identification string"),
    _spec("ssh.kex", "ssh", "kex", "str", "Key-exchange algorithm"),
    _spec("ssh.cipher", "ssh", "cipher", "str", "Cipher"),
    _spec("ssh.mac", "ssh", "mac", "str", "MAC algorithm"),
    _spec("ipsec.ike_version", "ipsec", "ike_version", "str", "IKE version"),
    _spec("ipsec.enc", "ipsec", "enc", "str", "Encryption algorithm"),
    _spec("ipsec.integ", "ipsec", "integ", "str", "Integrity algorithm"),
    _spec("ipsec.dh", "ipsec", "dh", "str", "Diffie-Hellman group"),
    _spec("rc4.source", "rc4", "source", "str", "Hook that recovered the RC4 key"),
    _spec("rc4.direction", "rc4", "direction", "str", "out / in / unknown"),
    _spec("rc4.key_len", "rc4", "key_len", "int", "RC4 key length in bytes", True),
    _spec("rc4.assoc", "rc4", "assoc", "str", "Association hint (thread id)"),
)

_SPECS_BY_NAME: dict[str, LayerFieldSpec] = {s.field: s for s in LAYER_FIELD_SPECS}

# Only base specs are extracted; union specs are resolved by lookup_attr().
_EXTRACTED_SPECS: tuple[LayerFieldSpec, ...] = tuple(
    s for s in LAYER_FIELD_SPECS if not s.union_of)


def _scalar_roots_by_layer() -> dict[str, tuple[str, ...]]:
    """Per layer, the non-fan-out top-level attributes the extracted specs read."""
    roots: dict[str, dict[str, None]] = {}
    for spec in _EXTRACTED_SPECS:
        root, fan_out = spec.segments[0]
        if fan_out:
            continue
        for layer_name in spec.layers:
            roots.setdefault(layer_name, {})[root] = None
    return {name: tuple(attrs) for name, attrs in roots.items()}


_SCALAR_ROOTS_BY_LAYER = _scalar_roots_by_layer()

# The union field whose values form a flow's TL methods.
_METHOD_FIELD = "telegram.method"


def layer_field_spec(name: str) -> Optional[LayerFieldSpec]:
    """Return the spec for *name* (case-insensitive), or ``None``."""
    if not isinstance(name, str):
        return None
    return _SPECS_BY_NAME.get(name.strip().lower())


def layer_field_names() -> list[str]:
    """All per-protocol filter field names, in table order."""
    return [s.field for s in LAYER_FIELD_SPECS]


# ---------------------------------------------------------------------------
# Path walking and value normalization
# ---------------------------------------------------------------------------

def _step(node: Any, key: str, fan_out: bool) -> list[Any]:
    """Apply one pre-split path step (``key`` or ``key[]``) to *node*."""
    if key:
        if not isinstance(node, (dict, Mapping)) or key not in node:
            return []
        node = node[key]
    if not fan_out:
        return [node]
    if isinstance(node, (list, tuple)):
        return list(node[:MAX_VALUES_PER_FIELD])
    return []


def _walk(obj: Any, segments: tuple[tuple[str, bool], ...]) -> list[Any]:
    """Resolve pre-split path *segments* against *obj*, returning every value.

    ``a.b`` descends into nested mappings; ``x[]`` fans out over a list, so
    ``messages[].method`` yields one value per message. Missing keys and
    non-list fan-out targets contribute nothing (never raises on shape).
    """
    nodes = [obj]
    for key, fan_out in segments:
        nodes = [hit for node in nodes for hit in _step(node, key, fan_out)]
        if not nodes:
            break
    return nodes


def _to_str(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = bytes(value).hex()
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    return text[:MAX_STR_LEN]


def _to_int(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    for base in (0, 10):  # 0: "0x1f"/"42"; 10: leading-zero decimals ("010")
        try:
            return int(text, base)
        except (TypeError, ValueError):
            continue
    return _to_str(value)


def _to_float(value: Any) -> Any:
    try:
        return float(value)
    except (TypeError, ValueError):
        return _to_str(value)


def _to_bool(value: Any) -> Any:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no", ""):
            return False
        return _to_str(value)
    return bool(value)


def _normalize(value: Any, spec: LayerFieldSpec) -> Any:
    """Coerce one raw value to a filterable scalar, or ``None`` to drop it."""
    if value is None or value == "" or isinstance(value, (Mapping, list, tuple, set)):
        return None
    if spec.zero_is_missing and not isinstance(value, bool) and value == 0:
        return None
    if spec.value_type == "int":
        return _to_int(value)
    if spec.value_type == "float":
        return _to_float(value)
    if spec.value_type == "bool":
        return _to_bool(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return _to_str(value)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _layer_name(layer_dict: Any) -> str:
    if not isinstance(layer_dict, Mapping):
        return ""
    name = layer_dict.get(LAYER_NAME_KEY, "")
    return name.lower() if isinstance(name, str) else ""


def _group_by_name(layer_dicts: Iterable[Mapping]) -> dict[str, list[Mapping]]:
    grouped: dict[str, list[Mapping]] = {}
    try:
        for layer_dict in layer_dicts or ():
            name = _layer_name(layer_dict)
            if name:
                grouped.setdefault(name, []).append(layer_dict)
    except Exception:
        pass  # a broken iterable yields whatever was grouped so far
    return grouped


def _collect(spec: LayerFieldSpec, grouped: dict[str, list[Mapping]]) -> tuple:
    """Deduped (order-preserving), capped values of *spec* across its layers."""
    values: dict = {}
    for layer_name in spec.layers:
        for layer_dict in grouped.get(layer_name, ()):
            for raw in _walk(layer_dict, spec.segments):
                value = _normalize(raw, spec)
                if value is None:
                    continue
                values[value] = None
                if len(values) >= MAX_VALUES_PER_FIELD:
                    return tuple(values)
    return tuple(values)


def extract_filter_attrs(layer_dicts: Iterable[Mapping]) -> dict[str, tuple]:
    """Compute every per-protocol filter attribute from layer dicts.

    *layer_dicts* are ``ProtocolLayer.to_dict()`` outputs or a tap file's
    ``meta["layers"]`` entries (identical shape; the protocol name is under
    ``"name"``). Returns ``{field: (value, ...)}`` holding only non-empty
    tuples. Never raises: malformed dicts/values are skipped.
    """
    grouped = _group_by_name(layer_dicts)
    attrs: dict[str, tuple] = {}
    if not grouped:
        return attrs
    for spec in _EXTRACTED_SPECS:
        try:
            values = _collect(spec, grouped)
        except Exception:
            continue
        if values:
            attrs[spec.field] = values
    return attrs


def extract_filter_attrs_from_flow(flow: Any) -> dict[str, tuple]:
    """:func:`extract_filter_attrs` over ``flow.layers`` (live flows)."""
    layer_dicts = []
    for layer in getattr(flow, "layers", None) or ():
        try:
            layer_dicts.append(layer.to_dict())
        except Exception:
            continue
    return extract_filter_attrs(layer_dicts) if layer_dicts else {}


def filter_attrs_key(flow: Any) -> tuple:
    """Cheap fingerprint of the layer state :func:`extract_filter_attrs_from_flow` reads.

    Equal keys mean the extracted attrs can be reused (live rebuilds): each
    layer contributes its name, its message count and the ``repr`` of every
    scalar root a spec reads (``repr`` so an in-place mutated dict such as
    ``envelope`` still changes the key). Message *contents* are assumed to be
    append-only, as :func:`friTap.tui.widgets.flow_list.layer_signature` does.
    """
    return tuple(
        (getattr(layer, "name", ""),
         len(getattr(layer, "messages", None) or ()),
         tuple(repr(getattr(layer, root, None))
               for root in _SCALAR_ROOTS_BY_LAYER.get(getattr(layer, "name", ""), ())))
        for layer in list(getattr(flow, "layers", None) or ())
    )


def filter_inputs_from_flow(
    flow: Any, filter_attrs: Optional[Mapping[str, tuple]] = None,
) -> tuple[dict[str, tuple], frozenset[str]]:
    """Return ``(filter_attrs, protocols)`` for a summary built from *flow*.

    *filter_attrs* skips the layer extraction when the caller already has
    attributes for an unchanged layer stack; the protocols are always
    recomputed because they also depend on the flow's scalar labels.
    The attrs come back as a private plain-dict copy: picklable / deepcopy- /
    asdict-able, and no caller-held mapping can mutate the summary.
    """
    if filter_attrs is None:
        filter_attrs = extract_filter_attrs_from_flow(flow)
    return dict(filter_attrs), canonical_protocols(flow)


def lookup_attr(attrs: Optional[Mapping[str, tuple]], field_name: str) -> tuple:
    """Values of *field_name* in extracted *attrs*, resolving union specs.

    A union field (``telegram.method``) yields its members' values deduped in
    member order (capped like any field); a base field yields its own tuple.
    """
    if not attrs:
        return ()
    spec = _SPECS_BY_NAME.get(field_name)
    if spec is None or not spec.union_of:
        return tuple(attrs.get(field_name, ()))
    united = dict.fromkeys(value for member in spec.union_of
                           for value in attrs.get(member, ()))
    return tuple(united)[:MAX_VALUES_PER_FIELD]


def all_methods(attrs: Mapping[str, tuple]) -> tuple[str, ...]:
    """Union (deduped, order-preserving) of the TL methods in *attrs*."""
    return lookup_attr(attrs, _METHOD_FIELD)
