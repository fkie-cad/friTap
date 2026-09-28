"""Cross-references between decrypted Telegram records of one capture.

Every decrypted MTProto cloud record becomes its own flow (one row per packet).
The forensic value lies in how those rows relate: which request an
``rpc_result`` answers, which server messages a ``msgs_ack`` acknowledges,
which messages a ``msg_container`` bundles, and which cloud record carried a
Secret-Chat (E2E) message.

:func:`extract_record_refs` reads those references out of one record's decoded
TL tree into a small :class:`RecordRef`; :class:`CrossRefIndex` indexes them by
``(auth_key_id, msg_id)`` - container children included - and
:meth:`CrossRefIndex.resolve` returns the JSON-native ``refs`` dict stored on
the record's layer::

    {
      "answers":     [{"msg_id": "0x…", "record_seq": 12, "method": "help.getConfig"}],
      "request_method": "help.getConfig",           # method of the first answered request
      "answered_by": [{"msg_id": "0x…", "record_seq": 15, "method": "config"}],  # the result's type
      "acks":        [{"msg_id": "0x…", "record_seq": 9, "method": "rpc_result"}],  # <= 64
      "acks_total":  3,
      "acked_by":    [{"msg_id": "0x…", "record_seq": 20, "method": "msgs_ack"}],
      "container":   [{"msg_id": "0x…", "seqno": 7, "method": "pong"}],  # this record's own children
      "carried_in":  {"msg_id": "0x…", "record_seq": 30},   # E2E records only
      "carries":     [{"record_seq": 31}],                  # cloud carriers of E2E
    }

Referenced entries carry ``record_seq`` only when the referenced record was
decrypted in this capture; empty keys are omitted. msg_ids are hex strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .tl import TlLimits, TlNode, TlVector, decode_tl

#: Maximum resolved ``acks`` entries kept per record (``acks_total`` has the count).
MAX_ACKS = 64

#: Decoder limits for reference extraction: keep every vector item (ack ids).
REF_LIMITS = TlLimits(keep_vector_items=100_000)

# Invocation wrappers whose ``query`` field holds the real RPC method.
_WRAPPER_PREFIXES = ("invokeWith", "invokeAfter", "initConnection")


@dataclass(frozen=True)
class ContainerChild:
    """One ``message`` of a ``msg_container``."""

    msg_id: int
    seqno: int
    method: str


@dataclass(frozen=True)
class RecordRef:
    """The references one decrypted cloud record makes to other records."""

    record_seq: int
    auth_key_id: str
    direction: str
    msg_id: int
    method: str
    child_msg_ids: Tuple[ContainerChild, ...] = ()
    answers_req_ids: Tuple[int, ...] = ()
    acked_ids: Tuple[int, ...] = ()
    #: The result type of each ``rpc_result`` (parallel to ``answers_req_ids``).
    answer_methods: Tuple[str, ...] = ()

    def answer_method(self, index: int) -> str:
        """Result type answering ``answers_req_ids[index]``, else ``rpc_result``."""
        if index < len(self.answer_methods) and self.answer_methods[index]:
            return self.answer_methods[index]
        return "rpc_result"


def msg_id_hex(msg_id: int) -> str:
    """``0x``-prefixed 16-digit hex of a (signed or unsigned) 64-bit msg_id."""
    return f"0x{msg_id & 0xFFFFFFFFFFFFFFFF:016x}"


def _unwrap_gzip(node):
    """The inner object of a ``gzip_packed`` node (itself otherwise)."""
    while isinstance(node, TlNode) and node.kind == "gzip":
        inner = node.value("packed_data")
        if not isinstance(inner, TlNode):
            break
        node = inner
    return node


def method_name(node) -> str:
    """The method/constructor name of *node*, looking through gzip and invoke wrappers."""
    node = _unwrap_gzip(node)
    while (isinstance(node, TlNode) and node.name.startswith(_WRAPPER_PREFIXES)
           and isinstance(node.value("query"), TlNode)):
        node = _unwrap_gzip(node.value("query"))
    return node.name if isinstance(node, TlNode) else ""


def _vector_ints(value) -> Tuple[int, ...]:
    if not isinstance(value, TlVector):
        return ()
    return tuple(item for item in value.items if isinstance(item, int))


def _objects_of(root: TlNode) -> List[TlNode]:
    """*root* itself, or the bodies of its container children."""
    root = _unwrap_gzip(root)
    if root.name != "msg_container":
        return [root]
    return [_unwrap_gzip(child.value("body")) for child in _container_messages(root)]


def _container_messages(root: TlNode) -> List[TlNode]:
    vector = root.value("messages")
    if not isinstance(vector, TlVector):
        return []
    return [item for item in vector.items if isinstance(item, TlNode) and item.name == "message"]


def _children(root: TlNode) -> Tuple[ContainerChild, ...]:
    root = _unwrap_gzip(root)
    if root.name != "msg_container":
        return ()
    return tuple(
        ContainerChild(int(msg.value("msg_id", 0) or 0), int(msg.value("seqno", 0) or 0),
                       method_name(msg.value("body")))
        for msg in _container_messages(root)
    )


def _rpc_results(objects: List[TlNode]) -> List[TlNode]:
    return [obj for obj in objects
            if isinstance(obj, TlNode) and obj.name == "rpc_result"
            and isinstance(obj.value("req_msg_id"), int)]


def _answers(objects: List[TlNode]) -> Tuple[int, ...]:
    return tuple(int(obj.value("req_msg_id")) for obj in _rpc_results(objects))


def _answer_methods(objects: List[TlNode]) -> Tuple[str, ...]:
    """The result type of each ``rpc_result`` (``""`` when not a named object)."""
    return tuple(method_name(obj.value("result")) for obj in _rpc_results(objects))


def _acks(objects: List[TlNode]) -> Tuple[int, ...]:
    ids: List[int] = []
    for obj in objects:
        if isinstance(obj, TlNode) and obj.name == "msgs_ack":
            ids.extend(_vector_ints(obj.value("msg_ids")))
    return tuple(ids)


def _record_method(root: TlNode, children: Tuple[ContainerChild, ...]) -> str:
    if children:
        return "msg_container[" + ", ".join(child.method for child in children) + "]"
    return method_name(root)


def refs_from_tree(root: TlNode, *, record_seq: int, auth_key_id: str, direction: str,
                   msg_id: int) -> RecordRef:
    """:func:`extract_record_refs` for an already decoded tree."""
    objects = _objects_of(root)
    children = _children(root)
    return RecordRef(
        record_seq=record_seq, auth_key_id=auth_key_id or "", direction=direction or "",
        msg_id=int(msg_id or 0), method=_record_method(root, children),
        child_msg_ids=children, answers_req_ids=_answers(objects), acked_ids=_acks(objects),
        answer_methods=_answer_methods(objects),
    )


def extract_record_refs(tl_bytes: bytes, *, record_seq: int, auth_key_id: str,
                        direction: str, msg_id: int) -> RecordRef:
    """Decode one cloud record's TL payload and collect its references. Never raises."""
    root = decode_tl(tl_bytes, domain="mtproto", limits=REF_LIMITS)
    return refs_from_tree(root, record_seq=record_seq, auth_key_id=auth_key_id,
                          direction=direction, msg_id=msg_id)


MsgKey = Tuple[str, int]


@dataclass
class _Target:
    """What one ``(auth_key_id, msg_id)`` resolves to."""

    record_seq: int
    method: str


@dataclass
class CrossRefIndex:
    """Index of :class:`RecordRef` objects keyed by ``(auth_key_id, msg_id)``."""

    _refs: Dict[int, RecordRef] = field(default_factory=dict)
    _by_msg: Dict[MsgKey, _Target] = field(default_factory=dict)
    # record_seq -> [(referring record_seq, its msg_id, its method)]
    _answered_by: Dict[int, List[Tuple[int, int, str]]] = field(default_factory=dict)
    _acked_by: Dict[int, List[Tuple[int, int, str]]] = field(default_factory=dict)
    _carried_in: Dict[int, Tuple[str, int]] = field(default_factory=dict)
    # carrier record_seq -> [record_seq of each E2E record it carries]
    _carries: Dict[int, List[int]] = field(default_factory=dict)
    _dirty: bool = False

    # -- building -------------------------------------------------------------- #
    def add(self, ref: RecordRef) -> None:
        """Index *ref*: its own msg_id and every container child's msg_id."""
        self._refs[ref.record_seq] = ref
        self._dirty = True
        if ref.msg_id:
            self._by_msg[(ref.auth_key_id, ref.msg_id)] = _Target(ref.record_seq, ref.method)
        for child in ref.child_msg_ids:
            self._by_msg[(ref.auth_key_id, child.msg_id)] = _Target(ref.record_seq, child.method)

    def add_e2e(self, record_seq: int, carrier_auth_key_id: str, carrier_msg_id: int) -> None:
        """Register a Secret-Chat record carried by cloud message *carrier_msg_id*."""
        self._carried_in[record_seq] = (carrier_auth_key_id or "", int(carrier_msg_id or 0))
        self._dirty = True

    # -- lookups --------------------------------------------------------------- #
    def lookup(self, auth_key_id: str, msg_id: int) -> Optional[_Target]:
        """The record holding *msg_id* (top level or container child), or None."""
        return self._by_msg.get((auth_key_id, msg_id))

    def _entry(self, auth_key_id: str, msg_id: int, with_method: bool = True) -> dict:
        entry = {"msg_id": msg_id_hex(msg_id)}
        target = self.lookup(auth_key_id, msg_id)
        if target is not None:
            entry["record_seq"] = target.record_seq
            if with_method and target.method:
                entry["method"] = target.method
        return entry

    def _reverse_maps(self) -> None:
        """(Re)build answered_by / acked_by / carries from every indexed record."""
        self._answered_by, self._acked_by = {}, {}
        for ref in self._refs.values():
            answer_methods = [ref.answer_method(i) for i in range(len(ref.answers_req_ids))]
            self._link_reverse(ref, ref.answers_req_ids, self._answered_by, answer_methods)
            self._link_reverse(ref, ref.acked_ids, self._acked_by)
        self._carries = self._carrier_map()
        self._dirty = False

    def _carrier_map(self) -> Dict[int, List[int]]:
        """Carrier record_seq -> the E2E records whose carrier msg_id it holds."""
        carries: Dict[int, List[int]] = {}
        for seq, (akid, mid) in self._carried_in.items():
            target = self.lookup(akid, mid)
            carrier = self._refs.get(target.record_seq) if target is not None else None
            if carrier is not None and carrier.auth_key_id == akid:
                carries.setdefault(carrier.record_seq, []).append(seq)
        return carries

    def _link_reverse(self, ref: RecordRef, ids, reverse: Dict[int, List[Tuple[int, int, str]]],
                      methods: Optional[List[str]] = None):
        """Point each referenced record back at *ref* (with *ref*'s per-id method)."""
        for index, target_id in enumerate(ids):
            target = self.lookup(ref.auth_key_id, target_id)
            if target is not None and target.record_seq != ref.record_seq:
                method = methods[index] if methods else _acking_method(ref)
                reverse.setdefault(target.record_seq, []).append(
                    (ref.record_seq, ref.msg_id, method))

    def finalize(self) -> None:
        """Build the reverse maps now (``resolve`` otherwise does it lazily)."""
        self._reverse_maps()

    # -- resolution ------------------------------------------------------------ #
    def resolve(self, record_seq: int) -> dict:
        """The JSON-native ``refs`` dict of *record_seq* (see module docstring)."""
        if self._dirty:
            self._reverse_maps()
        if record_seq in self._carried_in:
            return self._resolve_e2e(record_seq)
        ref = self._refs.get(record_seq)
        if ref is None:
            return {}
        refs: dict = {}
        self._put_forward(refs, ref)
        self._put_reverse(refs, record_seq)
        self._put_carries(refs, ref)
        return refs

    def _put_forward(self, refs: dict, ref: RecordRef) -> None:
        answers = [self._entry(ref.auth_key_id, req) for req in ref.answers_req_ids]
        if answers:
            refs["answers"] = answers
            method = next((a["method"] for a in answers if a.get("method")), "")
            if method:
                refs["request_method"] = method
        if ref.acked_ids:
            refs["acks"] = [self._entry(ref.auth_key_id, ack) for ack in ref.acked_ids[:MAX_ACKS]]
            refs["acks_total"] = len(ref.acked_ids)
        if ref.child_msg_ids:
            refs["container"] = [
                {"msg_id": msg_id_hex(c.msg_id), "seqno": c.seqno, "method": c.method}
                for c in ref.child_msg_ids
            ]

    def _put_reverse(self, refs: dict, record_seq: int) -> None:
        for key, reverse in (("answered_by", self._answered_by), ("acked_by", self._acked_by)):
            links = reverse.get(record_seq)
            if links:
                refs[key] = [_reverse_entry(seq, mid, method)
                             for seq, mid, method in _unique(links)]

    def _put_carries(self, refs: dict, ref: RecordRef) -> None:
        carried = self._carries.get(ref.record_seq)
        if carried:
            refs["carries"] = [{"record_seq": seq} for seq in sorted(carried)]

    def _holds(self, ref: RecordRef, msg_id: int) -> bool:
        target = self.lookup(ref.auth_key_id, msg_id)
        return target is not None and target.record_seq == ref.record_seq

    def _resolve_e2e(self, record_seq: int) -> dict:
        akid, carrier_msg_id = self._carried_in[record_seq]
        if not carrier_msg_id:
            return {}
        return {"carried_in": self._entry(akid, carrier_msg_id, with_method=False)}


def _acking_method(ref: RecordRef) -> str:
    """``msgs_ack`` for an ack record, even when it rides a container."""
    return "msgs_ack" if ref.acked_ids else ref.method


def _reverse_entry(record_seq: int, msg_id: int, method: str) -> dict:
    entry = {"msg_id": msg_id_hex(msg_id), "record_seq": record_seq}
    if method:
        entry["method"] = method
    return entry


def _unique(links: List[Tuple]) -> List[Tuple]:
    seen, out = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out
