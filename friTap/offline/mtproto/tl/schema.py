"""Parser for TL schema text (the ``.tl`` files TDLib/Telegram publish).

Produces a :class:`TlSchema`: every combinator (constructor or function) keyed
by its 32-bit id, plus lookups by name and by result type. The grammar handled
is the subset real Telegram schemas use:

* ``---functions---`` / ``---types---`` section switches;
* ``//`` comments (whole-line and trailing);
* ``name#id`` and bare ``name`` (id computed as the TL CRC32 of the line);
* ``{X:Type}`` generic parameters and ``!X`` generic arguments;
* ``flags:#`` / ``flags2:#`` bit fields and ``flags.N?T`` conditional fields;
* ``Vector<T>`` (boxed), ``vector<T>`` / ``%T`` (bare) and the builtins
  ``int long double string bytes int128 int256 Bool true Object``.

Builtin *definitions* (``int ? = Int;``, ``vector {t:Type} # [ t ] = Vector t;``,
``int128 4*[ int ] = Int128;``, ``bytes = Bytes;``) are skipped: the decoder
implements those types natively.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

#: Combinator names that are builtin types, never decoded through the schema.
BUILTIN_NAMES = frozenset(
    {"int", "long", "double", "string", "bytes", "int128", "int256", "vector"}
)
#: Primitive (bare, fixed-layout) type names the decoder reads natively.
PRIMITIVE_TYPES = frozenset(
    {"#", "int", "long", "double", "string", "bytes", "int128", "int256", "true"}
)

_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z_][\w.]*)(?:#(?P<id>[0-9a-fA-F]{1,8}))?"
    r"(?P<params>(?:\s+[^=]+?)?)\s*=\s*(?P<result>[^;]+?)\s*;?\s*$"
)
_GENERIC_RE = re.compile(r"^\{(?P<name>\w+):Type\}$")
_PARAM_RE = re.compile(r"^(?P<name>\w+):(?P<type>\S+)$")
_FLAG_RE = re.compile(r"^(?P<field>\w+)\.(?P<bit>\d+)\?(?P<type>\S+)$")


@dataclass(frozen=True)
class TlParam:
    """One ``name:type`` parameter; ``flag_field``/``flag_bit`` set for ``flags.N?T``."""

    name: str
    type: str
    flag_field: Optional[str] = None
    flag_bit: Optional[int] = None


@dataclass(frozen=True)
class TlCombinator:
    """A constructor (``is_function=False``) or function of a TL schema."""

    name: str
    id: int
    params: Tuple[TlParam, ...]
    result_type: str
    is_function: bool = False
    generics: Tuple[str, ...] = ()


@dataclass
class TlSchema:
    """Combinators of one or more ``.tl`` sources, keyed for decoding."""

    constructors: Dict[int, TlCombinator] = field(default_factory=dict)
    functions: Dict[int, TlCombinator] = field(default_factory=dict)
    by_name: Dict[str, TlCombinator] = field(default_factory=dict)
    by_type: Dict[str, List[TlCombinator]] = field(default_factory=dict)

    def add(self, combinator: TlCombinator) -> None:
        """Add *combinator* unless its id is already present (first wins)."""
        table = self.functions if combinator.is_function else self.constructors
        if combinator.id in table:
            return
        table[combinator.id] = combinator
        if combinator.is_function:
            return
        self.by_name.setdefault(combinator.name, combinator)
        self.by_type.setdefault(combinator.result_type, []).append(combinator)

    def merge(self, other: "TlSchema") -> None:
        """Add every combinator of *other* at lower precedence than ours."""
        for combinator in other.constructors.values():
            self.add(combinator)
        for combinator in other.functions.values():
            self.add(combinator)

    def name_for_id(self, ctor_id: int) -> Optional[str]:
        """Name of the constructor or function with *ctor_id*, else ``None``."""
        combinator = self.constructors.get(ctor_id) or self.functions.get(ctor_id)
        return combinator.name if combinator else None


def _strip_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def tl_crc32(line: str) -> int:
    """TL constructor id of a (comment-free) combinator *line*.

    Normalisation per the TL spec: drop the ``#id``, the trailing ``;``,
    ``name:flags.N?true`` params, map ``bytes`` to ``string``, turn ``<``/``>``
    into a space / nothing and remove ``{``/``}``.
    """
    text = line.strip().rstrip(";").strip()
    text = re.sub(r"^([\w.]+)#[0-9a-fA-F]+", r"\1", text)
    text = re.sub(r"\s\w+:\w+\.\d+\?true(?=\s)", "", text)
    text = re.sub(r"(?<=[:?<])bytes\b", "string", text)
    text = text.replace("<", " ").replace(">", "").replace("{", "").replace("}", "")
    text = re.sub(r"\s+", " ", text).strip()
    return zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF


def _parse_param(token: str) -> Optional[TlParam]:
    match = _PARAM_RE.match(token)
    if match is None:
        return None
    name, type_ = match.group("name"), match.group("type")
    flag = _FLAG_RE.match(type_)
    if flag is None:
        return TlParam(name, type_)
    return TlParam(name, flag.group("type"), flag.group("field"), int(flag.group("bit")))


def _parse_params(text: str) -> Optional[Tuple[Tuple[str, ...], Tuple[TlParam, ...]]]:
    """Split the parameter text into generics and params; ``None`` if unsupported."""
    generics: List[str] = []
    params: List[TlParam] = []
    for token in text.split():
        generic = _GENERIC_RE.match(token)
        if generic is not None:
            generics.append(generic.group("name"))
            continue
        param = _parse_param(token)
        if param is None:
            return None
        params.append(param)
    return tuple(generics), tuple(params)


def parse_line(line: str, *, is_function: bool = False) -> Optional[TlCombinator]:
    """Parse one combinator *line*; ``None`` for builtins/unsupported syntax."""
    text = _strip_comment(line)
    match = _LINE_RE.match(text)
    if match is None or match.group("name") in BUILTIN_NAMES:
        return None
    split = _parse_params(match.group("params") or "")
    if split is None:
        return None
    generics, params = split
    ctor_id = match.group("id")
    return TlCombinator(
        name=match.group("name"),
        id=int(ctor_id, 16) if ctor_id else tl_crc32(text),
        params=params,
        result_type=match.group("result").strip(),
        is_function=is_function,
        generics=generics,
    )


def _iter_statements(text: str):
    """Yield ``(statement, is_function)`` for each ``;``-terminated statement."""
    is_function = False
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        if line == "---functions---":
            is_function = True
        elif line == "---types---":
            is_function = False
        else:
            yield line, is_function


def parse_tl(text: str) -> TlSchema:
    """Parse TL schema *text* into a :class:`TlSchema` (first definition wins)."""
    schema = TlSchema()
    for line, is_function in _iter_statements(text):
        combinator = parse_line(line, is_function=is_function)
        if combinator is not None:
            schema.add(combinator)
    return schema


@dataclass(frozen=True)
class TlType:
    """A parsed parameter type, precomputed once per distinct type string.

    ``kind`` is one of ``prim`` (``name`` = int/long/...), ``bool``, ``vector``
    (boxed ``Vector<elem>``), ``bare_vector`` (``vector<elem>``), ``bare``
    (``%T`` or a lowercase constructor name), ``function`` (``!X``) or ``boxed``
    (any other type name, including ``Object`` and generic parameters).
    """

    kind: str
    name: str
    elem: Optional["TlType"] = None


def _split_generic(text: str) -> Tuple[str, Optional[str]]:
    if text.endswith(">") and "<" in text:
        head, _, arg = text.partition("<")
        return head, arg[:-1]
    return text, None


def _is_bare_name(name: str) -> bool:
    return name.rsplit(".", 1)[-1][:1].islower()


@lru_cache(maxsize=4096)
def parse_type(text: str) -> TlType:
    """Parse a parameter type string such as ``Vector<long>`` or ``%Message``."""
    if text in PRIMITIVE_TYPES:
        return TlType("prim", text)
    if text == "Bool":
        return TlType("bool", text)
    if text.startswith("!"):
        return TlType("function", text[1:])
    if text.startswith("%"):
        return TlType("bare", text[1:])
    head, arg = _split_generic(text)
    if arg is not None and head in ("Vector", "vector"):
        kind = "vector" if head == "Vector" else "bare_vector"
        return TlType(kind, head, parse_type(arg))
    if _is_bare_name(text):
        return TlType("bare", text)
    return TlType("boxed", text)
