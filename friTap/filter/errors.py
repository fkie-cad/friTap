"""Filter-specific exceptions."""

from __future__ import annotations

from dataclasses import dataclass


class FilterSyntaxError(Exception):
    """Raised when a filter expression has invalid syntax."""

    def __init__(self, message: str, position: int = -1) -> None:
        self.position = position
        if position >= 0:
            super().__init__(f"{message} (at position {position})")
        else:
            super().__init__(message)


# Suggestion.kind of a did-you-mean name spliced in place of the token.
FIELD_REPLACEMENT = "field_replacement"


@dataclass(frozen=True)
class Suggestion:
    """One ready-to-apply fix for an unknown field.

    Attributes:
        expression: The whole input rewritten with the fix applied.
        kind: ``"protocol_search"``, ``"method_search"``, ``"frame_search"``
            (generic searches for a bare unknown word) or
            ``"field_replacement"`` (a did-you-mean name spliced in).
        label: Short text naming the fix (``protocol contains "TELE"``,
            ``mtproto.dc_id``).
    """

    expression: str
    kind: str
    label: str


class UnknownFieldError(FilterSyntaxError):
    """Raised when a filter expression references an unknown field.

    ``str(error)`` stays the short one-liner (``Unknown field 'TELE' (at
    position 0)``); the extra attributes carry the hints for the UI.

    Attributes:
        name: The unknown token as typed.
        position: Offset of the token in the (stripped) expression.
        did_you_mean: Close valid field/protocol names, best first.
        actions: Ready-to-apply fixes, in display order. For a bare unknown
            word: the generic searches (``protocol contains "X"``,
            ``method contains "X"``, ``frame contains "X"``) followed by the
            first did-you-mean replacement, if any. When the token is used as
            a field (followed by an operator, ``foo == 3``) a generic search
            would not parse, so the actions are the did-you-mean field
            replacements only (possibly none).
        suggestions: The ``expression`` of each generic search (bare word)
            or field replacement (operator case) -- kept for API
            compatibility; excludes the bare-word did-you-mean action.
        followed_by_operator: True when the token is used as a field.
    """

    def __init__(
        self,
        name: str,
        position: int = -1,
        did_you_mean: list[str] | None = None,
        actions: tuple[Suggestion, ...] = (),
        followed_by_operator: bool = False,
    ) -> None:
        super().__init__(f"Unknown field {name!r}", position)
        self.name = name
        self.did_you_mean: list[str] = list(did_you_mean or [])
        self.actions: tuple[Suggestion, ...] = tuple(actions)
        self.followed_by_operator = followed_by_operator

    @property
    def suggestions(self) -> list[str]:
        """Expressions of the generic searches / field replacements."""
        if self.followed_by_operator:
            return [a.expression for a in self.actions]
        return [a.expression for a in self.actions if a.kind != FIELD_REPLACEMENT]


class FilterEvalError(Exception):
    """Raised when filter evaluation encounters an unexpected condition."""
