"""Filter-specific exceptions."""

from __future__ import annotations

from dataclasses import dataclass


class FilterSyntaxError(Exception):
    """Raised for invalid filter syntax.

    ``position`` is the offending token's offset (-1 when unknown); ``hint`` is an optional
    next step (e.g. ``did you mean: contains``), not part of ``str()``.
    """

    def __init__(self, message: str, position: int = -1, hint: str | None = None) -> None:
        self.position = position
        self.hint = hint
        if position >= 0:
            super().__init__(f"{message} (at position {position})")
        else:
            super().__init__(message)


# Suggestion.kind of a did-you-mean name spliced in place of the token.
FIELD_REPLACEMENT = "field_replacement"


@dataclass(frozen=True)
class Suggestion:
    """One ready-to-apply fix for an unknown field.

    ``expression`` is the whole input with the fix applied; ``kind`` is ``"protocol_search"``,
    ``"method_search"``, ``"frame_search"`` (bare-word searches) or ``"field_replacement"``
    (did-you-mean name spliced in); ``label`` names the fix (``protocol contains "TELE"``).
    """

    expression: str
    kind: str
    label: str


class UnknownFieldError(FilterSyntaxError):
    """Raised when a filter expression references an unknown field.

    ``str(error)`` stays a one-liner (``Unknown field 'TELE' (at position 0)``); the
    attributes carry UI hints.

    Attributes:
        name: The unknown token as typed.
        position: Offset in the (stripped) expression.
        did_you_mean: Close valid field/protocol names, best first.
        actions: Fixes in display order. A bare unknown word gets the generic searches
            (``protocol/method/frame contains "X"``) then the first did-you-mean
            replacement; a token used as a field (``foo == 3``) gets only did-you-mean
            replacements, since a search would not parse.
        suggestions: ``expression`` of each generic search or field replacement, excluding
            the bare-word did-you-mean action (API compatibility).
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
