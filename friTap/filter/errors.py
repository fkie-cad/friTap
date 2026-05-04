"""Filter-specific exceptions."""


class FilterSyntaxError(Exception):
    """Raised when a filter expression has invalid syntax."""

    def __init__(self, message: str, position: int = -1) -> None:
        self.position = position
        if position >= 0:
            super().__init__(f"{message} (at position {position})")
        else:
            super().__init__(message)


class FilterEvalError(Exception):
    """Raised when filter evaluation encounters an unexpected condition."""
