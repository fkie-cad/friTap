"""Registry for extraction definitions."""


class ExtractionRegistry:
    """Stores and retrieves extraction definitions keyed by (protocol, library)."""

    def __init__(self):
        self._definitions = {}  # type: Dict[Tuple[str, str], ExtractionDefinition]

    def register(self, definition):
        # type: (ExtractionDefinition) -> None
        key = (definition.protocol, definition.library)
        self._definitions[key] = definition

    def get(self, protocol, library):
        # type: (str, str) -> Optional[ExtractionDefinition]
        return self._definitions.get((protocol, library))

    def get_all_for_protocol(self, protocol):
        # type: (str) -> List[ExtractionDefinition]
        return [d for (p, _), d in self._definitions.items() if p == protocol]

    def list_protocols(self):
        # type: () -> List[str]
        return sorted(set(p for p, _ in self._definitions))


# Global registry instance
_registry = ExtractionRegistry()


def register(definition):
    # type: (ExtractionDefinition) -> None
    _registry.register(definition)


def get(protocol, library):
    # type: (str, str) -> Optional[ExtractionDefinition]
    return _registry.get(protocol, library)


def get_all_for_protocol(protocol):
    # type: (str) -> List[ExtractionDefinition]
    return _registry.get_all_for_protocol(protocol)
