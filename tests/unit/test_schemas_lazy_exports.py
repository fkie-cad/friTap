"""``friTap.schemas`` resolves its exports lazily (PEP 562).

Every name in ``__all__`` stays importable from the package, while importing
the dependency-free ``canonical`` submodule (as the offline CLI does through
``friTap.pipeline``) no longer pulls in pydantic.
"""

from __future__ import annotations

import subprocess
import sys

import friTap.schemas as schemas
from friTap.schemas import agent_messages, canonical, host_messages


def test_every_exported_name_resolves_to_its_submodule_object():
    for name in schemas.__all__:
        owner = next(m for m in (agent_messages, canonical, host_messages)
                     if hasattr(m, name))
        assert getattr(schemas, name) is getattr(owner, name)


def test_from_import_of_exports_still_works():
    from friTap.schemas import (  # noqa: F401
        AgentMessage,
        Endpoint,
        KeylogMessage,
        RuntimeCommand,
    )


def test_dir_lists_all_exports():
    assert set(schemas.__all__) <= set(dir(schemas))


def test_unknown_attribute_raises_attribute_error():
    try:
        schemas.DoesNotExist  # noqa: B018
    except AttributeError as exc:
        assert "DoesNotExist" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected AttributeError")


def _modules_loaded_by(statement: str) -> set[str]:
    code = f"import sys; {statement}; print('\\n'.join(sys.modules))"
    out = subprocess.run([sys.executable, "-c", code], check=True,
                         capture_output=True, text=True).stdout
    return set(out.split())


def test_importing_canonical_does_not_load_pydantic():
    assert "pydantic" not in _modules_loaded_by("import friTap.schemas.canonical")


def test_importing_offline_cli_does_not_load_pydantic():
    assert "pydantic" not in _modules_loaded_by("import friTap.offline.cli")
