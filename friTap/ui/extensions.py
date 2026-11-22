"""Public re-export of the core extension registry :mod:`friTap.extensions`.

Every name is the same object as in :mod:`friTap.extensions`, so registering
through either path is equivalent. Imports no Textual code.
"""

from friTap.extensions import (  # noqa: F401
    DISABLE_ENV_VAR,
    UI_EXTENSION_ENTRY_POINT_GROUP,
    BodyDecoderSpec,
    DetailTabSpec,
    ExtensionLoadError,
    FlowColumnSpec,
    LayerFieldSpec,
    extension_load_errors,
    get_body_decoders,
    get_detail_tabs,
    get_filter_fields,
    get_flow_columns,
    load_extensions,
    register_body_decoder,
    register_detail_tab,
    register_filter_field,
    register_flow_column,
    reset_extensions,
)
from friTap.extensions import __all__  # noqa: F401
