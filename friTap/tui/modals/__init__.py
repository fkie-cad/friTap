#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modal dialog package for friTap TUI."""

try:
    from .base import FriTapModal  # noqa: F401
    from .alert_modal import AlertModal  # noqa: F401
    from .backend_modal import BackendSelectModal  # noqa: F401
    from .capture_mode_modal import CaptureModeModal  # noqa: F401
    from .capture_select_modal import CaptureSelectModal  # noqa: F401
    from .device_modal import DeviceSelectModal  # noqa: F401
    from .help_modal import HelpScreen  # noqa: F401
    from .process_modal import ProcessSelectModal  # noqa: F401
    from .protocol_modal import ProtocolSelectModal  # noqa: F401
    from .server_check_modal import ServerCheckModal  # noqa: F401
    from .spawn_modal import SpawnInputModal  # noqa: F401
    from .start_confirm_modal import StartConfirmModal  # noqa: F401
    from .target_mode_modal import TargetModeModal  # noqa: F401
    MODALS_AVAILABLE = True
except ImportError:
    MODALS_AVAILABLE = False
