#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modal dialog package for friTap TUI."""

try:
    from .base import FriTapModal
    from .alert_modal import AlertModal
    from .backend_modal import BackendSelectModal
    from .capture_mode_modal import CaptureModeModal
    from .capture_select_modal import CaptureSelectModal
    from .device_modal import DeviceSelectModal
    from .help_modal import HelpScreen
    from .process_modal import ProcessSelectModal
    from .protocol_modal import ProtocolSelectModal
    from .server_check_modal import ServerCheckModal
    from .spawn_modal import SpawnInputModal
    from .start_confirm_modal import StartConfirmModal
    from .target_mode_modal import TargetModeModal
    MODALS_AVAILABLE = True

    __all__ = [
        "FriTapModal",
        "AlertModal",
        "BackendSelectModal",
        "CaptureModeModal",
        "CaptureSelectModal",
        "DeviceSelectModal",
        "HelpScreen",
        "ProcessSelectModal",
        "ProtocolSelectModal",
        "ServerCheckModal",
        "SpawnInputModal",
        "StartConfirmModal",
        "TargetModeModal",
    ]
except ImportError:
    MODALS_AVAILABLE = False
