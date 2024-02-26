import time
from typing import Optional

from binaryninja import (
    BinaryView,
    MessageBoxButtonSet,
    MessageBoxIcon,
    PluginCommand,
    get_int_input,
    get_save_filename_input,
    show_message_box,
)

from .core import *


def _getSavePath() -> Optional[str]:
    """
    Prompt the user for a save path via the UI. Will return None if the user
    cancels the operation.
    """

    return get_save_filename_input(
        "Save Screenshot", "png", f"binaryninja-{int(time.time())}.png"
    )


def _uiSaveImage(
    _bv: BinaryView,
    window: bool,
    scale: Optional[int] = None,
    useClipboard: bool = False,
) -> None:
    """
    UI helper to save an image. If no scale is provided, the user will be
    prompted with a popup.

    :param window: whether the whole window (or just view) should be captured
    :param scale: the DPI-scaling factor to render the image at
    """

    # Prompt for scale if not given, abort if still not given.
    if scale is None:
        if (
            scale := get_int_input("Resolution multiplier:", "Screenshot Ninja")
        ) is None:
            return

    try:
        pixmap = renderActiveWindow(scale) if window else renderActiveView(scale)
    except ValueError as error:
        show_message_box(
            "Error",
            str(error),
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    if useClipboard:
        copyToClipboard(pixmap.toImage())
        return

    if (path := _getSavePath()) is None:
        return
    if not pixmap.save(path):
        show_message_box(
            "Error",
            "Failed to save image.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def register() -> None:
    PluginCommand.register(
        "Screenshot Ninja \\ Save View Image @ 1x...",
        "",
        lambda bv: _uiSaveImage(bv, False, 1),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save View Image @ 2x...",
        "",
        lambda bv: _uiSaveImage(bv, False, 2),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save View Image @ 2x to Clipboard...",
        "",
        lambda bv: _uiSaveImage(bv, False, 2, useClipboard=True),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save View Image...",
        "",
        lambda bv: _uiSaveImage(bv, False),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save Window Image @ 1x...",
        "",
        lambda bv: _uiSaveImage(bv, True, 1),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save Window Image @ 2x...",
        "",
        lambda bv: _uiSaveImage(bv, True, 2),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save Window Image...",
        "",
        lambda bv: _uiSaveImage(bv, True),
    )
