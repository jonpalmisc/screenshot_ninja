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

from .core import get_active_view_image, get_active_window_image


def _get_save_path() -> Optional[str]:
    """
    Prompt the user for a save path via the UI. Will return None if the user
    cancels the operation.
    """

    # Use "binaryninja-" + the current Unix time as the default filename
    default_filename = f"binaryninja-{int(time.time())}.png"

    # Ask for the user's preferred output path; if the output path is None, then
    # the user has cancelled the operation
    path = get_save_filename_input("Save Screenshot", "png", default_filename)

    # Convert path from bytes to string if one was supplied
    if path is not None:
        path = path.decode("ascii")

    return path


def _ui_save_image(_bv: BinaryView, window: bool, scale: Optional[int] = None) -> None:
    """
    UI helper to save an image. If no scale is provided, the user will be
    prompted with a popup.

    :param window: whether the whole window (or just view) should be captured
    :param scale: the DPI-scaling factor to render the image at
    """

    # Try to ask the user for the scale, will be None if canceled
    if scale is None:
        scale = get_int_input("Resolution multiplier:", "Screenshot Ninja")
        if scale is None:
            return

    # Get the screenshot. You would think this would be called after the user
    # chooses a save location, but that messes up Qt's ability to determine the
    # active window, so...
    try:
        img = get_active_window_image(scale) if window else get_active_view_image(scale)
    except ValueError as e:
        show_message_box(
            "Error",
            str(e),
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )

    # Try to ask the user for a save location, will be None if canceled
    path = _get_save_path()
    if path is None:
        return

    # Try to save the image, will return False if unsuccessful
    if not img.save(path):
        show_message_box(
            "Error",
            "Failed to save image.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def register() -> None:
    PluginCommand.register(
        "Screenshot Ninja \\ Save view image @ 1x...",
        "Save an image of the currently visible linear/graph view at 1x scaling",
        lambda bv: _ui_save_image(bv, False, 1),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save view image @ 2x...",
        "Save an image of the currently visible linear/graph view at 2x scaling",
        lambda bv: _ui_save_image(bv, False, 2),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save view image...",
        "Save an image of the currently visible linear/graph view at custom scaling",
        lambda bv: _ui_save_image(bv, False),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save window image @ 1x...",
        "Save an image of the main window at 1x scaling",
        lambda bv: _ui_save_image(bv, True, 1),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save window image @ 2x...",
        "Save an image of the main window at 2x scaling",
        lambda bv: _ui_save_image(bv, True, 2),
    )

    PluginCommand.register(
        "Screenshot Ninja \\ Save window image...",
        "Save an image of the main window at custom scaling",
        lambda bv: _ui_save_image(bv, True),
    )
