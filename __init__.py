import time
from typing import Optional

from binaryninja import *
from binaryninjaui import DockHandler

from PySide6.QtCore import QPoint, QRect, QSize
from PySide6.QtGui import QPixmap, QRegion


def scaled_size(r: QRect, scale: int) -> QSize:
    """
    Get the scaled size of a QRect.

    :param r: the QRect to scale
    :param scale: the scaling factor to use
    :retval: the resulting QSize of the operation
    """

    s = QRect(r)

    s.setWidth(int(r.width() * scale))
    s.setHeight(int(r.height() * scale))

    return s.size()


def _save_view_image(scale: int) -> None:
    """
    Save an image of the currently active linear/graph view.

    :param scale: the scaling factor the screenshot should be taken at
    """

    dh = DockHandler.getActiveDockHandler()

    # Get the current ViewFrame, the underlying widget, and that widget's rect
    vf = dh.getViewFrame()
    vf_widget = vf.getCurrentWidget()
    vf_rect = vf_widget.rect()

    # Create a QPixmap and render the view widget to it
    screenshot = QPixmap(scaled_size(vf_rect, scale))
    screenshot.setDevicePixelRatio(scale)
    vf_widget.render(screenshot, QPoint(), QRegion(vf_rect))

    # Use "binaryninja-" + the current Unix time as the default filename
    default_filename = f"binaryninja-{int(time.time())}.png"

    # Ask for the user's preferred output path; if the output path is None, then
    # the user has cancelled the operation
    save_path = get_save_filename_input("Save Screenshot", "png", default_filename)
    if save_path is None:
        return

    # Attempt to save the screenshot and show an error message if unsuccessful
    if screenshot.save(save_path.decode("ascii")):
        print(f"Screenshot saved to {save_path.decode('ascii')} successfully.")
    else:
        show_message_box(
            "Error",
            "Failed to save screenshot",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def save_view_image_x1(_bv: BinaryView) -> None:
    """Shorthand function to save a screenshot at 1x resolution."""

    _save_view_image(1)


def save_view_image_x2(_bv: BinaryView) -> None:
    """Shorthand function to save a screenshot at 2x resolution."""

    _save_view_image(2)


def save_view_image_custom(_bv: BinaryView) -> None:
    """Prompts the user for a resolution multiplier, then saves a screenshot."""

    scale = get_int_input("Resolution multiplier:", "Screenshot Ninja")

    if scale is not None:
        _save_view_image(scale)


PluginCommand.register(
    "Screenshot Ninja \\ Save view image @ 1x...",
    "Save an image of the currently visible linear/graph view at 1x scaling",
    save_view_image_x1,
)

PluginCommand.register(
    "Screenshot Ninja \\ Save view image @ 2x...",
    "Save an image of the currently visible linear/graph view at 2x scaling",
    save_view_image_x2,
)

PluginCommand.register(
    "Screenshot Ninja \\ Save view image...",
    "Save an image of the currently visible linear/graph view at custom scaling",
    save_view_image_custom,
)
