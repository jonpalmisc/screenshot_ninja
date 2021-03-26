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

from binaryninjaui import DockHandler

import binaryninjaui

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import QPoint, QRect, QSize
    from PySide6.QtGui import QPixmap, QRegion
    from PySide6.QtWidgets import QApplication, QWidget
else:
    from PySide2.QtCore import QPoint, QRect, QSize
    from PySide2.QtGui import QPixmap, QRegion
    from PySide2.QtWidgets import QApplication, QWidget


# -- HELPERS -------------------------------------------------------------------


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


def save_widget_image(w: QWidget, scale: int, dest: str) -> None:
    """
    Save an image of the given widget.

    :param scale: the DPI-scaling factor to render the image at
    """

    r = w.rect()

    # Create a QPixmap and render the view widget to it
    img = QPixmap(scaled_size(r, scale))
    img.setDevicePixelRatio(scale)
    w.render(img, QPoint(), QRegion(r))

    # Attempt to save the screenshot and show an error message if unsuccessful
    if img.save(dest):
        print(f"Screenshot saved to {dest} successfully.")
    else:
        show_message_box(
            "Error",
            "Failed to save screenshot.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


# -- COMMAND IMPLEMENTATIONS ---------------------------------------------------


def save_active_window_image(scale: int, dest: str) -> None:
    """
    Save an image of the main window.

    :param scale: the DPI-scaling factor to render the image at
    :param dest: where to save the image
    """

    main_window = QApplication.activeWindow()

    # Save an image of the main window if found
    if main_window is not None:
        save_widget_image(main_window, scale, dest)
    else:
        show_message_box(
            "Error",
            "Couldn't find main window.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def save_active_view_image(scale: int, dest: str) -> None:
    """
    Save an image of the currently active linear/graph view.

    :param scale: the DPI-scaling factor to render the image at
    :param dest: where to save the image
    """

    dh = DockHandler.getActiveDockHandler()

    # Get the current ViewFrame and the underlying widget
    vf = dh.getViewFrame()
    vf_widget = vf.getCurrentWidget()

    # Save an image of the active view
    save_widget_image(vf_widget, scale, dest)


# -- COMMAND SHORTHANDS --------------------------------------------------------


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

    # Try to ask the user for a save location, will be None if canceled
    path = _get_save_path()
    if path is None:
        return

    # Save the actual screenshot
    if window:
        save_active_window_image(scale, path)
    else:
        save_active_view_image(scale, path)


# -- COMMAND REGISTRATION ------------------------------------------------------

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
