import time
from typing import Optional

from binaryninja import *
from binaryninjaui import DockHandler

from PySide6.QtCore import QPoint, QRect, QSize
from PySide6.QtGui import QPixmap, QRegion
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget


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


def save_widget_image(w: QWidget, scale: int) -> None:
    """
    Save an image of the given widget.

    :param scale: the scaling factor for the image
    """

    r = w.rect()

    # Create a QPixmap and render the view widget to it
    img = QPixmap(scaled_size(r, scale))
    img.setDevicePixelRatio(scale)
    w.render(img, QPoint(), QRegion(r))

    # Use "binaryninja-" + the current Unix time as the default filename
    default_filename = f"binaryninja-{int(time.time())}.png"

    # Ask for the user's preferred output path; if the output path is None, then
    # the user has cancelled the operation
    save_path = get_save_filename_input("Save Screenshot", "png", default_filename)
    if save_path is None:
        return

    # Attempt to save the screenshot and show an error message if unsuccessful
    if img.save(save_path.decode("ascii")):
        print(f"Screenshot saved to {save_path.decode('ascii')} successfully.")
    else:
        show_message_box(
            "Error",
            "Failed to save screenshot.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


# -- COMMAND IMPLEMENTATIONS ---------------------------------------------------


def _save_window_image(scale: int) -> None:
    """
    Save an image of the main window.

    :param scale: the scaling factor for the image
    """

    main_window = QApplication.activeWindow()

    # Save an image of the main window if found
    if main_window is not None:
        save_widget_image(main_window, scale)
    else:
        show_message_box(
            "Error",
            "Couldn't find main window.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def _save_view_image(scale: int) -> None:
    """
    Save an image of the currently active linear/graph view.

    :param scale: the scaling factor the screenshot should be taken at
    """

    dh = DockHandler.getActiveDockHandler()

    # Get the current ViewFrame and the underlying widget
    vf = dh.getViewFrame()
    vf_widget = vf.getCurrentWidget()

    # Save an image of the active view
    save_widget_image(vf_widget, scale)


# -- COMMAND SHORTHANDS --------------------------------------------------------


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


def save_window_image_x1(_bv: BinaryView) -> None:
    """
    Shorthand function to save a screenshot of the main window at 1x resolution.
    """

    _save_window_image(1)


def save_window_image_x2(_bv: BinaryView) -> None:
    """
    Shorthand function to save a screenshot of the main window at 2x resolution.
    """

    _save_window_image(2)


def save_window_image_custom(_bv: BinaryView) -> None:
    """
    Shorthand to save a screenshot of the main window at a custom resolution.
    """

    scale = get_int_input("Resolution multiplier:", "Screenshot Ninja")

    if scale is not None:
        _save_window_image(scale)


# -- COMMAND REGISTRATION ------------------------------------------------------

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

PluginCommand.register(
    "Screenshot Ninja \\ Save window image @ 1x...",
    "Save an image of the main window at 1x scaling",
    save_window_image_x1,
)

PluginCommand.register(
    "Screenshot Ninja \\ Save window image @ 2x...",
    "Save an image of the main window at 2x scaling",
    save_window_image_x2,
)

PluginCommand.register(
    "Screenshot Ninja \\ Save window image...",
    "Save an image of the main window at custom scaling",
    save_window_image_custom,
)
