import binaryninjaui
from binaryninjaui import DockHandler

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import QPoint, QRect, QSize
    from PySide6.QtGui import QPixmap, QRegion
    from PySide6.QtWidgets import QApplication, QWidget
else:
    from PySide2.QtCore import QPoint, QRect, QSize
    from PySide2.QtGui import QPixmap, QRegion
    from PySide2.QtWidgets import QApplication, QWidget


def _scaled_size(r: QRect, scale: int) -> QSize:
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


def get_widget_image(w: QWidget, scale: float) -> QPixmap:
    """
    Get an image (QPixmap) of the given widget. Does not save the image to
    disk; the caller is responsible for saving the image.

    :param scale: the DPI-scaling factor to render the image at
    """

    r = w.rect()

    # Create a QPixmap and render the view widget to it
    img = QPixmap(_scaled_size(r, scale))
    img.setDevicePixelRatio(scale)
    w.render(img, QPoint(), QRegion(r))

    return img


# -- COMMAND IMPLEMENTATIONS ---------------------------------------------------


def get_active_window_image(scale: float) -> QPixmap:
    """
    Get an image of the main window. Will raise a ValueError if the active
    window could not be found.

    :param scale: the DPI-scaling factor to render the image at
    """

    main_window = QApplication.activeWindow()

    if main_window is None:
        raise ValueError("Could not find active window.")

    return get_widget_image(main_window, scale)


def get_active_view_image(scale: float) -> QPixmap:
    """
    Get an image of the currently active linear/graph view. Will raise a
    ValueError if the active view could not be found.

    :param scale: the DPI-scaling factor to render the image at
    """

    dh = DockHandler.getActiveDockHandler()

    # Get the current ViewFrame and the underlying widget
    vf = dh.getViewFrame()
    view = vf.getCurrentWidget()

    if view is None:
        raise ValueError("Could not find active view.")

    return get_widget_image(view, scale)
