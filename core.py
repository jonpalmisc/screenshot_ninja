from binaryninjaui import DockHandler

from PySide6.QtCore import QPoint, QRect, QSize
from PySide6.QtGui import QPixmap, QRegion, QImage
from PySide6.QtWidgets import QApplication, QWidget


def _scaledSize(r: QRect, scale: int) -> QSize:
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


def renderWidgetImage(widget: QWidget, scale: float) -> QPixmap:
    """
    Get an image (QPixmap) of the given widget. Does not save the image to
    disk; the caller is responsible for saving the image.

    :param scale: the DPI-scaling factor to render the image at
    """

    rect = widget.rect()

    img = QPixmap(_scaledSize(rect, scale))
    img.setDevicePixelRatio(scale)
    widget.render(img, QPoint(), QRegion(rect))

    return img


def renderActiveWindow(scale: float) -> QPixmap:
    """
    Get an image of the main window. Will raise a ValueError if the active
    window could not be found.

    :param scale: the DPI-scaling factor to render the image at
    """

    if (main_window := QApplication.activeWindow()) is None:
        raise ValueError("Could not find active window.")

    return renderWidgetImage(main_window, scale)


def renderActiveView(scale: float) -> QPixmap:
    """
    Get an image of the currently active linear/graph view. Will raise a
    ValueError if the active view could not be found.

    :param scale: the DPI-scaling factor to render the image at
    """

    dock_handler = DockHandler.getActiveDockHandler()
    view_frame = dock_handler.getViewFrame()
    if (view := view_frame.getCurrentWidget()) is None:
        raise ValueError("Could not find active view.")

    return renderWidgetImage(view, scale)


def copyToClipboard(image: QImage) -> None:
    QApplication.clipboard().setImage(image)
