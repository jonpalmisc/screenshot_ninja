from .core import get_active_view_image, get_active_window_image
from . import frontend

__all__ = ["get_active_view_image", "get_active_window_image"]

frontend.register()
