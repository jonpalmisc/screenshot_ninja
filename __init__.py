from .core import *
from . import frontend

__all__ = ["renderActiveView", "renderActiveWindow"]

frontend.register()
