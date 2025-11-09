"""Protocol handler for covert channel"""

from .encoder import CIDBuffer, CIDEncoder
from .synchronizer import Synchronizer

__all__ = ["Synchronizer", "CIDEncoder", "CIDBuffer"]
